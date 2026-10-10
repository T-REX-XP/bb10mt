package qnx6

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"syscall"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type mountState struct {
	mu     sync.Mutex
	image  *Image
	editor *Editor
	err    error
	opened map[uint32]int
}
type fuseNode struct {
	fs.Inode
	state  *mountState
	number uint32
}

func mountErr(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrNotFound) {
		return syscall.ENOENT
	}
	return syscall.EIO
}
func (s *mountState) mutate(fn func(*Editor) error) syscall.Errno {
	if s.editor == nil {
		return syscall.EROFS
	}
	if s.err != nil {
		return syscall.EIO
	}
	if e := fn(s.editor); e != nil {
		s.err = e
		return mountErr(e)
	}
	return 0
}
func (n *fuseNode) imageNode() (Node, error)    { return n.state.image.Inode(n.number) }
func (n *fuseNode) pathname(name string) string { return path.Join("/", n.Path(nil), name) }
func fillAttr(n Node, bs uint32, a *fuse.Attr) {
	a.Ino = uint64(n.Number)
	a.Size = n.Size()
	a.Mode = uint32(n.Mode())
	a.Nlink = uint32(n.Links())
	a.Uid = n.UID()
	a.Gid = n.GID()
	a.Atime = uint64(binio.U32(n.Raw, 16))
	a.Mtime = uint64(binio.U32(n.Raw, 20))
	a.Ctime = uint64(binio.U32(n.Raw, 28))
	a.Blksize = bs
	a.Blocks = (n.Size() + 511) / 512
}
func (n *fuseNode) child(ctx context.Context, number uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	v, e := n.state.image.Inode(number)
	if e != nil {
		return nil, mountErr(e)
	}
	fillAttr(v, n.state.image.BlockSize, &out.Attr)
	child := &fuseNode{state: n.state, number: number}
	return n.NewInode(ctx, child, fs.StableAttr{Mode: uint32(v.Mode()) & syscall.S_IFMT, Ino: uint64(number)}), 0
}
func (n *fuseNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	v, e := n.imageNode()
	if e != nil {
		return nil, mountErr(e)
	}
	entries, e := n.state.image.Entries(v)
	if e != nil {
		return nil, mountErr(e)
	}
	for _, entry := range entries {
		if entry.Name == name {
			return n.child(ctx, entry.Inode, out)
		}
	}
	return nil, syscall.ENOENT
}
func (n *fuseNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	v, e := n.imageNode()
	if e != nil {
		return mountErr(e)
	}
	fillAttr(v, n.state.image.BlockSize, &out.Attr)
	return 0
}
func (n *fuseNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	v, e := n.imageNode()
	if e != nil {
		return nil, mountErr(e)
	}
	entries, e := n.state.image.Entries(v)
	if e != nil {
		return nil, mountErr(e)
	}
	var result []fuse.DirEntry
	for _, entry := range entries {
		if entry.Name == "." || entry.Name == ".." {
			continue
		}
		v, e := n.state.image.Inode(entry.Inode)
		if e != nil {
			return nil, mountErr(e)
		}
		result = append(result, fuse.DirEntry{Name: entry.Name, Ino: uint64(entry.Inode), Mode: uint32(v.Mode())})
	}
	return fs.NewListDirStream(result), 0
}
func (n *fuseNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	if flags&syscall.O_ACCMODE != syscall.O_RDONLY && n.state.editor == nil {
		return nil, 0, syscall.EROFS
	}
	return n.openHandle(), fuse.FOPEN_DIRECT_IO, 0
}

type mountFile struct {
	state  *mountState
	number uint32
	closed bool
}

func (n *fuseNode) openHandle() fs.FileHandle {
	if n.state.opened == nil {
		n.state.opened = map[uint32]int{}
	}
	n.state.opened[n.number]++
	return &mountFile{state: n.state, number: n.number}
}
func (f *mountFile) Release(ctx context.Context) syscall.Errno {
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	if !f.closed {
		f.state.opened[f.number]--
		f.closed = true
	}
	return 0
}
func (n *fuseNode) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	v, e := n.imageNode()
	if e != nil {
		return nil, mountErr(e)
	}
	read, e := n.state.image.ReadNodeAt(v, dest, off)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, mountErr(e)
	}
	return fuse.ReadResultData(dest[:read]), 0
}
func (n *fuseNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	v, e := n.imageNode()
	if e != nil {
		return nil, mountErr(e)
	}
	if v.Mode()&syscall.S_IFMT != syscall.S_IFLNK || v.Size() > 4096 {
		return nil, syscall.EINVAL
	}
	var b bytes.Buffer
	if e = n.state.image.Data(v, &b); e != nil {
		return nil, mountErr(e)
	}
	return b.Bytes(), 0
}
func (n *fuseNode) Write(ctx context.Context, f fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	if off < 0 {
		return 0, syscall.EINVAL
	}
	v, e := n.imageNode()
	if e != nil {
		return 0, mountErr(e)
	}
	size := max(v.Size(), uint64(off)+uint64(len(data)))
	status := n.state.mutate(func(ed *Editor) error { return ed.RewriteNode(n.number, off, data, size) })
	if status != 0 {
		return 0, status
	}
	return uint32(len(data)), 0
}
func (n *fuseNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	status := n.state.mutate(func(ed *Editor) error {
		if size, ok := in.GetSize(); ok {
			if e := ed.RewriteNode(n.number, 0, nil, size); e != nil {
				return e
			}
		}
		v, e := ed.Inode(n.number)
		if e != nil {
			return e
		}
		if mode, ok := in.GetMode(); ok {
			binio.LE.PutUint16(v.Raw[32:], v.Mode()&syscall.S_IFMT|uint16(mode)&07777)
		}
		if uid, ok := in.GetUID(); ok {
			binio.Put32(v.Raw, 8, uid)
		}
		if gid, ok := in.GetGID(); ok {
			binio.Put32(v.Raw, 12, gid)
		}
		if at, ok := in.GetATime(); ok {
			binio.Put32(v.Raw, 16, uint32(at.Unix()))
		}
		if mt, ok := in.GetMTime(); ok {
			binio.Put32(v.Raw, 20, uint32(mt.Unix()))
		}
		return ed.setNode(v)
	})
	if status == 0 {
		v, _ := n.imageNode()
		fillAttr(v, n.state.image.BlockSize, &out.Attr)
	}
	return status
}
func (n *fuseNode) create(ctx context.Context, name string, mode uint32, dir bool, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p := n.pathname(name)
	status := n.state.mutate(func(ed *Editor) error {
		var e error
		if dir {
			e = ed.Mkdir(p, false)
		} else {
			e = ed.WriteFile(p, bytes.NewReader(nil), 0, true)
		}
		if e != nil {
			return e
		}
		v, _, e := ed.Resolve(p)
		if e != nil {
			return e
		}
		binio.LE.PutUint16(v.Raw[32:], v.Mode()&syscall.S_IFMT|uint16(mode)&07777)
		if caller, ok := fuse.FromContext(ctx); ok {
			binio.Put32(v.Raw, 8, caller.Uid)
			binio.Put32(v.Raw, 12, caller.Gid)
		}
		return ed.setNode(v)
	})
	if status != 0 {
		return nil, status
	}
	v, _, e := n.state.image.Resolve(p)
	if e != nil {
		return nil, mountErr(e)
	}
	return n.child(ctx, v.Number, out)
}
func (n *fuseNode) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	child, status := n.create(ctx, name, mode, false, out)
	if status != 0 {
		return nil, nil, 0, status
	}
	node := child.Operations().(*fuseNode)
	return child, node.openHandle(), fuse.FOPEN_DIRECT_IO, 0
}
func (n *fuseNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	return n.create(ctx, name, mode, true, out)
}
func (n *fuseNode) remove(name string, dir bool) syscall.Errno {
	p := n.pathname(name)
	v, _, e := n.state.image.Resolve(p)
	if e != nil {
		return mountErr(e)
	}
	if (v.Mode()&syscall.S_IFMT == syscall.S_IFDIR) != dir {
		if dir {
			return syscall.ENOTDIR
		}
		return syscall.EISDIR
	}
	if n.state.opened[v.Number] > 0 && v.Links() <= 1 {
		return syscall.EBUSY
	}
	return n.state.mutate(func(ed *Editor) error { return ed.Remove(p, false) })
}
func (n *fuseNode) Unlink(ctx context.Context, name string) syscall.Errno {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	return n.remove(name, false)
}
func (n *fuseNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	return n.remove(name, true)
}
func (n *fuseNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	other, ok := newParent.(*fuseNode)
	if !ok || other.state != n.state {
		return syscall.EXDEV
	}
	if flags & ^uint32(1) != 0 {
		return syscall.ENOTSUP
	}
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	if target, _, e := n.state.image.Resolve(other.pathname(newName)); e == nil && n.state.opened[target.Number] > 0 && target.Links() <= 1 {
		return syscall.EBUSY
	}
	return n.state.mutate(func(ed *Editor) error { return ed.Rename(n.pathname(name), other.pathname(newName), flags&1 == 0) })
}
func (n *fuseNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	other, ok := target.(*fuseNode)
	if !ok || other.state != n.state {
		return nil, syscall.EXDEV
	}
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	status := n.state.mutate(func(ed *Editor) error { return ed.HardLink(other.pathname(""), n.pathname(name)) })
	if status != 0 {
		return nil, status
	}
	return n.child(ctx, other.number, out)
}
func (n *fuseNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	p := n.pathname(name)
	status := n.state.mutate(func(ed *Editor) error {
		if e := ed.Symlink(target, p); e != nil {
			return e
		}
		if caller, ok := fuse.FromContext(ctx); ok {
			v, _, e := ed.Resolve(p)
			if e != nil {
				return e
			}
			binio.Put32(v.Raw, 8, caller.Uid)
			binio.Put32(v.Raw, 12, caller.Gid)
			return ed.setNode(v)
		}
		return nil
	})
	if status != 0 {
		return nil, status
	}
	v, _, e := n.state.image.Resolve(p)
	if e != nil {
		return nil, mountErr(e)
	}
	return n.child(ctx, v.Number, out)
}
func (n *fuseNode) Fsync(ctx context.Context, f fs.FileHandle, flags uint32) syscall.Errno {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	if n.state.err != nil {
		return syscall.EIO
	}
	if n.state.editor == nil {
		return 0
	}
	return mountErr(n.state.editor.File.Sync())
}
func (n *fuseNode) Flush(ctx context.Context, f fs.FileHandle) syscall.Errno {
	return n.Fsync(ctx, f, 0)
}
func (n *fuseNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	n.state.mu.Lock()
	defer n.state.mu.Unlock()
	im := n.state.image
	out.Bsize = im.BlockSize
	out.Frsize = im.BlockSize
	out.Blocks = uint64(im.Blocks)
	out.Files = uint64(im.Inodes)
	out.NameLen = 510
	out.Bfree = uint64(binio.U32(im.Super, 64))
	out.Ffree = uint64(binio.U32(im.Super, 56))
	if ed := n.state.editor; ed != nil {
		out.Bfree = uint64(freeBlocks(ed.bitmapBytes, ed.Blocks, uint64(ed.reserved)))
		out.Ffree = 0
		for number := uint32(1); number <= ed.Inodes; number++ {
			v, e := ed.Inode(number)
			if e != nil {
				return mountErr(e)
			}
			if v.Mode() == 0 {
				out.Ffree++
			}
		}
	}
	out.Bavail = out.Bfree
	return 0
}

func Mount(ctx context.Context, input, output, mountpoint string, opt MountOptions, log io.Writer) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	st, e := os.Lstat(mountpoint)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("mountpoint must be an existing directory")
	}
	entries, e := os.ReadDir(mountpoint)
	if e != nil {
		return e
	}
	if len(entries) > 0 {
		return fmt.Errorf("mountpoint must be empty")
	}
	source, e := os.Open(input)
	if e != nil {
		return e
	}
	defer source.Close()
	st, e = source.Stat()
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("mount input must be a regular image")
	}
	serve := func(file *os.File, writable bool) error {
		state := &mountState{}
		var e error
		if writable {
			state.editor, e = NewEditor(file)
			if e == nil {
				state.image = state.editor.Image
			}
		} else {
			state.image, e = Open(binio.Reader{ReaderAt: file, Size: st.Size()})
		}
		if e != nil {
			return e
		}
		check, e := state.image.Check()
		if e != nil {
			return e
		}
		if len(check.Errors) > 0 {
			return fmt.Errorf("mount source invalid: %s", check.Errors[0])
		}
		root := &fuseNode{state: state, number: 1}
		mountOpt := &fs.Options{NullPermissions: true, MountOptions: fuse.MountOptions{FsName: "bb10mt-qnx6", Name: "qnx6", Debug: opt.Debug, Options: []string{"default_permissions"}}}
		if !writable {
			mountOpt.MountOptions.Options = append(mountOpt.MountOptions.Options, "ro")
		}
		server, e := fs.Mount(mountpoint, root, mountOpt)
		if e != nil {
			return e
		}
		done := make(chan struct{})
		go func() { server.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
			if e = server.Unmount(); e != nil {
				fmt.Fprintf(log, "Unmount failed: %v; manually unmount %q to finish safely.\n", e, mountpoint)
			}
			<-done
			if e != nil {
				return e
			}
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.err != nil {
			return fmt.Errorf("mount mutation failed; output discarded: %w", state.err)
		}
		if writable {
			return state.editor.Commit()
		}
		return nil
	}
	if output == "" {
		return serve(source, false)
	}
	return atomicfile.Write(output, func(f *os.File) error {
		if _, e := io.CopyN(f, source, st.Size()); e != nil {
			return e
		}
		return serve(f, true)
	})
}

var _ fs.NodeReader = (*fuseNode)(nil)
var _ fs.NodeWriter = (*fuseNode)(nil)
var _ fs.NodeRenamer = (*fuseNode)(nil)
