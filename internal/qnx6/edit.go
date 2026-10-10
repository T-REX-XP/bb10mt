package qnx6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/bb10root/bb10mt/internal/binio"
)

// Editor operates on a disposable working copy. Callers must never open the
// user's original image for editing. Commit updates metadata and verifies it.
type Editor struct {
	*Image
	File                 *os.File
	bitmapBytes          []byte
	bitmapPositions      []int64
	nextBlock, nextInode uint32
	reserved             uint32
}

func NewEditor(f *os.File) (*Editor, error) {
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	im, e := Open(binio.Reader{ReaderAt: f, Size: st.Size()})
	if e != nil {
		return nil, e
	}
	bitmap, pos, e := im.bitmap()
	if e != nil {
		return nil, e
	}
	ceil := func(n, d uint64) uint64 { return (n + d - 1) / d }
	extra := func(n uint64) uint64 {
		if n <= 16 {
			return 0
		}
		p := uint64(im.BlockSize / 4)
		a := ceil(n, p)
		result := a
		for a > 16 {
			a = ceil(a, p)
			result += a
		}
		return result
	}
	it := ceil(uint64(im.Inodes)*128, uint64(im.BlockSize))
	bm := ceil(ceil(uint64(im.Blocks), 8), uint64(im.BlockSize))
	reserved := 2 * (it + extra(it) + bm + extra(bm))
	if reserved >= uint64(im.Blocks) {
		return nil, fmt.Errorf("filesystem has no user area")
	}
	return &Editor{Image: im, File: f, bitmapBytes: bitmap, bitmapPositions: pos, nextBlock: uint32(reserved), nextInode: 1, reserved: uint32(reserved)}, nil
}
func (e *Editor) writeAt(b []byte, off int64) error {
	if _, err := e.File.WriteAt(b, off); err != nil {
		return err
	}
	// Only blocks overlapping this write become stale. Clearing the whole
	// cache discarded unchanged parent directories and inode tables after every
	// mutation, turning recursive removals into repeated disk scans.
	end := off + int64(len(b))
	for cachedOff := range e.cache {
		if off < cachedOff+int64(e.BlockSize) && cachedOff < end {
			delete(e.cache, cachedOff)
		}
	}
	if off+int64(len(b)) > e.R.Size {
		e.R.Size = off + int64(len(b))
	}
	return nil
}
func (e *Editor) alloc() (uint32, error) {
	for pass := 0; pass < 2; pass++ {
		stop := e.Blocks
		if pass == 1 {
			stop = e.nextBlock
			e.nextBlock = e.reserved
		}
		for n := e.nextBlock; n < stop; n++ {
			if e.bitmapBytes[n/8]&(1<<(n%8)) == 0 {
				e.bitmapBytes[n/8] |= 1 << (n % 8)
				e.nextBlock = n + 1
				return n, nil
			}
		}
	}
	return 0, fmt.Errorf("no free data blocks")
}
func (e *Editor) free(refs []uint32) error {
	for _, n := range refs {
		if n < e.reserved || n >= e.Blocks {
			return fmt.Errorf("attempt to free reserved/out-of-range block")
		}
		e.bitmapBytes[n/8] &^= 1 << (n % 8)
		e.nextBlock = min(e.nextBlock, n)
	}
	return nil
}
func (e *Editor) writeBlock(n uint32, b []byte) error {
	if len(b) > int(e.BlockSize) || n >= e.Blocks {
		return fmt.Errorf("invalid block write")
	}
	p := make([]byte, e.BlockSize)
	copy(p, b)
	return e.writeAt(p, e.DataStart+int64(n)*int64(e.BlockSize))
}
func (e *Editor) setNode(n Node) error {
	off := uint64(n.Number-1) * 128
	idx := off / uint64(e.BlockSize)
	within := off % uint64(e.BlockSize)
	if n.Number < 1 || n.Number > e.Inodes || idx >= uint64(len(e.inodeBlocks)) {
		return fmt.Errorf("inode write outside table")
	}
	return e.writeAt(n.Raw, e.inodeBlocks[idx]+int64(within))
}
func (e *Editor) newInode(mode uint16) (Node, error) {
	for pass := 0; pass < 2; pass++ {
		stop := e.Inodes + 1
		if pass == 1 {
			stop = e.nextInode
			e.nextInode = 1
		}
		for i := e.nextInode; i < stop; i++ {
			n, err := e.Inode(i)
			if err != nil {
				return n, err
			}
			if n.Mode() != 0 {
				continue
			}
			e.nextInode = i + 1
			clear(n.Raw)
			binio.LE.PutUint16(n.Raw[32:], mode)
			binio.LE.PutUint16(n.Raw[34:], 1)
			now := uint32(time.Now().Unix())
			for _, p := range []int{16, 20, 24, 28} {
				binio.Put32(n.Raw, p, now)
			}
			for p := 36; p < 100; p += 4 {
				binio.Put32(n.Raw, p, Missing)
			}
			return n, e.setNode(n)
		}
	}
	return Node{}, fmt.Errorf("no free inodes")
}

// chain replaces only the pointer tree; the caller owns data block lifetime.
func (e *Editor) chain(raw []byte, ptr, level int, blocks []uint32) error {
	old, e2 := e.references(raw, ptr, level, true)
	if e2 != nil {
		return e2
	}
	data, _, e2 := e.positions(raw, ptr, level, true)
	if e2 != nil {
		return e2
	}
	keep := map[uint32]bool{}
	for _, off := range data {
		if off >= 0 {
			keep[uint32((off-e.DataStart)/int64(e.BlockSize))] = true
		}
	}
	var oldMeta []uint32
	for _, n := range old {
		if !keep[n] {
			oldMeta = append(oldMeta, n)
		}
	}
	current := append([]uint32(nil), blocks...)
	depth := 0
	pointers := int(e.BlockSize / 4)
	for len(current) > 16 {
		if depth >= 3 {
			return fmt.Errorf("file exceeds supported indirection")
		}
		next := []uint32{}
		for start := 0; start < len(current); start += pointers {
			n, err := e.alloc()
			if err != nil {
				return err
			}
			b := bytes.Repeat([]byte{255}, int(e.BlockSize))
			for i, v := range current[start:min(start+pointers, len(current))] {
				binio.Put32(b, i*4, v)
			}
			if err = e.writeBlock(n, b); err != nil {
				return err
			}
			next = append(next, n)
		}
		current = next
		depth++
	}
	for i := 0; i < 16; i++ {
		binio.Put32(raw, ptr+i*4, Missing)
	}
	for i, v := range current {
		binio.Put32(raw, ptr+i*4, v)
	}
	raw[level] = byte(depth)
	return e.free(oldMeta)
}
func (e *Editor) writeData(n Node, r io.Reader, size uint64) error {
	if binio.U32(n.Raw, 104) != 0 {
		return fmt.Errorf("encrypted inode mutation unsupported")
	}
	if size > uint64(e.Blocks)*uint64(e.BlockSize) {
		return fmt.Errorf("file too large")
	}
	old, err := e.references(n.Raw, 36, 100, true)
	if err != nil {
		return err
	}
	oldData, _, err := e.positions(n.Raw, 36, 100, true)
	if err != nil {
		return err
	}
	dataSet := map[uint32]bool{}
	for _, off := range oldData {
		if off >= 0 {
			dataSet[uint32((off-e.DataStart)/int64(e.BlockSize))] = true
		}
	}
	count := (size + uint64(e.BlockSize) - 1) / uint64(e.BlockSize)
	blocks := make([]uint32, 0, count)
	buf := make([]byte, e.BlockSize)
	left := size
	for left > 0 {
		amount := min(left, uint64(e.BlockSize))
		clear(buf)
		if _, err = io.ReadFull(r, buf[:amount]); err != nil {
			return err
		}
		b, err := e.alloc()
		if err != nil {
			return err
		}
		if err = e.writeBlock(b, buf); err != nil {
			return err
		}
		blocks = append(blocks, b)
		left -= amount
	}
	if err = e.chain(n.Raw, 36, 100, blocks); err != nil {
		return err
	}
	binio.Put64(n.Raw, 0, size)
	now := uint32(time.Now().Unix())
	binio.Put32(n.Raw, 20, now)
	binio.Put32(n.Raw, 28, now)
	if err = e.setNode(n); err != nil {
		return err
	}
	var free []uint32
	for _, b := range old {
		if dataSet[b] {
			free = append(free, b)
		}
	}
	return e.free(free)
}
func (e *Editor) directoryBytes(n Node) ([]byte, error) {
	if n.Mode()&0xf000 != 0x4000 || n.Size() > 64<<20 {
		return nil, fmt.Errorf("invalid directory")
	}
	var b bytes.Buffer
	if err := e.Data(n, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func canonical(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if path.Clean(p) != p {
		return "", fmt.Errorf("noncanonical image path: %s", p)
	}
	return p, nil
}
func (e *Editor) parent(p string) (Node, string, error) {
	p, err := canonical(p)
	if err != nil {
		return Node{}, "", err
	}
	if p == "/" {
		return Node{}, "", fmt.Errorf("cannot replace root")
	}
	parent, _, err := e.Resolve(path.Dir(p))
	return parent, path.Base(p), err
}
func (e *Editor) addEntry(parent Node, name string, inode uint32) error {
	if len([]byte(name)) == 0 || len([]byte(name)) > 510 || name == "." || name == ".." {
		return fmt.Errorf("invalid entry name")
	}
	entries, err := e.Entries(parent)
	if err != nil {
		return err
	}
	for _, v := range entries {
		if v.Name == name {
			return fmt.Errorf("destination already exists: %s", name)
		}
	}
	raw, err := e.directoryBytes(parent)
	if err != nil {
		return err
	}
	b := make([]byte, 32)
	binio.Put32(b, 0, inode)
	if len(name) <= 27 {
		b[4] = byte(len(name))
		copy(b[5:], name)
	} else {
		// Names occupy one block in this format. Appending avoids changing indices
		// referenced by other directories, even when a name was previously removed.
		block, err := e.alloc()
		if err != nil {
			return err
		}
		data := make([]byte, e.BlockSize)
		binio.LE.PutUint16(data, uint16(len(name)))
		copy(data[2:], name)
		if err = e.writeBlock(block, data); err != nil {
			return err
		}
		names := make([]uint32, len(e.nameBlocks))
		for i, off := range e.nameBlocks {
			names[i] = uint32((off - e.DataStart) / int64(e.BlockSize))
		}
		idx := len(names)
		names = append(names, block)
		node := e.Super[232:312]
		if err = e.chain(node, 8, 72, names); err != nil {
			return err
		}
		binio.Put64(node, 0, uint64(len(names))*uint64(e.BlockSize))
		e.nameSize = binio.U64(node, 0)
		e.nameBlocks = append(e.nameBlocks, e.DataStart+int64(block)*int64(e.BlockSize))
		b[4] = 255
		binio.Put32(b, 8, uint32(idx))
		if binio.U32(e.Super, 24)&0x100 != 0 {
			binio.Put32(b, 12, LongNameChecksum([]byte(name)))
		}
	}
	return e.writeData(parent, bytes.NewReader(append(raw, b...)), uint64(len(raw)+32))
}
func (e *Editor) Mkdir(p string, parents bool) error {
	p, err := canonical(p)
	if err != nil {
		return err
	}
	if p == "/" {
		return nil
	}
	existing, _, err := e.Resolve(p)
	if err == nil {
		if existing.Mode()&0xf000 != 0x4000 {
			return fmt.Errorf("mkdir destination is not directory")
		}
		if parents {
			return nil
		}
		return fmt.Errorf("directory exists")
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	if parents {
		if err = e.Mkdir(path.Dir(p), true); err != nil {
			return err
		}
	}
	parent, name, err := e.parent(p)
	if err != nil {
		return err
	}
	n, err := e.newInode(0x4000 | 0755)
	if err != nil {
		return err
	}
	binio.LE.PutUint16(n.Raw[34:], 2)
	data := make([]byte, 64)
	binio.Put32(data, 0, n.Number)
	data[4] = 1
	data[5] = '.'
	binio.Put32(data, 32, parent.Number)
	data[36] = 2
	copy(data[37:], "..")
	if err = e.writeData(n, bytes.NewReader(data), 64); err != nil {
		return err
	}
	if err = e.addEntry(parent, name, n.Number); err != nil {
		return err
	}
	parent, err = e.Inode(parent.Number)
	if err != nil {
		return err
	}
	if parent.Links() == 65535 {
		return fmt.Errorf("directory link overflow")
	}
	binio.LE.PutUint16(parent.Raw[34:], parent.Links()+1)
	return e.setNode(parent)
}
func (e *Editor) WriteFile(p string, r io.Reader, size uint64, exclusive bool) error {
	n, _, err := e.Resolve(p)
	if err == nil {
		if exclusive {
			return fmt.Errorf("destination exists: %s", p)
		}
		if n.Mode()&0xf000 != 0x8000 {
			return fmt.Errorf("destination is not a regular file")
		}
		return e.writeData(n, r, size)
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	parent, name, err := e.parent(p)
	if err != nil {
		return err
	}
	n, err = e.newInode(0x8000 | 0666)
	if err != nil {
		return err
	}
	if err = e.writeData(n, r, size); err != nil {
		return err
	}
	return e.addEntry(parent, name, n.Number)
}
func (e *Editor) Remove(p string, recursive bool) error {
	p, err := canonical(p)
	if err != nil {
		return err
	}
	parent, name, err := e.parent(p)
	if err != nil {
		return err
	}
	n, _, err := e.Resolve(p)
	if err != nil {
		return err
	}
	if n.Mode()&0xf000 == 0x4000 {
		entries, err := e.Entries(n)
		if err != nil {
			return err
		}
		for _, v := range entries {
			if v.Name == "." || v.Name == ".." {
				continue
			}
			if !recursive {
				return fmt.Errorf("directory is not empty")
			}
			if err = e.Remove(path.Join(p, v.Name), true); err != nil {
				return err
			}
		}
		parent, err = e.Inode(parent.Number)
		if err != nil {
			return err
		}
		if parent.Links() == 0 {
			return fmt.Errorf("invalid parent link count")
		}
		binio.LE.PutUint16(parent.Raw[34:], parent.Links()-1)
		if err = e.setNode(parent); err != nil {
			return err
		}
	}
	parent, err = e.Inode(parent.Number)
	if err != nil {
		return err
	}
	raw, err := e.directoryBytes(parent)
	if err != nil {
		return err
	}
	entries, err := e.Entries(parent)
	if err != nil {
		return err
	}
	found := false
	for _, v := range entries {
		if v.Name == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("directory entry missing")
	}
	for off := 0; off < len(raw); off += 32 {
		if binio.U32(raw, off) != n.Number {
			continue
		}
		b := raw[off : off+32]
		entryName := ""
		if b[4] <= 27 {
			entryName = string(b[5 : 5+int(b[4])])
		} else if b[4] == 255 {
			idx := uint64(binio.U32(b, 8))
			h, err := e.tableRead(e.nameBlocks, e.nameSize, idx*uint64(e.BlockSize), 2)
			if err != nil {
				return err
			}
			nb, err := e.tableRead(e.nameBlocks, e.nameSize, idx*uint64(e.BlockSize)+2, int(binio.LE.Uint16(h)))
			if err != nil {
				return err
			}
			entryName = string(nb)
		}
		if entryName == name {
			clear(b)
			break
		}
	}
	if err = e.writeData(parent, bytes.NewReader(raw), uint64(len(raw))); err != nil {
		return err
	}
	n, err = e.Inode(n.Number)
	if err != nil {
		return err
	}
	if n.Mode()&0xf000 == 0x4000 || n.Links() <= 1 {
		refs, err := e.references(n.Raw, 36, 100, true)
		if err != nil {
			return err
		}
		if err = e.free(refs); err != nil {
			return err
		}
		clear(n.Raw)
		e.nextInode = min(e.nextInode, n.Number)
	} else {
		binio.LE.PutUint16(n.Raw[34:], n.Links()-1)
	}
	return e.setNode(n)
}
func (e *Editor) Commit() error {
	left := len(e.bitmapBytes)
	at := 0
	for _, off := range e.bitmapPositions {
		if left == 0 {
			break
		}
		amount := min(left, int(e.BlockSize))
		if err := e.writeAt(e.bitmapBytes[at:at+amount], off); err != nil {
			return err
		}
		left -= amount
		at += amount
	}
	binio.Put32(e.Super, 64, freeBlocks(e.bitmapBytes, e.Blocks, uint64(e.reserved)))
	var inodes uint32
	for n := uint32(1); n <= e.Inodes; n++ {
		v, err := e.Inode(n)
		if err != nil {
			return err
		}
		if v.Mode() != 0 {
			inodes++
		}
	}
	binio.Put32(e.Super, 56, e.Inodes-inodes)
	binio.Put32(e.Super, 4, CRC(e.Super[8:]))
	if err := e.writeAt(e.Super, e.SuperOffset); err != nil {
		return err
	}
	if err := e.File.Sync(); err != nil {
		return err
	}
	im, err := Open(e.R)
	if err != nil {
		return err
	}
	report, err := im.Check()
	if err != nil {
		return err
	}
	if len(report.Errors) > 0 {
		return fmt.Errorf("edited filesystem has %d errors: %s", len(report.Errors), report.Errors[0])
	}
	return nil
}
