package qnx6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bb10root/bb10mt/internal/binio"
)

// ReadNodeAt reads a bounded range, including sparse zero blocks, without
// materializing the entire file. The caller serializes access to Image caches.
func (im *Image) ReadNodeAt(n Node, b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative file offset")
	}
	if len(b) == 0 {
		return 0, nil
	}
	if binio.U32(n.Raw, 104) != 0 {
		return 0, fmt.Errorf("encrypted inode unsupported")
	}
	if uint64(off) >= n.Size() {
		return 0, io.EOF
	}
	positions, size, e := im.positions(n.Raw, 36, 100, true)
	if e != nil {
		return 0, e
	}
	wanted := int(min(uint64(len(b)), size-uint64(off)))
	done := 0
	for done < wanted {
		index := uint64(off) / uint64(im.BlockSize)
		within := int(uint64(off) % uint64(im.BlockSize))
		amount := min(wanted-done, int(im.BlockSize)-within)
		p := positions[index]
		if p < 0 {
			clear(b[done : done+amount])
		} else {
			if _, e = im.R.ReadAt(b[done:done+amount], p+int64(within)); e != nil {
				return done, e
			}
		}
		done += amount
		off += int64(amount)
	}
	if done < len(b) {
		return done, io.EOF
	}
	return done, nil
}

func (e *Editor) dropEntry(parent Node, name string, number uint32) error {
	raw, err := e.directoryBytes(parent)
	if err != nil {
		return err
	}
	for off := 0; off < len(raw); off += 32 {
		b := raw[off : off+32]
		if binio.U32(b, 0) != number {
			continue
		}
		entryName := ""
		switch {
		case b[4] <= 27:
			entryName = string(b[5 : 5+int(b[4])])
		case b[4] == 255:
			idx := uint64(binio.U32(b, 8)) * uint64(e.BlockSize)
			h, err := e.tableRead(e.nameBlocks, e.nameSize, idx, 2)
			if err != nil {
				return err
			}
			value, err := e.tableRead(e.nameBlocks, e.nameSize, idx+2, int(binio.LE.Uint16(h)))
			if err != nil {
				return err
			}
			entryName = string(value)
		}
		if entryName == name {
			clear(b)
			return e.writeData(parent, bytes.NewReader(raw), uint64(len(raw)))
		}
	}
	return ErrNotFound
}
func (e *Editor) HardLink(source, destination string) error {
	n, _, err := e.Resolve(source)
	if err != nil {
		return err
	}
	if n.Mode()&0xf000 == 0x4000 {
		return fmt.Errorf("cannot hard-link a directory")
	}
	if n.Links() == 65535 {
		return fmt.Errorf("link count overflow")
	}
	if _, _, err = e.Resolve(destination); err == nil {
		return fmt.Errorf("destination exists")
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	parent, name, err := e.parent(destination)
	if err != nil {
		return err
	}
	if err = e.addEntry(parent, name, n.Number); err != nil {
		return err
	}
	n, err = e.Inode(n.Number)
	if err != nil {
		return err
	}
	binio.LE.PutUint16(n.Raw[34:], n.Links()+1)
	return e.setNode(n)
}
func (e *Editor) Symlink(target, destination string) error {
	if target == "" || len(target) > 4096 || strings.ContainsRune(target, 0) {
		return fmt.Errorf("invalid symlink target")
	}
	if _, _, err := e.Resolve(destination); err == nil {
		return fmt.Errorf("destination exists")
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	parent, name, err := e.parent(destination)
	if err != nil {
		return err
	}
	n, err := e.newInode(0xa000 | 0777)
	if err != nil {
		return err
	}
	if err = e.writeData(n, strings.NewReader(target), uint64(len(target))); err != nil {
		return err
	}
	return e.addEntry(parent, name, n.Number)
}
func (e *Editor) Rename(source, destination string, replace bool) error {
	source, err := canonical(source)
	if err != nil {
		return err
	}
	destination, err = canonical(destination)
	if err != nil {
		return err
	}
	if source == destination {
		return nil
	}
	if source == "/" || destination == "/" || strings.HasPrefix(destination, source+"/") {
		return fmt.Errorf("invalid rename extent")
	}
	n, _, err := e.Resolve(source)
	if err != nil {
		return err
	}
	oldParent, oldName, err := e.parent(source)
	if err != nil {
		return err
	}
	newParent, newName, err := e.parent(destination)
	if err != nil {
		return err
	}
	other, _, err := e.Resolve(destination)
	if err == nil {
		if other.Number == n.Number {
			return nil
		}
		if !replace {
			return fmt.Errorf("destination exists")
		}
		if (other.Mode()&0xf000 == 0x4000) != (n.Mode()&0xf000 == 0x4000) {
			return fmt.Errorf("rename type mismatch")
		}
		if err = e.Remove(destination, false); err != nil {
			return err
		}
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	newParent, err = e.Inode(newParent.Number)
	if err != nil {
		return err
	}
	if err = e.addEntry(newParent, newName, n.Number); err != nil {
		return err
	}
	oldParent, err = e.Inode(oldParent.Number)
	if err != nil {
		return err
	}
	if err = e.dropEntry(oldParent, oldName, n.Number); err != nil {
		return err
	}
	if n.Mode()&0xf000 == 0x4000 && oldParent.Number != newParent.Number {
		n, err = e.Inode(n.Number)
		if err != nil {
			return err
		}
		raw, err := e.directoryBytes(n)
		if err != nil {
			return err
		}
		found := false
		for off := 0; off < len(raw); off += 32 {
			b := raw[off : off+32]
			if b[4] == 2 && string(b[5:7]) == ".." {
				binio.Put32(b, 0, newParent.Number)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("renamed directory has no parent entry")
		}
		if err = e.writeData(n, bytes.NewReader(raw), uint64(len(raw))); err != nil {
			return err
		}
		for _, change := range []struct {
			number uint32
			delta  int
		}{{oldParent.Number, -1}, {newParent.Number, 1}} {
			parent, err := e.Inode(change.number)
			if err != nil {
				return err
			}
			links := int(parent.Links()) + change.delta
			if links < 1 || links > 65535 {
				return fmt.Errorf("rename link count overflow")
			}
			binio.LE.PutUint16(parent.Raw[34:], uint16(links))
			if err = e.setNode(parent); err != nil {
				return err
			}
		}
	}
	return nil
}

// RewriteNode streams old contents into a disposable host file for random
// writes/truncation. A failed mutation must discard the caller's working image.
func (e *Editor) RewriteNode(number uint32, offset int64, data []byte, size uint64) error {
	n, err := e.Inode(number)
	if err != nil {
		return err
	}
	if n.Mode()&0xf000 != 0x8000 || offset < 0 || size > uint64(e.Blocks)*uint64(e.BlockSize) || uint64(offset) > size || uint64(len(data)) > size-uint64(offset) {
		return fmt.Errorf("invalid file rewrite range")
	}
	tmp, err := os.CreateTemp(filepath.Dir(e.File.Name()), ".bb10mt-file-*")
	if err != nil {
		return err
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()
	if err = e.Data(n, &prefixWriter{Writer: tmp, remaining: min(n.Size(), size)}); err != nil {
		return err
	}
	if err = tmp.Truncate(int64(size)); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err = tmp.WriteAt(data, offset); err != nil {
			return err
		}
	}
	if _, err = tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return e.writeData(n, tmp, size)
}

type prefixWriter struct {
	io.Writer
	remaining uint64
}

func (w *prefixWriter) Write(b []byte) (int, error) {
	n := int(min(uint64(len(b)), w.remaining))
	if n > 0 {
		written, e := w.Writer.Write(b[:n])
		if e != nil {
			return written, e
		}
		if written != n {
			return written, io.ErrShortWrite
		}
		w.remaining -= uint64(n)
	}
	return len(b), nil
}
