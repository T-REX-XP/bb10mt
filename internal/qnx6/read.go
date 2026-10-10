package qnx6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bb10root/bb10mt/internal/binio"
)

const Magic = 0x97e6eedd
const Missing = 0xffffffff

var ErrNotFound = errors.New("image path missing")

type Image struct {
	R                         binio.Reader
	SuperOffset               int64
	PrimaryOffset             int64
	Super                     []byte
	BlockSize, Blocks, Inodes uint32
	DataStart                 int64
	inodeBlocks, nameBlocks   []int64
	inodeSize, nameSize       uint64
	cache                     map[int64][]byte
}
type Node struct {
	Raw    []byte
	Number uint32
}

func (n Node) Size() uint64  { return binio.U64(n.Raw, 0) }
func (n Node) Mode() uint16  { return binio.LE.Uint16(n.Raw[32:34]) }
func (n Node) UID() uint32   { return binio.U32(n.Raw, 8) }
func (n Node) GID() uint32   { return binio.U32(n.Raw, 12) }
func (n Node) Links() uint16 { return binio.LE.Uint16(n.Raw[34:36]) }

type Entry struct {
	Inode            uint32
	Name             string
	ChecksumOffset   int64
	Stored, Expected uint32
}

func Open(r binio.Reader) (*Image, error) {
	im := &Image{R: r, cache: map[int64][]byte{}}
	var valid [][]byte
	var positions []int64
	for off := int64(0); off+512 <= min(r.Size, 65536); off += 512 {
		b, e := r.Bytes(off, 512)
		if e != nil {
			return nil, e
		}
		if binio.U32(b, 0) == Magic && binio.U32(b, 4) == CRC(b[8:]) {
			valid = append(valid, b)
			positions = append(positions, off)
		}
	}
	if len(valid) == 0 {
		return nil, fmt.Errorf("no valid little-endian QNX6 superblock (CRC required)")
	}
	sb := valid[0]
	pos := positions[0]
	bs := binio.U32(sb, 48)
	if bs < 512 || bs > 65536 || bs&(bs-1) != 0 {
		return nil, fmt.Errorf("unsupported QNX6 block size %d", bs)
	}
	// A complete image can carry a second superblock after its data region;
	// legacy compact images omit that unused tail. Highest serial wins.
	start := int64(12288)
	if bs > 4096 {
		start = int64(bs)
	}
	backup := start + int64(binio.U32(sb, 60))*int64(bs)
	for _, candidate := range positions[1:] {
		if candidate != backup {
			return nil, fmt.Errorf("ambiguous QNX6 primary superblocks")
		}
	}
	if backup+512 <= r.Size {
		b, e := r.Bytes(backup, 512)
		if e != nil {
			return nil, e
		}
		if binio.U32(b, 0) == Magic && binio.U32(b, 4) == CRC(b[8:]) && binio.U64(b, 8) > binio.U64(sb, 8) {
			if binio.U32(b, 48) != bs || binio.U32(b, 60) != binio.U32(sb, 60) {
				return nil, fmt.Errorf("inconsistent secondary geometry")
			}
			sb = b
			pos = backup
		}
	}
	if binio.LE.Uint16(sb[28:30]) != 4 {
		return nil, fmt.Errorf("unsupported QNX6 version")
	}
	if sb[484] != 0 {
		return nil, fmt.Errorf("unsupported inode checksum mode %d", sb[484])
	}
	im.SuperOffset = pos
	im.PrimaryOffset = positions[0]
	im.Super = sb
	im.BlockSize = bs
	im.Blocks = binio.U32(sb, 60)
	im.Inodes = binio.U32(sb, 52)
	im.DataStart = start
	if im.Inodes == 0 || im.Blocks == 0 {
		return nil, fmt.Errorf("invalid QNX6 counts")
	}
	var e error
	im.inodeBlocks, im.inodeSize, e = im.positions(sb[72:152], 8, 72, false)
	if e != nil {
		return nil, fmt.Errorf("inode table: %w", e)
	}
	if im.inodeSize < uint64(im.Inodes)*128 {
		return nil, fmt.Errorf("inode table shorter than inode count")
	}
	im.nameBlocks, im.nameSize, e = im.positions(sb[232:312], 8, 72, false)
	if e != nil {
		return nil, fmt.Errorf("long names: %w", e)
	}
	return im, nil
}
func (im *Image) block(n uint32) (int64, error) {
	if n >= im.Blocks {
		return 0, fmt.Errorf("block %d outside filesystem", n)
	}
	off := im.DataStart + int64(n)*int64(im.BlockSize)
	return off, im.R.Range(off, int64(im.BlockSize))
}
func (im *Image) cached(off int64) ([]byte, error) {
	if b, ok := im.cache[off]; ok {
		return b, nil
	}
	b, e := im.R.Bytes(off, int64(im.BlockSize))
	if e != nil {
		return nil, e
	}
	if len(im.cache) >= 512 {
		clear(im.cache)
	}
	im.cache[off] = b
	return b, nil
}
func (im *Image) positions(raw []byte, ptr, level int, sparse bool) ([]int64, uint64, error) {
	size := binio.U64(raw, 0)
	depth := int(raw[level])
	if depth > 3 {
		return nil, 0, fmt.Errorf("unsupported QNX6 indirection depth")
	}
	count := size / uint64(im.BlockSize)
	if size%uint64(im.BlockSize) != 0 {
		count++
	}
	if count > uint64(im.Blocks) || count > 16<<20 {
		return nil, 0, fmt.Errorf("inode extent too large")
	}
	result := make([]int64, 0, int(count))
	stack := map[uint32]bool{}
	var walk func(uint32, int) error
	walk = func(n uint32, d int) error {
		if len(result) >= int(count) {
			return nil
		}
		if n == Missing {
			if !sparse {
				return fmt.Errorf("missing metadata block")
			}
			capacity := uint64(1)
			for i := 0; i < d; i++ {
				capacity *= uint64(im.BlockSize / 4)
			}
			for k := uint64(0); k < capacity && len(result) < int(count); k++ {
				result = append(result, -1)
			}
			return nil
		}
		off, e := im.block(n)
		if e != nil {
			return e
		}
		if d == 0 {
			result = append(result, off)
			return nil
		}
		if stack[n] {
			return fmt.Errorf("cyclic indirect blocks")
		}
		stack[n] = true
		defer delete(stack, n)
		b, e := im.cached(off)
		if e != nil {
			return e
		}
		for p := 0; p < len(b) && len(result) < int(count); p += 4 {
			if e = walk(binio.U32(b, p), d-1); e != nil {
				return e
			}
		}
		return nil
	}
	for i := 0; i < 16 && len(result) < int(count); i++ {
		if e := walk(binio.U32(raw, ptr+i*4), depth); e != nil {
			return nil, 0, e
		}
	}
	if len(result) != int(count) {
		return nil, 0, fmt.Errorf("incomplete block chain")
	}
	return result, size, nil
}
func (im *Image) tableRead(blocks []int64, size uint64, off uint64, n int) ([]byte, error) {
	if off > size || uint64(n) > size-off {
		return nil, fmt.Errorf("metadata range outside table")
	}
	b := make([]byte, n)
	done := 0
	for done < n {
		idx := off / uint64(im.BlockSize)
		within := off % uint64(im.BlockSize)
		if idx >= uint64(len(blocks)) {
			return nil, fmt.Errorf("table extent missing")
		}
		block, e := im.cached(blocks[idx])
		if e != nil {
			return nil, e
		}
		amount := min(n-done, len(block)-int(within))
		copy(b[done:], block[int(within):int(within)+amount])
		done += amount
		off += uint64(amount)
	}
	return b, nil
}
func (im *Image) Inode(n uint32) (Node, error) {
	if n < 1 || n > im.Inodes {
		return Node{}, fmt.Errorf("invalid inode %d", n)
	}
	b, e := im.tableRead(im.inodeBlocks, im.inodeSize, uint64(n-1)*128, 128)
	return Node{b, n}, e
}
func (im *Image) Data(n Node, w io.Writer) error {
	if binio.U32(n.Raw, 104) != 0 {
		return fmt.Errorf("encrypted inode %d unsupported", n.Number)
	}
	blocks, size, e := im.positions(n.Raw, 36, 100, true)
	if e != nil {
		return e
	}
	zero := make([]byte, im.BlockSize)
	for _, off := range blocks {
		amount := min(size, uint64(im.BlockSize))
		if off < 0 {
			if _, e = w.Write(zero[:amount]); e != nil {
				return e
			}
		} else {
			if _, e = io.CopyN(w, io.NewSectionReader(im.R.ReaderAt, off, int64(amount)), int64(amount)); e != nil {
				return e
			}
		}
		size -= amount
	}
	return nil
}
func (im *Image) Entries(n Node) ([]Entry, error) {
	if n.Mode()&0xf000 != 0x4000 {
		return nil, fmt.Errorf("inode %d is not a directory", n.Number)
	}
	if n.Size()%32 != 0 {
		return nil, fmt.Errorf("unaligned directory size")
	}
	if n.Size() > 64<<20 {
		return nil, fmt.Errorf("directory too large")
	}
	blocks, _, e := im.positions(n.Raw, 36, 100, false)
	if e != nil {
		return nil, e
	}
	result := []Entry{}
	seen := map[string]bool{}
	for off := uint64(0); off < n.Size(); off += 32 {
		b, e := im.tableRead(blocks, n.Size(), off, 32)
		if e != nil {
			return nil, e
		}
		ino := binio.U32(b, 0)
		if ino == 0 || ino == Missing {
			continue
		}
		if ino > im.Inodes {
			return nil, fmt.Errorf("directory inode out of bounds")
		}
		entry := Entry{Inode: ino, ChecksumOffset: -1}
		length := int(b[4])
		var name []byte
		if length == 255 {
			idx := uint64(binio.U32(b, 8))
			p := idx * uint64(im.BlockSize)
			h, e := im.tableRead(im.nameBlocks, im.nameSize, p, 2)
			if e != nil {
				return nil, e
			}
			length = int(binio.LE.Uint16(h))
			if length < 28 || length > 510 {
				return nil, fmt.Errorf("invalid long-name length")
			}
			name, e = im.tableRead(im.nameBlocks, im.nameSize, p+2, length)
			if e != nil {
				return nil, e
			}
			if binio.U32(im.Super, 24)&0x100 != 0 {
				entry.ChecksumOffset = blocks[off/uint64(im.BlockSize)] + int64(off%uint64(im.BlockSize)) + 12
				entry.Stored = binio.U32(b, 12)
				entry.Expected = LongNameChecksum(name)
			}
		} else if length > 0 && length <= 27 {
			name = b[5 : 5+length]
		} else {
			return nil, fmt.Errorf("encrypted/invalid directory entry")
		}
		if bytes.IndexByte(name, 0) >= 0 || bytes.IndexByte(name, '/') >= 0 {
			return nil, fmt.Errorf("invalid filename bytes")
		}
		entry.Name = string(name)
		if seen[entry.Name] {
			return nil, fmt.Errorf("duplicate directory name %q", entry.Name)
		}
		seen[entry.Name] = true
		result = append(result, entry)
	}
	return result, nil
}
func (im *Image) Resolve(path string) (Node, []Entry, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	n, e := im.Inode(1)
	if e != nil {
		return n, nil, e
	}
	var bad []Entry
	if path == "/" || path == "" {
		return n, bad, nil
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return Node{}, nil, fmt.Errorf("noncanonical image path")
		}
		entries, e := im.Entries(n)
		if e != nil {
			return n, nil, e
		}
		found := false
		for _, v := range entries {
			if v.Name == part {
				if v.ChecksumOffset >= 0 && v.Stored != v.Expected {
					bad = append(bad, v)
				}
				n, e = im.Inode(v.Inode)
				if e != nil {
					return n, nil, e
				}
				found = true
				break
			}
		}
		if !found {
			return n, nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
	}
	return n, bad, nil
}

func (im *Image) ReadFile(p string, limit uint64) ([]byte, error) {
	n, _, e := im.Resolve(p)
	if e != nil {
		return nil, e
	}
	if n.Mode()&0xf000 != 0x8000 || n.Size() > limit {
		return nil, fmt.Errorf("invalid regular file size/type: %s", p)
	}
	var b bytes.Buffer
	if e = im.Data(n, &b); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
