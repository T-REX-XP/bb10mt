package qnx6

import (
	"bytes"
	"fmt"
	"os"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
)

func Mkfs(output string, blocks, inodes, blockSize uint32) error {
	if blockSize < 512 || blockSize > 65536 || blockSize&(blockSize-1) != 0 {
		return fmt.Errorf("block size must be a power of two from 512 to 65536")
	}
	if inodes < 2 || blocks < 16 || inodes > 16<<20 {
		return fmt.Errorf("invalid filesystem geometry")
	}
	ceil := func(n, d uint64) uint64 { return (n + d - 1) / d }
	ptrs := uint64(blockSize / 4)
	extra := func(n uint64) uint64 {
		var result uint64
		for n > 16 {
			n = ceil(n, ptrs)
			result += n
		}
		return result
	}
	it := ceil(uint64(inodes)*128, uint64(blockSize))
	bm := ceil(ceil(uint64(blocks), 8), uint64(blockSize))
	sys := it + extra(it) + bm + extra(bm)
	reserved := sys * 2
	if reserved+2 >= uint64(blocks) || sys > 1<<24 {
		return fmt.Errorf("not enough blocks for metadata")
	}
	start := int64(12288)
	sbOffset := int64(8192)
	if blockSize > 4096 {
		start = int64(blockSize)
		sbOffset = 0
	}
	return atomicfile.Write(output, func(f *os.File) error {
		if err := f.Truncate(start + int64(blocks)*int64(blockSize) + int64(blockSize)); err != nil {
			return err
		}
		sb := make([]byte, 512)
		binio.Put32(sb, 0, Magic)
		binio.Put64(sb, 8, 1)
		binio.Put32(sb, 24, 0x100)
		binio.LE.PutUint16(sb[28:], 4)
		binio.Put32(sb, 48, blockSize)
		binio.Put32(sb, 52, inodes)
		binio.Put32(sb, 56, inodes-2)
		binio.Put32(sb, 60, blocks)
		binio.Put32(sb, 64, blocks-uint32(reserved)-2)
		next := uint32(0)
		writeBlock := func(n uint32, b []byte) error { _, e := f.WriteAt(b, start+int64(n)*int64(blockSize)); return e }
		chain := func(raw []byte, n uint64) error {
			data := make([]uint32, n)
			for i := range data {
				data[i] = next
				next++
			}
			binio.Put64(raw, 0, n*uint64(blockSize))
			depth := 0
			for len(data) > 16 {
				parents := []uint32{}
				for p := 0; p < len(data); p += int(ptrs) {
					b := bytes.Repeat([]byte{255}, int(blockSize))
					for i, v := range data[p:min(p+int(ptrs), len(data))] {
						binio.Put32(b, i*4, v)
					}
					idx := next
					next++
					if err := writeBlock(idx, b); err != nil {
						return err
					}
					parents = append(parents, idx)
				}
				data = parents
				depth++
			}
			for i := 0; i < 16; i++ {
				binio.Put32(raw, 8+i*4, Missing)
			}
			for i, v := range data {
				binio.Put32(raw, 8+i*4, v)
			}
			raw[72] = byte(depth)
			return nil
		}
		if err := chain(sb[72:152], it); err != nil {
			return err
		}
		if err := chain(sb[152:232], bm); err != nil {
			return err
		}
		binio.Put64(sb, 152, ceil(uint64(blocks), 8))
		for _, off := range []int{232, 312, 392} {
			for i := 0; i < 16; i++ {
				binio.Put32(sb, off+8+i*4, Missing)
			}
		}
		if uint64(next) != sys {
			return fmt.Errorf("metadata layout mismatch")
		}
		bitmap := make([]byte, bm*uint64(blockSize))
		for n := uint32(0); uint64(n) < reserved+2; n++ {
			bitmap[n/8] |= 1 << (n % 8)
		}
		// Bitmap is placed immediately after the inode data/pointer tree.
		bmStart := uint32(it + extra(it))
		if _, err := f.WriteAt(bitmap, start+int64(bmStart)*int64(blockSize)); err != nil {
			return err
		}
		inodeData := make([]byte, 256)
		for i := 0; i < 2; i++ {
			raw := inodeData[i*128 : (i+1)*128]
			binio.Put64(raw, 0, uint64(blockSize))
			raw[101] = 1
			binio.LE.PutUint16(raw[32:], 0x4000|0755)
			binio.LE.PutUint16(raw[34:], 2)
			if i == 0 {
				binio.LE.PutUint16(raw[34:], 3)
			}
			for p := 36; p < 100; p += 4 {
				binio.Put32(raw, p, Missing)
			}
			binio.Put32(raw, 36, uint32(reserved)+uint32(i))
		}
		if _, err := f.WriteAt(inodeData, start); err != nil {
			return err
		}
		root := make([]byte, blockSize)
		entry := func(b []byte, p int, n uint32, name string) {
			binio.Put32(b, p, n)
			b[p+4] = byte(len(name))
			copy(b[p+5:], name)
		}
		entry(root, 0, 1, ".")
		entry(root, 32, 1, "..")
		entry(root, 64, 2, ".boot")
		if err := writeBlock(uint32(reserved), root); err != nil {
			return err
		}
		clear(root)
		entry(root, 0, 2, ".")
		entry(root, 32, 1, "..")
		if err := writeBlock(uint32(reserved)+1, root); err != nil {
			return err
		}
		binio.Put32(sb, 4, CRC(sb[8:]))
		if _, err := f.WriteAt(sb, sbOffset); err != nil {
			return err
		}
		if _, err := f.WriteAt(sb, start+int64(blocks)*int64(blockSize)); err != nil {
			return err
		}
		st, err := f.Stat()
		if err != nil {
			return err
		}
		im, err := Open(binio.Reader{ReaderAt: f, Size: st.Size()})
		if err != nil {
			return err
		}
		report, err := im.Check()
		if err != nil {
			return err
		}
		if len(report.Errors) > 0 {
			return fmt.Errorf("new filesystem invalid: %s", report.Errors[0])
		}
		return nil
	})
}
