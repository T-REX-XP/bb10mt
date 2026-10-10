package qnx6

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
)

type CompactReport struct {
	MovedBlocks int   `json:"movedBlocks"`
	InputBytes  int64 `json:"inputBytes"`
	OutputBytes int64 `json:"outputBytes"`
}

// Compact moves user blocks into holes and omits the unallocated physical tail.
// Logical geometry and inode identities are preserved, as in legacy compact
// images. The active superblock is retained at the primary location.
func Compact(input, output string) (CompactReport, error) {
	var report CompactReport
	source, err := os.Open(input)
	if err != nil {
		return report, err
	}
	defer source.Close()
	st, err := source.Stat()
	if err != nil {
		return report, err
	}
	report.InputBytes = st.Size()
	im, err := Open(binio.Reader{ReaderAt: source, Size: st.Size()})
	if err != nil {
		return report, err
	}
	check, err := im.Check()
	if err != nil {
		return report, err
	}
	if len(check.Errors) != 0 {
		return report, fmt.Errorf("source filesystem invalid: %s", check.Errors[0])
	}
	bitmap, bitmapPositions, err := im.bitmap()
	if err != nil {
		return report, err
	}
	reserved := uint32(reservedBlocks(im.Inodes, im.Blocks, im.BlockSize))
	used := func(n uint32) bool { return bitmap[n/8]&(1<<(n%8)) != 0 }
	move := map[uint32]uint32{}
	low, high := reserved, im.Blocks-1
	for low < high {
		for low < high && used(low) {
			low++
		}
		for high > low && !used(high) {
			high--
		}
		if low >= high {
			break
		}
		move[high] = low
		bitmap[low/8] |= 1 << (low % 8)
		bitmap[high/8] &^= 1 << (high % 8)
		low++
		high--
	}
	mapBlock := func(n uint32) uint32 {
		if v, ok := move[n]; ok {
			return v
		}
		return n
	}
	report.MovedBlocks = len(move)
	last := im.Blocks - 1
	for last > 0 && !used(last) {
		last--
	}
	report.OutputBytes = max(im.PrimaryOffset+512, im.DataStart+int64(last+1)*int64(im.BlockSize))
	err = atomicfile.Write(output, func(f *os.File) error {
		if _, err := binio.BulkCopyN(f, io.NewSectionReader(source, 0, st.Size()), st.Size()); err != nil {
			return err
		}
		for from, to := range move {
			b, err := im.R.Bytes(im.DataStart+int64(from)*int64(im.BlockSize), int64(im.BlockSize))
			if err != nil {
				return err
			}
			if _, err = f.WriteAt(b, im.DataStart+int64(to)*int64(im.BlockSize)); err != nil {
				return err
			}
		}
		// Walk the original chains while writing transformed pointers to the
		// relocated blocks. Every referenced block was checked for unique ownership.
		var rewrite func([]byte, int, int) error
		rewrite = func(raw []byte, ptr, level int) error {
			remaining := (binio.U64(raw, 0) + uint64(im.BlockSize) - 1) / uint64(im.BlockSize)
			var walk func(uint32, int) error
			walk = func(n uint32, depth int) error {
				capacity := uint64(1)
				for i := 0; i < depth; i++ {
					capacity *= uint64(im.BlockSize / 4)
				}
				if n == Missing || depth == 0 {
					remaining -= min(remaining, capacity)
					return nil
				}
				b, err := im.R.Bytes(im.DataStart+int64(n)*int64(im.BlockSize), int64(im.BlockSize))
				if err != nil {
					return err
				}
				for p := 0; p < len(b) && remaining > 0; p += 4 {
					child := binio.U32(b, p)
					if err = walk(child, depth-1); err != nil {
						return err
					}
					binio.Put32(b, p, mapBlock(child))
				}
				_, err = f.WriteAt(b, im.DataStart+int64(mapBlock(n))*int64(im.BlockSize))
				return err
			}
			for p := ptr; p < ptr+64 && remaining > 0; p += 4 {
				n := binio.U32(raw, p)
				if err := walk(n, int(raw[level])); err != nil {
					return err
				}
				binio.Put32(raw, p, mapBlock(n))
			}
			return nil
		}
		for i := uint32(1); i <= im.Inodes; i++ {
			n, err := im.Inode(i)
			if err != nil {
				return err
			}
			if n.Mode() == 0 {
				continue
			}
			if err = rewrite(n.Raw, 36, 100); err != nil {
				return err
			}
			position := uint64(i-1) * 128
			off := im.inodeBlocks[position/uint64(im.BlockSize)]
			block := uint32((off - im.DataStart) / int64(im.BlockSize))
			if _, err = f.WriteAt(n.Raw, im.DataStart+int64(mapBlock(block))*int64(im.BlockSize)+int64(position%uint64(im.BlockSize))); err != nil {
				return err
			}
		}
		super := bytes.Clone(im.Super)
		for _, off := range []int{72, 152, 232, 312, 392} {
			if err := rewrite(super[off:off+80], 8, 72); err != nil {
				return err
			}
		}
		for at, off := range bitmapPositions {
			start := at * int(im.BlockSize)
			if start >= len(bitmap) {
				break
			}
			n := uint32((off - im.DataStart) / int64(im.BlockSize))
			if _, err := f.WriteAt(bitmap[start:min(start+int(im.BlockSize), len(bitmap))], im.DataStart+int64(mapBlock(n))*int64(im.BlockSize)); err != nil {
				return err
			}
		}
		binio.Put32(super, 4, CRC(super[8:]))
		if _, err := f.WriteAt(super, im.PrimaryOffset); err != nil {
			return err
		}
		if err := f.Truncate(report.OutputBytes); err != nil {
			return err
		}
		result, err := Open(binio.Reader{ReaderAt: f, Size: report.OutputBytes})
		if err != nil {
			return err
		}
		final, err := result.Check()
		if err != nil {
			return err
		}
		if len(final.Errors) != 0 {
			return fmt.Errorf("compacted filesystem invalid: %s", final.Errors[0])
		}
		// Verify data, directories and symlinks independently of remapped pointers.
		for i := uint32(1); i <= im.Inodes; i++ {
			a, err := im.Inode(i)
			if err != nil {
				return err
			}
			if a.Mode() == 0 {
				continue
			}
			b, err := result.Inode(i)
			if err != nil {
				return err
			}
			before, after := sha256.New(), sha256.New()
			if err = im.Data(a, before); err != nil {
				return err
			}
			if err = result.Data(b, after); err != nil {
				return err
			}
			if !bytes.Equal(before.Sum(nil), after.Sum(nil)) {
				return fmt.Errorf("compaction changed inode %d payload", i)
			}
		}
		return nil
	})
	return report, err
}
