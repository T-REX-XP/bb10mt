package vmdk

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"sort"
	"unicode/utf16"

	"github.com/bb10root/bb10mt/internal/binio"
)

type Partition struct {
	Index              int
	Scheme, Name, Type string
	Offset, Size       int64
}

func (d *Disk) Partitions() ([]Partition, error) {
	r := binio.Reader{ReaderAt: d, Size: d.Size}
	mbr, err := r.Bytes(0, 512)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(mbr[510:], []byte{0x55, 0xaa}) {
		return nil, fmt.Errorf("invalid MBR signature")
	}
	var result []Partition
	add := func(scheme, name, kind string, first, count uint64) error {
		if count == 0 || first > uint64(d.Size/512) || count > uint64(d.Size/512)-first {
			return fmt.Errorf("partition outside disk")
		}
		result = append(result, Partition{Index: len(result) + 1, Scheme: scheme, Name: name, Type: kind, Offset: int64(first) * 512, Size: int64(count) * 512})
		return nil
	}
	protective := false
	for i := 0; i < 4; i++ {
		if mbr[446+i*16+4] == 0xee {
			protective = true
		}
	}
	if protective {
		h, err := r.Bytes(512, 512)
		if err != nil {
			return nil, err
		}
		if string(h[:8]) != "EFI PART" {
			return nil, fmt.Errorf("invalid GPT signature")
		}
		size := binio.U32(h, 12)
		if size < 92 || size > 512 {
			return nil, fmt.Errorf("invalid GPT header length")
		}
		stored := binio.U32(h, 16)
		check := bytes.Clone(h[:size])
		clear(check[16:20])
		if stored != crc32.ChecksumIEEE(check) {
			return nil, fmt.Errorf("GPT header CRC mismatch")
		}
		if binio.U64(h, 24) != 1 {
			return nil, fmt.Errorf("invalid GPT current LBA")
		}
		firstUsable, lastUsable := binio.U64(h, 40), binio.U64(h, 48)
		if firstUsable > lastUsable || lastUsable >= uint64(d.Size/512) {
			return nil, fmt.Errorf("invalid GPT usable range")
		}
		n, entrySize := uint64(binio.U32(h, 80)), uint64(binio.U32(h, 84))
		lba := binio.U64(h, 72)
		if n == 0 || n > 65536 || entrySize < 128 || entrySize > 4096 || entrySize%8 != 0 || n*entrySize > 64<<20 || lba > uint64(d.Size/512) {
			return nil, fmt.Errorf("invalid GPT entry geometry")
		}
		table, err := r.Bytes(int64(lba)*512, int64(n*entrySize))
		if err != nil {
			return nil, err
		}
		if crc32.ChecksumIEEE(table) != binio.U32(h, 88) {
			return nil, fmt.Errorf("GPT table CRC mismatch")
		}
		for i := uint64(0); i < n; i++ {
			e := table[i*entrySize : (i+1)*entrySize]
			if bytes.Equal(e[:16], make([]byte, 16)) {
				continue
			}
			first, last := binio.U64(e, 32), binio.U64(e, 40)
			if last < first || first < firstUsable || last > lastUsable {
				return nil, fmt.Errorf("invalid GPT partition range")
			}
			var chars []uint16
			for at := 56; at < 128; at += 2 {
				c := binio.LE.Uint16(e[at:])
				if c == 0 {
					break
				}
				chars = append(chars, c)
			}
			kind := fmt.Sprintf("%08X-%04X-%04X-%X-%X", binio.U32(e, 0), binio.LE.Uint16(e[4:]), binio.LE.Uint16(e[6:]), e[8:10], e[10:16])
			if err = add("GPT", string(utf16.Decode(chars)), kind, first, last-first+1); err != nil {
				return nil, err
			}
		}
	} else {
		extended := func(t byte) bool { return t == 5 || t == 15 || t == 0x85 }
		for i := 0; i < 4; i++ {
			e := mbr[446+i*16 : 462+i*16]
			kind := e[4]
			if kind == 0 {
				continue
			}
			first, count := uint64(binio.U32(e, 8)), uint64(binio.U32(e, 12))
			if !extended(kind) {
				if err = add("MBR", "", fmt.Sprintf("0x%02X", kind), first, count); err != nil {
					return nil, err
				}
				continue
			}
			if count == 0 || first+count > uint64(d.Size/512) {
				return nil, fmt.Errorf("extended partition outside disk")
			}
			base, end, next := first, first+count, first
			seen := map[uint64]bool{}
			for next != 0 {
				if next < base || next >= end || seen[next] || len(seen) > 4096 {
					return nil, fmt.Errorf("cyclic/out-of-range EBR chain")
				}
				seen[next] = true
				ebr, err := r.Bytes(int64(next)*512, 512)
				if err != nil {
					return nil, err
				}
				if !bytes.Equal(ebr[510:], []byte{0x55, 0xaa}) {
					return nil, fmt.Errorf("invalid EBR signature")
				}
				part := ebr[446:462]
				start, length := next+uint64(binio.U32(part, 8)), uint64(binio.U32(part, 12))
				if part[4] != 0 {
					if extended(part[4]) || start < base || length > end-start || start >= end {
						return nil, fmt.Errorf("invalid logical partition")
					}
					if err = add("MBR-LOG", "", fmt.Sprintf("0x%02X", part[4]), start, length); err != nil {
						return nil, err
					}
				}
				link := ebr[462:478]
				if link[4] == 0 {
					next = 0
				} else {
					if !extended(link[4]) {
						return nil, fmt.Errorf("invalid EBR next link")
					}
					next = base + uint64(binio.U32(link, 8))
				}
			}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no partitions")
	}
	ordered := append([]Partition(nil), result...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	for i := 1; i < len(ordered); i++ {
		if ordered[i].Offset < ordered[i-1].Offset+ordered[i-1].Size {
			return nil, fmt.Errorf("overlapping disk partitions")
		}
	}
	return result, nil
}
