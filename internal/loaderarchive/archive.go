// Package loaderarchive reads the legacy BB10MT loaders.dat container.
package loaderarchive

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"

	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/ulikunitz/xz/lzma"
)

const MaxEntrySize = 32 << 20

type Entry struct {
	Name                         string
	Original, Compressed, Offset int64
	CRC                          uint32
}
type Archive struct {
	R       binio.Reader
	Entries []Entry
}

func Read(r binio.Reader) (*Archive, error) {
	hdr, e := r.Bytes(0, 10)
	if e != nil {
		return nil, e
	}
	if string(hdr[:6]) != "BB10MT" {
		return nil, fmt.Errorf("invalid loader archive magic")
	}
	count := binio.U32(hdr, 6)
	if count == 0 || count > 4096 {
		return nil, fmt.Errorf("invalid loader archive count")
	}
	a := &Archive{R: r}
	at := int64(10)
	seen := map[string]bool{}
	for range count {
		b, e := r.Bytes(at, 4)
		if e != nil {
			return nil, e
		}
		n := int64(binio.U32(b, 0))
		at += 4
		if n == 0 || n > 4096 {
			return nil, fmt.Errorf("invalid loader entry name length")
		}
		b, e = r.Bytes(at, n+28)
		if e != nil {
			return nil, e
		}
		at += n + 28
		name := string(b[:n])
		key := strings.ToUpper(name)
		if seen[key] || strings.ContainsAny(name, "/\\:\x00") || name == "." || name == ".." {
			return nil, fmt.Errorf("unsafe/duplicate loader entry name")
		}
		seen[key] = true
		v := Entry{Name: name, Original: int64(binio.U64(b, int(n))), Compressed: int64(binio.U64(b, int(n)+8)), Offset: int64(binio.U64(b, int(n)+16)), CRC: binio.U32(b, int(n)+24)}
		if v.Original <= 0 || v.Original > MaxEntrySize || v.Compressed < 13 || v.Compressed > MaxEntrySize+1<<20 {
			return nil, fmt.Errorf("invalid loader entry size")
		}
		if e = r.Range(v.Offset, v.Compressed); e != nil {
			return nil, e
		}
		a.Entries = append(a.Entries, v)
	}
	extents := append([]Entry{}, a.Entries...)
	sort.Slice(extents, func(i, j int) bool { return extents[i].Offset < extents[j].Offset })
	end := at
	for _, v := range extents {
		if v.Offset < end {
			return nil, fmt.Errorf("overlapping loader archive data/header")
		}
		end = v.Offset + v.Compressed
	}
	return a, nil
}
func (a *Archive) Extract(name string) ([]byte, error) {
	var entry *Entry
	for i := range a.Entries {
		if strings.EqualFold(a.Entries[i].Name, name) {
			entry = &a.Entries[i]
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("loader archive entry not found: %s", name)
	}
	packed, e := a.R.Bytes(entry.Offset, entry.Compressed)
	if e != nil {
		return nil, e
	}
	if crc32.ChecksumIEEE(packed) != entry.CRC {
		return nil, fmt.Errorf("loader archive compressed CRC mismatch")
	}
	declared := binio.U64(packed, 5)
	if declared != ^uint64(0) && declared != uint64(entry.Original) {
		return nil, fmt.Errorf("LZMA size disagrees with loader archive")
	}
	decoder, e := (lzma.ReaderConfig{DictCap: MaxEntrySize}).NewReader(bytes.NewReader(packed))
	if e != nil {
		return nil, e
	}
	data, e := io.ReadAll(io.LimitReader(decoder, entry.Original+1))
	if e != nil {
		return nil, e
	}
	if int64(len(data)) != entry.Original {
		return nil, fmt.Errorf("loader decompressed size mismatch")
	}
	return data, nil
}
