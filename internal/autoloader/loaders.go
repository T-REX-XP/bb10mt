package autoloader

import (
	"bytes"
	"compress/gzip"
	"debug/pe"
	"fmt"
	"io"

	"github.com/bb10root/bb10mt/internal/binio"
)

type Loader struct {
	DeviceID uint32 `json:"deviceID"`
	Index    int    `json:"index"`
	Data     []byte `json:"-"`
}

// Loaders extracts the CAP .data descriptor table. Some descriptors have no
// embedded payload; these are deliberately skipped. Gzip CRC/length are checked.
func Loaders(r binio.Reader) ([]Loader, error) {
	if _, err := PEEnd(r); err != nil {
		return nil, err
	}
	p, err := pe.NewFile(io.NewSectionReader(r.ReaderAt, 0, r.Size))
	if err != nil {
		return nil, err
	}
	defer p.Close()
	var base uint64
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		base = uint64(h.ImageBase)
	case *pe.OptionalHeader64:
		base = h.ImageBase
	}
	var data *pe.Section
	for _, s := range p.Sections {
		if s.Name == ".data" {
			if data != nil {
				return nil, fmt.Errorf("ambiguous .data section")
			}
			data = s
		}
	}
	if data == nil {
		return nil, fmt.Errorf("CAP .data section not found")
	}
	b, err := r.Bytes(int64(data.Offset), int64(data.Size))
	if err != nil {
		return nil, err
	}
	va := base + uint64(data.VirtualAddress)
	pattern := []byte{4, 11, 0, 4}
	start, count := -1, 0
	for pos := 0; pos+48 <= len(b); pos++ {
		if !bytes.Equal(b[pos:pos+4], pattern) {
			continue
		}
		var n uint32
		if pos >= 8 && binio.U32(b, pos-4) == 0x70000 {
			n = binio.U32(b, pos-8)
		}
		if pos >= 12 && binio.U32(b, pos-8) == 0x70000 && binio.U32(b, pos-4) == 0 {
			n = binio.U32(b, pos-12)
		}
		if n == 0 {
			continue
		}
		if n > 4096 || uint64(n)*48 > uint64(len(b)-pos) {
			return nil, fmt.Errorf("loader descriptor table exceeds section")
		}
		if start != -1 {
			return nil, fmt.Errorf("multiple loader descriptor tables")
		}
		start, count = pos, int(n)
	}
	if start < 0 {
		return nil, fmt.Errorf("loader descriptor table not found")
	}
	var result []Loader
	total := 0
	for i := 0; i < count; i++ {
		h := b[start+i*48 : start+(i+1)*48]
		ptr := uint64(binio.U32(h, 16))
		if ptr == 0 || ptr == 0xffffffff {
			continue
		}
		// Reference tables also contain descriptors for loaders not bundled in
		// this CAP. A non-section pointer is an absent resource, not file data.
		if ptr < va || ptr-va >= uint64(len(b)) {
			continue
		}
		off := int(ptr - va)
		gz, err := gzip.NewReader(bytes.NewReader(b[off:]))
		if err != nil {
			return nil, fmt.Errorf("loader %d: %w", i, err)
		}
		gz.Multistream(false)
		payload, err := io.ReadAll(io.LimitReader(gz, 32<<20+1))
		closeErr := gz.Close()
		if err != nil {
			return nil, fmt.Errorf("loader %d: %w", i, err)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		total += len(payload)
		if len(payload) == 0 || len(payload) > 32<<20 || total > 256<<20 {
			return nil, fmt.Errorf("loader payload size limit exceeded")
		}
		result = append(result, Loader{binio.U32(h, 0), i, payload})
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no embedded loaders")
	}
	return result, nil
}
