// Package binio provides bounded little-endian access to untrusted binary files.
package binio

import (
	"encoding/binary"
	"fmt"
	"io"
)

var LE = binary.LittleEndian

type Reader struct {
	io.ReaderAt
	Size int64
}

func (r Reader) Range(off, n int64) error {
	if off < 0 || n < 0 || off > r.Size || n > r.Size-off {
		return fmt.Errorf("range [%d,+%d) outside %d-byte file", off, n, r.Size)
	}
	return nil
}
func (r Reader) Bytes(off, n int64) ([]byte, error) {
	if err := r.Range(off, n); err != nil {
		return nil, err
	}
	if n > 64<<20 {
		return nil, fmt.Errorf("metadata exceeds 64 MiB limit")
	}
	b := make([]byte, int(n))
	_, err := r.ReadAt(b, off)
	if err != nil {
		return nil, err
	}
	return b, nil
}
func (r Reader) Section(off, n int64) (*io.SectionReader, error) {
	if err := r.Range(off, n); err != nil {
		return nil, err
	}
	return io.NewSectionReader(r.ReaderAt, off, n), nil
}
func U32(b []byte, off int) uint32      { return LE.Uint32(b[off : off+4]) }
func U64(b []byte, off int) uint64      { return LE.Uint64(b[off : off+8]) }
func Put32(b []byte, off int, v uint32) { LE.PutUint32(b[off:off+4], v) }
func Put64(b []byte, off int, v uint64) { LE.PutUint64(b[off:off+8], v) }
