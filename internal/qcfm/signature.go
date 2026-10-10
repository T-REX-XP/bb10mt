package qcfm

import (
	"bytes"
	_ "embed"
	"hash/crc32"
	"io"

	"github.com/bb10root/bb10mt/internal/binio"
)

// Legacy fake signature from GPL-3.0 upstream; this is not an OEM signature.
//
//go:embed signature.bin
var signature []byte

// FlashTrailer validates the entire container before returning its own trailer.
// Unsigned containers get a fresh legacy fake trailer with the transport CRC;
// no mutable global signature can leak from an earlier flashed file.
func FlashTrailer(r binio.Reader) (Container, []byte, error) {
	c, e := Read(r)
	if e != nil {
		return c, nil, e
	}
	if c.Signed {
		b, e := r.Bytes(c.PayloadEnd, 560)
		return c, b, e
	}
	b := bytes.Clone(signature)
	h := crc32.NewIEEE()
	if _, e = io.Copy(h, io.NewSectionReader(r.ReaderAt, 0, c.PayloadEnd)); e != nil {
		return c, nil, e
	}
	if _, e = h.Write(b[:556]); e != nil {
		return c, nil, e
	}
	binio.Put32(b, 556, h.Sum32())
	return c, b, nil
}
