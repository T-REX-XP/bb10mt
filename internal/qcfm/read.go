package qcfm

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/bb10root/bb10mt/internal/binio"
)

// Read validates structure before exposing any payload. A zero optional header
// CRC means absent, as in the legacy writer. Nonzero main-header CRC fields are
// rejected until their variant is known; they are never silently ignored.
func Read(r binio.Reader) (Container, error) {
	var c Container
	h, e := r.Bytes(0, 32)
	if e != nil {
		return c, e
	}
	if string(h[:4]) != "mfcq" || binio.U32(h, 8) != 1 {
		return c, fmt.Errorf("unsupported QCFM main header")
	}
	if binio.U32(h, 4) != 0 || binio.U32(h, 20) != 0 {
		return c, fmt.Errorf("unsupported nonzero main-header CRC variant")
	}
	c.HeaderSize = int64(binio.U32(h, 16))
	if c.HeaderSize < 32 || c.HeaderSize > maxHeader {
		return c, fmt.Errorf("invalid header size")
	}
	if e = r.Range(0, c.HeaderSize); e != nil {
		return c, e
	}
	v2off := int64(binio.U32(h, 24))
	n1 := int64(binio.U32(h, 12))
	if n1 > 10000 {
		return c, fmt.Errorf("too many V1 partitions")
	}
	p := int64(32)
	payload := c.HeaderSize
	for i := int64(0); i < n1; i++ {
		if p+40 > c.HeaderSize {
			return c, fmt.Errorf("V1 control exceeds header")
		}
		b, e := r.Bytes(p, 40)
		if e != nil {
			return c, e
		}
		if string(b[:4]) != "qcfp" || binio.U32(b, 8) != 1 {
			return c, fmt.Errorf("invalid V1 control")
		}
		n := int64(binio.U32(b, 12))
		end := p + 40 + n*8
		if end > c.HeaderSize {
			return c, fmt.Errorf("V1 run table exceeds header")
		}
		rr, e := r.Bytes(p+40, n*8)
		if e != nil {
			return c, e
		}
		if crc := binio.U32(b, 28); crc != 0 && crc != crc32.ChecksumIEEE(rr) {
			return c, fmt.Errorf("V1 run CRC mismatch")
		}
		if crc := binio.U32(b, 4); crc != 0 {
			all := append(append([]byte{}, b[8:]...), rr...)
			if crc != crc32.ChecksumIEEE(all) {
				return c, fmt.Errorf("V1 control CRC mismatch")
			}
		}
		ch := Chunk{Flags: binio.U32(b, 32), BlockSize: binio.U32(b, 16), DataOffset: payload}
		for j := int64(0); j < n; j++ {
			v := rr[j*8 : j*8+8]
			run := Run{binio.U32(v, 0), binio.U32(v, 4)}
			if run.Count != 0 {
				ch.Runs = append(ch.Runs, run)
			} else if run.Offset != 0 {
				return c, fmt.Errorf("invalid zero-count V1 run")
			}
		}
		if e = validateRuns(&ch, r); e != nil {
			return c, e
		}
		payload += ch.DataSize
		c.V1 = append(c.V1, ch)
		p = end
	}
	c.Version = 1
	c.PayloadEnd = payload
	if v2off != 0 {
		if v2off != p || v2off+28 > c.HeaderSize {
			return c, fmt.Errorf("invalid V2 header offset")
		}
		b, e := r.Bytes(v2off, 28)
		if e != nil {
			return c, e
		}
		if string(b[:4]) != "mfcq" || binio.U32(b, 8) != 0x20000 || binio.U32(b, 12) != 28 {
			return c, fmt.Errorf("invalid V2 header")
		}
		if binio.U32(b, 4) != 0 || binio.U32(b, 24) != 0 {
			return c, fmt.Errorf("unsupported nonzero V2 header CRC variant")
		}
		n2 := int64(binio.U32(b, 16))
		if n2 == 0 || n2 > 10000 {
			return c, fmt.Errorf("invalid V2 partition count")
		}
		if n1 != 0 && n1 != n2 {
			return c, fmt.Errorf("hybrid partition counts differ")
		}
		p = v2off + 28
		payload = c.HeaderSize
		for i := int64(0); i < n2; i++ {
			if p+44 > c.HeaderSize {
				return c, fmt.Errorf("V2 control exceeds header")
			}
			b, e := r.Bytes(p, 44)
			if e != nil {
				return c, e
			}
			length := int64(binio.U32(b, 8))
			ro := int64(binio.U32(b, 16))
			n := int64(binio.U32(b, 20))
			if string(b[:4]) != "pfcq" || binio.U32(b, 4) != 0x20000 || length < 44 || length > c.HeaderSize-p || ro < 44 || ro > length || n > (length-ro)/16 {
				return c, fmt.Errorf("invalid V2 control or run bounds")
			}
			// Hardware version and per-control signature areas are retained in OEM
			// containers, but their cryptographic validity is outside CRC verification.
			for _, pair := range [][2]int{{24, 28}, {32, 36}} {
				off := int64(binio.U32(b, pair[0]))
				cnt := int64(binio.U32(b, pair[1]))
				if cnt != 0 && (off < 44 || off > length || cnt > length-off) {
					return c, fmt.Errorf("V2 auxiliary bounds invalid")
				}
			}
			ch := Chunk{Type: binio.U32(b, 12), BlockSize: binio.U32(b, 40), DataOffset: payload}
			rr, e := r.Bytes(p+ro, n*16)
			if e != nil {
				return c, e
			}
			for j := int64(0); j < n; j++ {
				v := rr[j*16 : j*16+16]
				if string(v[:4]) != "rrcq" || binio.U32(v, 4) != 16 || binio.U32(v, 12) == 0 {
					return c, fmt.Errorf("invalid V2 run")
				}
				ch.Runs = append(ch.Runs, Run{binio.U32(v, 8), binio.U32(v, 12)})
			}
			if e = validateRuns(&ch, r); e != nil {
				return c, e
			}
			payload += ch.DataSize
			c.V2 = append(c.V2, ch)
			p += length
		}
		if c.HeaderSize < int64(binio.U32(b, 20)) {
			return c, fmt.Errorf("invalid V2 header size")
		}
		if n1 > 0 {
			for i, a := range c.V1 {
				b := c.V2[i]
				if a.DataOffset != b.DataOffset || a.DataSize != b.DataSize || a.BlockSize != b.BlockSize || len(a.Runs) != len(b.Runs) {
					return c, fmt.Errorf("hybrid payload maps differ")
				}
				for j, v := range a.Runs {
					if v.Count != b.Runs[j].Count || v.Offset-a.Runs[0].Offset != b.Runs[j].Offset-b.Runs[0].Offset {
						return c, fmt.Errorf("hybrid runs differ")
					}
				}
			}
			c.Version = 3
		} else {
			c.Version = 2
		}
		c.PayloadEnd = payload
	}
	if len(c.Chunks()) == 0 {
		return c, fmt.Errorf("empty container")
	}
	if r.Size == c.PayloadEnd {
		return c, nil
	}
	if r.Size-c.PayloadEnd == 560 {
		sig, e := r.Bytes(c.PayloadEnd, 560)
		if e != nil {
			return c, e
		}
		// OEM and historical fake trailers share these tags but contain different
		// signature bytes. CRC verifies transport integrity, never authenticity.
		if bytes.Equal(sig[:40], signature[:40]) && bytes.Equal(sig[188:228], signature[188:228]) && bytes.Equal(sig[376:416], signature[376:416]) {
			h := crc32.NewIEEE()
			if _, e = io.Copy(h, io.NewSectionReader(r.ReaderAt, 0, r.Size-4)); e != nil {
				return c, e
			}
			if h.Sum32() != binio.U32(sig, 556) {
				return c, fmt.Errorf("legacy signature CRC mismatch")
			}
			c.Signed = true
			return c, nil
		}
	}
	return c, fmt.Errorf("unrecognized QCFM trailer (%d bytes); no signature verification available", r.Size-c.PayloadEnd)
}

func validateRuns(ch *Chunk, r binio.Reader) error {
	if ch.BlockSize < 512 || ch.BlockSize > 1<<20 || ch.BlockSize&(ch.BlockSize-1) != 0 {
		return fmt.Errorf("invalid block size")
	}
	var end uint64
	for _, v := range ch.Runs {
		next := uint64(v.Offset) + uint64(v.Count)
		if v.Count == 0 || uint64(v.Offset) < end || next > 1<<32 {
			return fmt.Errorf("overlapping, unsorted or overflowing run")
		}
		ch.DataSize += int64(v.Count) * int64(ch.BlockSize)
		end = next
	}
	return r.Range(ch.DataOffset, ch.DataSize)
}

// Extract writes a logical partition. V2 offsets are absolute within the image;
// V1 offsets include a flash destination delta, returned separately in lists.
// The format has no byte length: output ends at the last stored block.
func Extract(r binio.Reader, ch Chunk, v1 bool, w io.Writer) error {
	base := uint64(0)
	if v1 && len(ch.Runs) > 0 {
		base = uint64(ch.Runs[0].Offset)
	}
	ff := bytes.Repeat([]byte{255}, int(ch.BlockSize))
	pos := uint64(0)
	src := ch.DataOffset
	for _, v := range ch.Runs {
		target := (uint64(v.Offset) - base) * uint64(ch.BlockSize)
		if target < pos {
			return fmt.Errorf("invalid extraction order")
		}
		for pos < target {
			n := min(uint64(len(ff)), target-pos)
			if _, e := w.Write(ff[:n]); e != nil {
				return e
			}
			pos += n
		}
		n := int64(v.Count) * int64(ch.BlockSize)
		if _, e := io.CopyN(w, io.NewSectionReader(r.ReaderAt, src, n), n); e != nil {
			return e
		}
		src += n
		pos += uint64(n)
	}
	return nil
}
