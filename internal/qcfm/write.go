package qcfm

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
)

type Options struct {
	Version    int
	Fast, Sign bool
}
type source struct {
	Input
	file   *os.File
	size   int64
	runs   []Run
	digest uint32
}

func scan(s *source, fast bool) error {
	buf := make([]byte, BlockSize)
	h := crc32.NewIEEE()
	var idx uint64
	for off := int64(0); off < s.size; off += BlockSize {
		n := int(min(int64(BlockSize), s.size-off))
		clear(buf)
		if _, e := s.file.ReadAt(buf[:n], off); e != nil {
			return e
		}
		_, _ = h.Write(buf[:n])
		// Keep the last block even if erased: this preserves aligned trailing holes
		// and the padded extent of partial blocks, which QCFM cannot encode exactly.
		erased := true
		for _, b := range buf[:n] {
			if b != 255 {
				erased = false
				break
			}
		}
		keep := fast || !erased || off+int64(n) == s.size
		if idx > math.MaxUint32 {
			return fmt.Errorf("input exceeds QCFM address space")
		}
		if keep {
			if len(s.runs) > 0 && uint64(s.runs[len(s.runs)-1].Offset)+uint64(s.runs[len(s.runs)-1].Count) == idx {
				s.runs[len(s.runs)-1].Count++
			} else {
				s.runs = append(s.runs, Run{uint32(idx), 1})
			}
		}
		idx++
		if len(s.runs) > maxHeader/16 {
			return fmt.Errorf("too many sparse runs")
		}
	}
	s.digest = h.Sum32()
	return nil
}

func Pack(path string, inputs []Input, opt Options) error {
	if opt.Version < 1 || opt.Version > 3 {
		return fmt.Errorf("versions must be 1, 2 or 1,2")
	}
	if len(inputs) == 0 || len(inputs) > 10000 {
		return fmt.Errorf("expected 1..10000 inputs")
	}
	src := make([]source, len(inputs))
	defer func() {
		for _, s := range src {
			if s.file != nil {
				_ = s.file.Close()
			}
		}
	}()
	for i, in := range inputs {
		f, e := os.Open(in.Path)
		if e != nil {
			return e
		}
		src[i] = source{Input: in, file: f}
		st, e := f.Stat()
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() || st.Size() == 0 {
			return fmt.Errorf("input must be a nonempty regular file: %s", in.Path)
		}
		src[i].size = st.Size()
		if opt.Version == 2 && (in.Delta != 0 || in.Flags != 0) {
			return fmt.Errorf("V2 cannot preserve V1 flash offset/flags; use --versions 1,2")
		}
		if e = scan(&src[i], opt.Fast); e != nil {
			return e
		}
	}
	h := make([]byte, 32)
	copy(h, "mfcq")
	binio.Put32(h, 8, 1)
	if opt.Version&1 != 0 {
		binio.Put32(h, 12, uint32(len(src)))
		for _, s := range src {
			n := len(s.runs)
			if n <= 3 {
				n = 3
			} else {
				n = 7 + (n-4)/4*4
			}
			b := make([]byte, 40+n*8)
			copy(b, "qcfp")
			binio.Put32(b, 8, 1)
			binio.Put32(b, 12, uint32(n))
			binio.Put32(b, 16, BlockSize)
			binio.Put32(b, 32, s.Flags)
			for j, r := range s.runs {
				if uint64(r.Offset)+uint64(s.Delta) > math.MaxInt32 {
					return fmt.Errorf("V1 flash offset overflow")
				}
				binio.Put32(b, 40+j*8, r.Offset+s.Delta)
				binio.Put32(b, 44+j*8, r.Count)
			}
			binio.Put32(b, 28, crc32.ChecksumIEEE(b[40:]))
			binio.Put32(b, 4, crc32.ChecksumIEEE(b[8:]))
			h = append(h, b...)
			if len(h) > maxHeader {
				return fmt.Errorf("header too large")
			}
		}
	}
	v2off := len(h)
	if opt.Version&2 != 0 {
		binio.Put32(h, 24, uint32(v2off))
		b := make([]byte, 28)
		copy(b, "mfcq")
		binio.Put32(b, 8, 0x20000)
		binio.Put32(b, 12, 28)
		binio.Put32(b, 16, uint32(len(src)))
		h = append(h, b...)
		for _, s := range src {
			n := len(s.runs)
			b := make([]byte, 44+n*16)
			copy(b, "pfcq")
			binio.Put32(b, 4, 0x20000)
			binio.Put32(b, 8, uint32(len(b)))
			binio.Put32(b, 12, TypeFor(s.Path))
			binio.Put32(b, 16, 44)
			binio.Put32(b, 20, uint32(n))
			binio.Put32(b, 40, BlockSize)
			for j, r := range s.runs {
				p := 44 + j*16
				copy(b[p:], "rrcq")
				binio.Put32(b, p+4, 16)
				binio.Put32(b, p+8, r.Offset)
				binio.Put32(b, p+12, r.Count)
			}
			h = append(h, b...)
			if len(h) > maxHeader {
				return fmt.Errorf("header too large")
			}
		}
	}
	// V1 legacy readers expect at least 64 KiB. All variants grow dynamically.
	headerSize := len(h)
	if opt.Version&1 != 0 {
		headerSize = max(BlockSize, (headerSize+BlockSize-1)/BlockSize*BlockSize)
	}
	if headerSize > maxHeader {
		return fmt.Errorf("header too large")
	}
	h = append(h, make([]byte, headerSize-len(h))...)
	binio.Put32(h, 16, uint32(headerSize))
	if opt.Version&2 != 0 {
		binio.Put32(h, v2off+20, uint32(headerSize-32))
	}
	return atomicfile.Write(path, func(out *os.File) error {
		hash := crc32.NewIEEE()
		w := io.MultiWriter(out, hash)
		if _, e := w.Write(h); e != nil {
			return e
		}
		buf := make([]byte, BlockSize)
		for _, s := range src {
			for _, r := range s.runs {
				for j := uint32(0); j < r.Count; j++ {
					off := (int64(r.Offset) + int64(j)) * BlockSize
					n := int(min(int64(BlockSize), s.size-off))
					clear(buf)
					if _, e := s.file.ReadAt(buf[:n], off); e != nil {
						return e
					}
					if _, e := w.Write(buf); e != nil {
						return e
					}
				}
			}
			// Verify the source did not change between run discovery and serialization.
			st, e := s.file.Stat()
			if e != nil {
				return e
			}
			if st.Size() != s.size {
				return fmt.Errorf("input changed while packing")
			}
			check := crc32.NewIEEE()
			if _, e = io.Copy(check, io.NewSectionReader(s.file, 0, s.size)); e != nil {
				return e
			}
			if check.Sum32() != s.digest {
				return fmt.Errorf("input changed while packing")
			}
		}
		if opt.Sign {
			sig := bytes.Clone(signature)
			if _, e := w.Write(sig[:556]); e != nil {
				return e
			}
			binio.Put32(sig, 556, hash.Sum32())
			if _, e := out.Write(sig[556:]); e != nil {
				return e
			}
		}
		st, e := out.Stat()
		if e != nil {
			return e
		}
		_, e = Read(binio.Reader{ReaderAt: out, Size: st.Size()})
		return e
	})
}
