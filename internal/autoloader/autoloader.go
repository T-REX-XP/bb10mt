// Package autoloader handles PE executables with BlackBerry CAP tails.
package autoloader

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"os"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
)

const signatureWord = 0x97c5d59c
const MaxFiles = 10

type File struct{ Offset, Size int64 }
type Header struct {
	Version                             int
	PEEnd, SignatureOffset, TableOffset int64
	Files                               []File
}

// PEEnd includes headers, all raw sections and the Authenticode certificate
// table, if any. Truncated PE sections are errors, never silently clamped.
func PEEnd(r binio.Reader) (int64, error) {
	// debug/pe loads COFF tables eagerly. Bound them before calling it so
	// hostile counts cannot turn a tiny input into a huge allocation.
	dos, e := r.Bytes(0, 64)
	if e != nil {
		return 0, e
	}
	if string(dos[:2]) != "MZ" {
		return 0, fmt.Errorf("PE DOS header required")
	}
	base := int64(binio.U32(dos, 60))
	hdr, e := r.Bytes(base, 24)
	if e != nil {
		return 0, e
	}
	if string(hdr[:4]) != "PE\x00\x00" {
		return 0, fmt.Errorf("invalid PE signature")
	}
	sections := int64(binio.LE.Uint16(hdr[6:]))
	optional := int64(binio.LE.Uint16(hdr[20:]))
	if sections == 0 || sections > 1024 {
		return 0, fmt.Errorf("invalid PE section count")
	}
	if e = r.Range(base+24, optional+sections*40); e != nil {
		return 0, e
	}
	symbols := int64(binio.U32(hdr, 16))
	if symbols > 1<<20 {
		return 0, fmt.Errorf("PE symbol table too large")
	}
	if symbols != 0 {
		off := int64(binio.U32(hdr, 12))
		if e = r.Range(off, symbols*18+4); e != nil {
			return 0, e
		}
		str, err := r.Bytes(off+symbols*18, 4)
		if err != nil {
			return 0, err
		}
		n := int64(binio.U32(str, 0))
		if n < 4 || n > 64<<20 {
			return 0, fmt.Errorf("invalid PE string table size")
		}
		if e = r.Range(off+symbols*18, n); e != nil {
			return 0, e
		}
	}
	p, e := pe.NewFile(io.NewSectionReader(r.ReaderAt, 0, r.Size))
	if e != nil {
		return 0, fmt.Errorf("invalid PE: %w", e)
	}
	defer p.Close()
	var end int64
	var cert pe.DataDirectory
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		end = int64(h.SizeOfHeaders)
		cert = h.DataDirectory[4]
	case *pe.OptionalHeader64:
		end = int64(h.SizeOfHeaders)
		cert = h.DataDirectory[4]
	default:
		return 0, fmt.Errorf("PE optional header required")
	}
	for _, s := range p.Sections {
		off, n := int64(s.Offset), int64(s.Size)
		if e = r.Range(off, n); e != nil {
			return 0, e
		}
		if n != 0 {
			end = max(end, off+n)
		}
	}
	if cert.Size != 0 {
		if e = r.Range(int64(cert.VirtualAddress), int64(cert.Size)); e != nil {
			return 0, e
		}
		end = max(end, int64(cert.VirtualAddress)+int64(cert.Size))
	}
	if end < 64 {
		return 0, fmt.Errorf("invalid PE extent")
	}
	return end, r.Range(0, end)
}

func Read(r binio.Reader) (Header, error) {
	var h Header
	end, e := PEEnd(r)
	if e != nil {
		return h, e
	}
	h.PEEnd = end
	sig := make([]byte, 12)
	for i := 0; i < 3; i++ {
		binio.Put32(sig, i*4, signatureWord)
	}
	// The tail lives near PE data. Bound scan memory and preserve overlap across
	// windows so a signature crossing a read boundary is found.
	buf := make([]byte, 65536)
	for off := end; off < min(r.Size, end+64<<20); {
		n := min(int64(len(buf)), r.Size-off)
		if _, e = r.ReadAt(buf[:n], off); e != nil {
			return h, e
		}
		for pos := 0; pos+12 <= int(n); pos++ {
			if !bytes.Equal(buf[pos:pos+12], sig) {
				continue
			}
			base := off + int64(pos)
			candidate, e := readTail(r, base, end)
			if e == nil {
				return candidate, nil
			}
		}
		if n <= 12 {
			break
		}
		off += n - 11
	}
	return h, fmt.Errorf("valid BlackBerry autoloader tail not found")
}
func readTail(r binio.Reader, base, end int64) (Header, error) {
	h := Header{PEEnd: end, SignatureOffset: base}
	for _, v := range []int{1, 2} {
		pos := base + 12
		if v == 2 {
			pos += 80
		}
		b, e := r.Bytes(pos, 8)
		if e != nil {
			continue
		}
		n := binio.U64(b, 0)
		if n == 0 || n > MaxFiles {
			continue
		}
		table, e := r.Bytes(pos+8, int64(n)*8)
		if e != nil {
			continue
		}
		files := make([]File, n)
		ok := true
		prev := pos + 8 + int64(n)*8 - 1
		for i := range files {
			u := binio.U64(table, i*8)
			if u > uint64(r.Size) || u <= uint64(prev) {
				ok = false
				break
			}
			files[i].Offset = int64(u)
			prev = int64(u)
		}
		if !ok || prev >= r.Size {
			continue
		}
		for i := range files {
			next := r.Size
			if i+1 < len(files) {
				next = files[i+1].Offset
			}
			files[i].Size = next - files[i].Offset
		}
		h.Version = v
		h.TableOffset = pos + 8
		h.Files = files
		return h, nil
	}
	return h, fmt.Errorf("invalid CAP offset table")
}

func Create(output, capPath string, inputs []string, version int) error {
	if version != 1 && version != 2 {
		return fmt.Errorf("CAP version must be 1 or 2")
	}
	if len(inputs) < 1 || len(inputs) > MaxFiles {
		return fmt.Errorf("CAP requires 1..%d inputs", MaxFiles)
	}
	cap, e := os.Open(capPath)
	if e != nil {
		return e
	}
	defer cap.Close()
	st, e := cap.Stat()
	if e != nil {
		return e
	}
	capSize, e := PEEnd(binio.Reader{ReaderAt: cap, Size: st.Size()})
	if e != nil {
		return e
	}
	// CAP stubs can have a meaningful overlay between the PE sections and
	// the tail (112 bytes in the retained Z30 executable). Preserve it.
	if st.Size() > capSize {
		if existing, err := Read(binio.Reader{ReaderAt: cap, Size: st.Size()}); err == nil {
			capSize = existing.SignatureOffset
		} else if st.Size()-capSize <= 64<<20 {
			capSize = st.Size()
		} else {
			return fmt.Errorf("CAP stub has an unrecognized oversized overlay")
		}
	}
	files := make([]*os.File, len(inputs))
	sizes := make([]int64, len(inputs))
	defer func() {
		for _, f := range files {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	for i, path := range inputs {
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		files[i] = f
		st, e := f.Stat()
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() || st.Size() == 0 {
			return fmt.Errorf("CAP input must be a nonempty regular file")
		}
		sizes[i] = st.Size()
	}
	fixed := 20
	if version == 2 {
		fixed += 80
	}
	tailSize := max(fixed+8*len(files), fixed+32)
	tail := make([]byte, tailSize)
	for i := 0; i < 3; i++ {
		binio.Put32(tail, i*4, signatureWord)
	}
	binio.Put64(tail, fixed-8, uint64(len(files)))
	off := capSize + int64(tailSize)
	for i, n := range sizes {
		binio.Put64(tail, fixed+i*8, uint64(off))
		if n > int64(^uint64(0)>>1)-off {
			return fmt.Errorf("CAP size overflow")
		}
		off += n
	}
	return atomicfile.Write(output, func(out *os.File) error {
		if _, e := io.CopyN(out, io.NewSectionReader(cap, 0, capSize), capSize); e != nil {
			return e
		}
		if _, e := out.Write(tail); e != nil {
			return e
		}
		for i, f := range files {
			if _, e := io.CopyN(out, io.NewSectionReader(f, 0, sizes[i]), sizes[i]); e != nil {
				return e
			}
		}
		st, e := out.Stat()
		if e != nil {
			return e
		}
		h, e := Read(binio.Reader{ReaderAt: out, Size: st.Size()})
		if e != nil {
			return e
		}
		if h.Version != version || len(h.Files) != len(files) {
			return fmt.Errorf("CAP verification failed")
		}
		for i, v := range h.Files {
			if v.Size != sizes[i] {
				return fmt.Errorf("CAP payload size mismatch")
			}
		}
		return nil
	})
}

func ExtractCAP(input, output string) error {
	f, e := os.Open(input)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	h, e := Read(binio.Reader{ReaderAt: f, Size: st.Size()})
	if e != nil {
		return e
	}
	return atomicfile.Write(output, func(out *os.File) error {
		_, e := io.CopyN(out, io.NewSectionReader(f, 0, h.SignatureOffset), h.SignatureOffset)
		return e
	})
}
