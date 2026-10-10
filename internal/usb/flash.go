package usb

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/autoloader"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qcfm"
)

type Prepared struct {
	Path         string
	PayloadBytes int64
	Trailer      []byte
	SHA256       string
}

// PrepareFirmware snapshots every input into a private staging directory and
// validates every container before a USB device is opened. It accepts native
// QCFM, CAP autoloaders and known raw partition extensions.
func PrepareFirmware(dir string, inputs []qcfm.Input, version int) ([]Prepared, error) {
	var prepared []Prepared
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no flash inputs")
	}
	add := func(r io.ReaderAt, offset, size int64) (err error) {
		path := filepath.Join(dir, fmt.Sprintf("flash-%03d.qcfm", len(prepared)))
		if err = atomicfile.Write(path, func(f *os.File) error { _, e := io.CopyN(f, io.NewSectionReader(r, offset, size), size); return e }); err != nil {
			return err
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		defer f.Close()
		br := binio.Reader{ReaderAt: f, Size: size}
		c, trailer, e := qcfm.FlashTrailer(br)
		if e != nil {
			return e
		}
		h := sha256.New()
		if _, e = io.Copy(h, io.NewSectionReader(f, 0, size)); e != nil {
			return e
		}
		prepared = append(prepared, Prepared{path, c.PayloadEnd, trailer, hex.EncodeToString(h.Sum(nil))})
		return nil
	}
	for _, in := range inputs {
		err := func() error {
			f, e := os.Open(in.Path)
			if e != nil {
				return e
			}
			defer f.Close()
			st, e := f.Stat()
			if e != nil {
				return e
			}
			if !st.Mode().IsRegular() {
				return fmt.Errorf("flash input must be regular")
			}
			br := binio.Reader{ReaderAt: f, Size: st.Size()}
			magic, e := br.Bytes(0, 4)
			if e != nil {
				return e
			}
			switch {
			case string(magic) == "mfcq":
				if in.Delta != 0 || in.Flags != 0 {
					return fmt.Errorf("container input cannot have raw offset/flags")
				}
				return add(f, 0, st.Size())
			case string(magic[:2]) == "MZ":
				if in.Delta != 0 || in.Flags != 0 {
					return fmt.Errorf("CAP input cannot have raw offset/flags")
				}
				cap, e := autoloader.Read(br)
				if e != nil {
					return e
				}
				for _, part := range cap.Files {
					if e = add(f, part.Offset, part.Size); e != nil {
						return e
					}
				}
				return nil
			default:
				if qcfm.TypeFor(in.Path) == 0 {
					return fmt.Errorf("unknown raw partition extension: %s", in.Path)
				}
				name := filepath.Join(dir, fmt.Sprintf("raw-%03d%s", len(prepared), qcfm.Extension(qcfm.TypeFor(in.Path))))
				if e = atomicfile.Write(name, func(out *os.File) error { _, e := io.CopyN(out, f, st.Size()); return e }); e != nil {
					return e
				}
				in.Path = name
				packed := name + ".signed"
				if e = qcfm.Pack(packed, []qcfm.Input{in}, qcfm.Options{Version: version, Sign: true}); e != nil {
					return e
				}
				p, e := os.Open(packed)
				if e != nil {
					return e
				}
				defer p.Close()
				st, e = p.Stat()
				if e != nil {
					return e
				}
				return add(p, 0, st.Size())
			}
		}()
		if err != nil {
			return nil, fmt.Errorf("prepare %s: %w", in.Path, err)
		}
	}
	return prepared, nil
}

type FlashReport struct {
	SourceSHA256 string `json:"sourceSHA256"`
	PayloadBytes int64  `json:"payloadBytes"`
	Blocks       uint32 `json:"blocks"`
}

func (p *Protocol) Flash(ctx context.Context, model uint32, input Prepared) (FlashReport, error) {
	report := FlashReport{SourceSHA256: input.SHA256, PayloadBytes: input.PayloadBytes}
	f, e := os.Open(input.Path)
	if e != nil {
		return report, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return report, e
	}
	br := binio.Reader{ReaderAt: f, Size: st.Size()}
	c, trailer, e := qcfm.FlashTrailer(br)
	if e != nil {
		return report, e
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.NewSectionReader(f, 0, st.Size())); e != nil {
		return report, e
	}
	if hex.EncodeToString(h.Sum(nil)) != input.SHA256 || c.PayloadEnd != input.PayloadBytes {
		return report, fmt.Errorf("staged firmware changed before flashing")
	}
	if e = ctx.Err(); e != nil {
		return report, e
	}
	pre := make([]byte, 36)
	pre[0] = 0x15
	if model&0xffff == 0x2c0a {
		pre[0] = 0x40
	}
	pre[1] = 0x28
	pre[6] = 2
	pre[28] = 1
	pre[32] = 2
	if _, e = p.Channel2(0x20ee, pre, 0x39); e != nil {
		return report, e
	}
	const chunk = 0x3ff4 - 8
	for at := int64(0); at < c.PayloadEnd; {
		if e = ctx.Err(); e != nil {
			return report, e
		}
		n := min(int64(chunk), c.PayloadEnd-at)
		b := make([]byte, 8+int(n))
		binary.LittleEndian.PutUint32(b, report.Blocks)
		binary.LittleEndian.PutUint32(b[4:], uint32(n))
		if _, e = f.ReadAt(b[8:], at); e != nil {
			return report, e
		}
		if _, e = p.Channel2(0xf7, b, 0xdf); e != nil {
			return report, e
		}
		report.Blocks++
		at += n
	}
	b := make([]byte, 562)
	binary.LittleEndian.PutUint16(b, 560)
	copy(b[2:], trailer)
	if _, e = p.Channel2(0x40f9, b, 0x4006); e != nil {
		return report, e
	}
	_, e = p.Channel2(0x40c0, nil, 0x4006, 0x402e)
	return report, e
}
