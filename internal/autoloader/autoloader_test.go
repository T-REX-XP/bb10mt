package autoloader

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func fixturePE() []byte {
	b := make([]byte, 1024)
	copy(b, "MZ")
	binio.Put32(b, 60, 128)
	copy(b[128:], "PE\x00\x00")
	binio.LE.PutUint16(b[132:], 0x14c)
	binio.LE.PutUint16(b[134:], 1)
	binio.LE.PutUint16(b[148:], 224)
	binio.LE.PutUint16(b[152:], 0x10b)
	binio.Put32(b, 152+60, 512)
	binio.Put32(b, 152+92, 16)
	p := 152 + 224
	copy(b[p:], ".text")
	binio.Put32(b, p+16, 512)
	binio.Put32(b, p+20, 512)
	return b
}
func TestCAPRoundtripDynamicCount(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, count := range []int{1, 4, 5, 10} {
			dir := t.TempDir()
			cap := filepath.Join(dir, "cap")
			os.WriteFile(cap, fixturePE(), 0600)
			inputs := make([]string, count)
			for i := range inputs {
				inputs[i] = filepath.Join(dir, string(rune('a'+i)))
				os.WriteFile(inputs[i], bytes.Repeat([]byte{byte(i)}, 77+i), 0600)
			}
			out := filepath.Join(dir, "loader")
			if e := Create(out, cap, inputs, version); e != nil {
				t.Fatal(e)
			}
			b, _ := os.ReadFile(out)
			r := binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))}
			h, e := Read(r)
			if e != nil {
				t.Fatal(e)
			}
			if h.Version != version || len(h.Files) != count {
				t.Fatal(h)
			}
			for i, v := range h.Files {
				want, _ := os.ReadFile(inputs[i])
				if !bytes.Equal(want, b[v.Offset:v.Offset+v.Size]) {
					t.Fatal("payload/table overlap")
				}
			}
			extracted := filepath.Join(dir, "extracted")
			if e = ExtractCAP(out, extracted); e != nil {
				t.Fatal(e)
			}
			got, _ := os.ReadFile(extracted)
			if !bytes.Equal(got, fixturePE()) {
				t.Fatal("CAP changed")
			}
		}
	}
}
func TestMalformedOffsetsAndPE(t *testing.T) {
	dir := t.TempDir()
	cap := filepath.Join(dir, "cap")
	os.WriteFile(cap, fixturePE(), 0600)
	p := filepath.Join(dir, "p")
	os.WriteFile(p, []byte("payload"), 0600)
	out := filepath.Join(dir, "out")
	if e := Create(out, cap, []string{p, p}, 2); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(out)
	for _, offset := range []uint64{0, 1100, uint64(len(data)), ^uint64(0)} {
		b := bytes.Clone(data)
		binio.Put64(b, 1024+100, offset)
		if _, e := Read(binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))}); e == nil {
			t.Fatal("bad offset accepted", offset)
		}
	}
	b := fixturePE()
	binio.Put32(b, 376+16, 4096)
	if _, e := PEEnd(binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))}); e == nil {
		t.Fatal("truncated PE accepted")
	}
}
func TestMissingInputLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	cap := filepath.Join(dir, "cap")
	os.WriteFile(cap, fixturePE(), 0600)
	out := filepath.Join(dir, "out")
	if e := Create(out, cap, []string{filepath.Join(dir, "missing")}, 2); e == nil {
		t.Fatal("missing input accepted")
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("partial output")
	}
}

func TestCAPOverlayPreserved(t *testing.T) {
	dir := t.TempDir()
	cap := filepath.Join(dir, "cap")
	stub := append(fixturePE(), bytes.Repeat([]byte{0xa5}, 112)...)
	os.WriteFile(cap, stub, 0600)
	p := filepath.Join(dir, "payload")
	os.WriteFile(p, []byte("data"), 0600)
	out := filepath.Join(dir, "out")
	if err := Create(out, cap, []string{p}, 2); err != nil {
		t.Fatal(err)
	}
	extracted := filepath.Join(dir, "extracted")
	if err := ExtractCAP(out, extracted); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(extracted)
	if !bytes.Equal(got, stub) {
		t.Fatal("CAP overlay lost")
	}
}
func FuzzRead(f *testing.F) {
	f.Add(fixturePE())
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, _ = Read(binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))})
	})
}
