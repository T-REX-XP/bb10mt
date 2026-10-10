package qcfm

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func openContainer(t *testing.T, path string) (*os.File, binio.Reader, Container) {
	t.Helper()
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	st, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	r := binio.Reader{ReaderAt: f, Size: st.Size()}
	c, e := Read(r)
	if e != nil {
		t.Fatal(e)
	}
	return f, r, c
}

func TestSparseRoundtrip(t *testing.T) {
	for _, v := range []int{1, 2, 3} {
		for _, sign := range []bool{false, true} {
			for _, fast := range []bool{false, true} {
				dir := t.TempDir()
				input := filepath.Join(dir, "partition.radio.rcfs")
				data := bytes.Repeat([]byte{255}, BlockSize*6)
				copy(data[BlockSize:], []byte("first run"))
				copy(data[3*BlockSize:], []byte("second run"))
				if e := os.WriteFile(input, data, 0600); e != nil {
					t.Fatal(e)
				}
				in := Input{Path: input}
				if v != 2 {
					in.Delta = 123
					in.Flags = 2
				}
				output := filepath.Join(dir, "test.signed")
				if e := Pack(output, []Input{in}, Options{v, fast, sign}); e != nil {
					t.Fatal(v, sign, fast, e)
				}
				_, r, c := openContainer(t, output)
				if c.Version != v || c.Signed != sign {
					t.Fatal(c)
				}
				if v > 1 && c.V2[0].Type != 12 {
					t.Fatal("lost radio type")
				}
				var b bytes.Buffer
				if e := Extract(r, c.Chunks()[0], v == 1, &b); e != nil {
					t.Fatal(e)
				}
				want := data
				if v == 1 && !fast {
					want = data[BlockSize:]
				}
				if !bytes.Equal(want, b.Bytes()) {
					t.Fatalf("roundtrip v=%d fast=%v", v, fast)
				}
			}
		}
	}
}
func TestHeaderGrowsWithFragmentation(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "fragmented.ufs")
	f, e := os.Create(input)
	if e != nil {
		t.Fatal(e)
	}
	// 2100 runs exceed the old one-run budget and V1's fixed 64 KiB budget.
	a := bytes.Repeat([]byte{255}, BlockSize)
	b := make([]byte, BlockSize)
	for i := 0; i < 2100; i++ {
		if _, e = f.Write(b); e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(a); e != nil {
			t.Fatal(e)
		}
	}
	f.Close()
	for _, v := range []int{1, 2, 3} {
		out := filepath.Join(dir, string(rune('0'+v))+".signed")
		if e = Pack(out, []Input{{Path: input}}, Options{Version: v}); e != nil {
			t.Fatal(e)
		}
		_, r, c := openContainer(t, out)
		if len(c.Chunks()[0].Runs) < 2000 {
			t.Fatal("runs lost")
		}
		var sink countingWriter
		if e = Extract(r, c.Chunks()[0], v == 1, &sink); e != nil {
			t.Fatal(e)
		}
		if sink.n != 4200*BlockSize {
			t.Fatal(sink.n)
		}
	}
}

type countingWriter struct{ n int64 }

func (w *countingWriter) Write(b []byte) (int, error) { w.n += int64(len(b)); return len(b), nil }
func TestPartialAndErasedInputs(t *testing.T) {
	for _, data := range [][]byte{[]byte("abc"), bytes.Repeat([]byte{255}, 3*BlockSize+2)} {
		dir := t.TempDir()
		in := filepath.Join(dir, "p.ufs")
		os.WriteFile(in, data, 0600)
		out := filepath.Join(dir, "out")
		if e := Pack(out, []Input{{Path: in}}, Options{Version: 2, Sign: true}); e != nil {
			t.Fatal(e)
		}
		_, r, c := openContainer(t, out)
		var b bytes.Buffer
		if e := Extract(r, c.Chunks()[0], false, &b); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(b.Bytes()[:len(data)], data) || b.Len()%BlockSize != 0 {
			t.Fatal("partial/erased extent lost")
		}
	}
}
func TestCorruptionRejected(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "p.ufs")
	os.WriteFile(in, []byte("x"), 0600)
	out := filepath.Join(dir, "out")
	if e := Pack(out, []Input{{Path: in}}, Options{Version: 3, Sign: true}); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(out)
	for _, pos := range []int{44, 100, len(data) - 1, len(data) - 600} {
		b := bytes.Clone(data)
		b[pos] ^= 1
		if _, e := Read(binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))}); e == nil {
			t.Fatalf("accepted corruption at %d", pos)
		}
	}
	for _, n := range []int{0, 31, 90, len(data) - 561, len(data) - 1} {
		if _, e := Read(binio.Reader{ReaderAt: bytes.NewReader(data[:n]), Size: int64(n)}); e == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
}
func TestNoOutputOnFailureAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if e := Pack(out, []Input{{Path: filepath.Join(dir, "missing")}}, Options{Version: 2}); e == nil {
		t.Fatal("accepted missing input")
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("published failed output")
	}
	os.WriteFile(out, []byte("keep"), 0600)
	if e := Pack(out, nil, Options{Version: 2}); e == nil {
		t.Fatal("accepted empty inputs")
	}
	b, _ := os.ReadFile(out)
	if string(b) != "keep" {
		t.Fatal("overwritten")
	}
}
func TestInputPathsAndTypes(t *testing.T) {
	in, e := ParseInput("sub/p.radio.sig2=0x123,2", "/base")
	if e != nil || in.Delta != 0x123 || in.Flags != 2 || TypeFor(in.Path) != 140 {
		t.Fatal(in, e)
	}
	for _, s := range []string{"", "=2", "p=-1,0", "p=0,0,0", "p=x"} {
		if _, e := ParseInput(s, "."); e == nil {
			t.Fatal(s)
		}
	}
}
func FuzzRead(f *testing.F) {
	f.Add([]byte("mfcq"))
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		c, e := Read(binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))})
		if e == nil {
			for _, ch := range c.Chunks() {
				if ch.DataSize > int64(len(b)) {
					t.Fatal("bad bounds")
				}
				_ = io.Discard
			}
		}
	})
}

// Cover transfers spanning multiple bulk buffers, with erased gaps and a
// partial final block. Compare the reconstructed logical image byte for byte.
func TestBulkRunsPreserveGapsAndPartialPadding(t *testing.T) {
	for _, v := range []int{2, 3} {
		data := bytes.Repeat([]byte{0x37}, (9<<20)+17)
		gapStart := 5 << 20
		gapEnd := gapStart + 3*BlockSize
		for i := gapStart; i < gapEnd; i++ {
			data[i] = 255
		}
		dir := t.TempDir()
		in := filepath.Join(dir, "bulk.ufs")
		out := filepath.Join(dir, "bulk.signed")
		if err := os.WriteFile(in, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := Pack(out, []Input{{Path: in}}, Options{Version: v, Sign: true}); err != nil {
			t.Fatal(err)
		}
		_, reader, container := openContainer(t, out)
		if len(container.V2[0].Runs) != 2 {
			t.Fatal("sparse gap lost", container.V2[0].Runs)
		}
		var got bytes.Buffer
		if err := Extract(reader, container.V2[0], false, &got); err != nil {
			t.Fatal(err)
		}
		expected := append(bytes.Clone(data), make([]byte, BlockSize-len(data)%BlockSize)...)
		if !bytes.Equal(got.Bytes(), expected) {
			t.Fatal("changed bulk payload/gap/padding")
		}
	}
}
