package qnx6

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func editor(t *testing.T) (*Editor, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fs.ufs")
	if err := Mkfs(p, 10240, 1024, 4096); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	e, err := NewEditor(f)
	if err != nil {
		t.Fatal(err)
	}
	return e, p
}
func TestMkfsGeometries(t *testing.T) {
	for _, bs := range []uint32{512, 1024, 2048, 4096, 8192, 65536} {
		p := filepath.Join(t.TempDir(), "fs")
		if err := Mkfs(p, 1024, 64, bs); err != nil {
			t.Fatal(bs, err)
		}
	}
}

func TestSmallImageWithBackupInsideScanWindow(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tiny")
	if err := Mkfs(p, 16, 2, 512); err != nil {
		t.Fatal(err)
	}
}
func TestSuccessfulDoubleIndirection(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fs")
	if err := Mkfs(p, 10000, 64, 512); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := NewEditor(f)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{42}, (16*128+1)*512)
	if err = e.WriteFile("/double", bytes.NewReader(data), uint64(len(data)), true); err != nil {
		t.Fatal(err)
	}
	if err = e.Commit(); err != nil {
		t.Fatal(err)
	}
	n, _, err := e.Resolve("/double")
	if err != nil || n.Raw[100] != 2 {
		t.Fatal(err, "wrong indirection")
	}
	var got bytes.Buffer
	if err = e.Data(n, &got); err != nil || !bytes.Equal(got.Bytes(), data) {
		t.Fatal(err, "payload mismatch")
	}
}
func TestEditorCreatesReplacesAndRemoves(t *testing.T) {
	e, p := editor(t)
	if err := e.Mkdir("/var/data", true); err != nil {
		t.Fatal(err)
	}
	name := "/var/data/libAppWorldStoreFront.so.1.0.0"
	data := bytes.Repeat([]byte("payload"), 20000)
	if err := e.WriteFile(name, bytes.NewReader(data), uint64(len(data)), true); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(); err != nil {
		t.Fatal(err)
	}
	st, _ := e.File.Stat()
	im, err := Open(binio.Reader{ReaderAt: e.File, Size: st.Size()})
	if err != nil {
		t.Fatal(err)
	}
	n, bad, err := im.Resolve(name)
	if err != nil || len(bad) != 0 {
		t.Fatal(err, bad)
	}
	var out bytes.Buffer
	if err = im.Data(n, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatal(err, "payload mismatch")
	}
	if err = e.WriteFile(name, bytes.NewReader([]byte("small")), 5, false); err != nil {
		t.Fatal(err)
	}
	if err = e.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = e.Remove("/var", true); err != nil {
		t.Fatal(err)
	}
	if err = e.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = p
}
func TestEditorDoubleIndirectAndManyLongNames(t *testing.T) {
	e, _ := editor(t)
	data := bytes.Repeat([]byte{42}, (16*1024+1)*4096)
	if err := e.WriteFile("/large", bytes.NewReader(data), uint64(len(data)), true); err == nil {
		t.Fatal("expected out of space on small image")
	}
	// A failed editor is discarded, just as the transaction wrapper does.
	e, _ = editor(t)
	for i := 0; i < 20; i++ {
		name := string(rune('a'+i)) + "-a-file-with-a-long-filename.bin"
		if err := e.WriteFile("/"+name, bytes.NewReader([]byte("x")), 1, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Commit(); err != nil {
		t.Fatal(err)
	}
}
