package qnx6

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func TestCompactRemapsDoubleIndirectAndLongNames(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source")
	if err := Mkfs(input, 10000, 64, 512); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(input, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEditor(f)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("different content"), 70000)
	if err = e.WriteFile("/temporary", bytes.NewReader(data), uint64(len(data)), true); err != nil {
		t.Fatal(err)
	}
	name := "/long filename occupying a name table block"
	if err = e.WriteFile(name, bytes.NewReader(data), uint64(len(data)), true); err != nil {
		t.Fatal(err)
	}
	if err = e.Remove("/temporary", false); err != nil {
		t.Fatal(err)
	}
	if err = e.Commit(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	before, _ := os.ReadFile(input)
	output := filepath.Join(dir, "compact")
	report, err := Compact(input, output)
	if err != nil || report.MovedBlocks == 0 || report.OutputBytes >= report.InputBytes {
		t.Fatal(report, err)
	}
	after, _ := os.ReadFile(input)
	if !bytes.Equal(before, after) {
		t.Fatal("source changed")
	}
	f, err = os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	im, err := Open(binio.Reader{ReaderAt: f, Size: report.OutputBytes})
	if err != nil {
		t.Fatal(err)
	}
	n, issues, err := im.Resolve(name)
	if err != nil || len(issues) != 0 {
		t.Fatal(err, issues)
	}
	var got bytes.Buffer
	if err = im.Data(n, &got); err != nil || !bytes.Equal(got.Bytes(), data) {
		t.Fatal("payload changed", err)
	}
	if _, err = Compact(input, output); err == nil {
		t.Fatal("existing output overwritten")
	}
}
