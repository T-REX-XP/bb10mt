package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFailedBuildAndExistingOutput(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "artifact")
	err := Write(p, func(f *os.File) error {
		_, e := f.WriteString("partial")
		if e != nil {
			return e
		}
		return errors.New("injected failure")
	})
	if err == nil {
		t.Fatal("failure ignored")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("left files on failure")
	}
	if e := Write(p, func(f *os.File) error { _, e := f.WriteString("verified"); return e }); e != nil {
		t.Fatal(e)
	}
	if e := Write(p, func(f *os.File) error { t.Fatal("must not run"); return nil }); e == nil {
		t.Fatal("overwrite accepted")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "verified" {
		t.Fatal("clobbered")
	}
}
