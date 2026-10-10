package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryPublicationNeverReplacesExistingEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	stage, out := filepath.Join(dir, "stage"), filepath.Join(dir, "out")
	os.Mkdir(stage, 0700)
	os.WriteFile(filepath.Join(stage, "file"), []byte("staged"), 0600)
	os.Mkdir(out, 0700)
	if e := PublishDirectory(stage, out); e == nil {
		t.Fatal("replaced concurrent output directory")
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 0 {
		t.Fatal("modified existing output")
	}
	os.Remove(out)
	if e := PublishDirectory(stage, out); e != nil {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(filepath.Join(out, "file")); e != nil || string(b) != "staged" {
		t.Fatal(string(b), e)
	}
}
