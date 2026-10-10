package qnx6

import (
	"bytes"
	"fmt"
	"testing"
)

// BB10 images and the Pascal writer mark every allocated inode with flags=1.
// Byte-level metadata checks are separate from the editor's own fsck.
func TestBB10NewInodeMetadata(t *testing.T) {
	e, _ := editor(t)
	if err := e.Mkdir("/payload", false); err != nil {
		t.Fatal(err)
	}
	if err := e.WriteFile("/payload/file", bytes.NewBufferString("data"), 4, true); err != nil {
		t.Fatal(err)
	}
	if err := e.Symlink("file", "/payload/link"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/payload", "/payload/file", "/payload/link"} {
		n, _, err := e.Resolve(path)
		if err != nil {
			t.Fatal(err)
		}
		if n.Raw[101] != 1 {
			t.Errorf("%s: inode flags=%d, want 1", path, n.Raw[101])
		}
		if path == "/payload" && n.Size() != uint64(e.BlockSize) {
			t.Errorf("directory size=%d, want one full block (%d)", n.Size(), e.BlockSize)
		}
	}
	if err := e.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestBB10DirectoryReusesSlotsAndGrowsByBlocks(t *testing.T) {
	e, _ := editor(t)
	if err := e.Mkdir("/payload", false); err != nil {
		t.Fatal(err)
	}
	// Two slots hold '.' and '..'; the remaining slots must be reused.
	capacity := int(e.BlockSize/32) - 2
	for i := 0; i < capacity; i++ {
		if err := e.WriteFile(fmt.Sprintf("/payload/f%d", i), bytes.NewReader(nil), 0, true); err != nil {
			t.Fatal(err)
		}
	}
	assertSize := func(want uint64) {
		t.Helper()
		n, _, err := e.Resolve("/payload")
		if err != nil || n.Size() != want {
			t.Fatalf("directory size=%d, want %d: %v", n.Size(), want, err)
		}
	}
	assertSize(uint64(e.BlockSize))
	if err := e.Remove("/payload/f0", false); err != nil {
		t.Fatal(err)
	}
	if err := e.WriteFile("/payload/replacement", bytes.NewReader(nil), 0, true); err != nil {
		t.Fatal(err)
	}
	assertSize(uint64(e.BlockSize))
	if err := e.WriteFile("/payload/overflow", bytes.NewReader(nil), 0, true); err != nil {
		t.Fatal(err)
	}
	assertSize(2 * uint64(e.BlockSize))
	n, _, err := e.Resolve("/payload")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := e.Entries(n)
	if err != nil || len(entries) != capacity+3 {
		t.Fatalf("entries=%d, want %d: %v", len(entries), capacity+3, err)
	}
	if err := e.Commit(); err != nil {
		t.Fatal(err)
	}
}
