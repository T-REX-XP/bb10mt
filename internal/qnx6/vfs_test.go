package qnx6

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestVFSRenameLinksAndRandomWrites(t *testing.T) {
	file := filepath.Join(t.TempDir(), "image.ufs")
	if e := Mkfs(file, 1024, 128, 4096); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(file, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	ed, e := NewEditor(f)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"/a/sub", "/b"} {
		if e = ed.Mkdir(p, true); e != nil {
			t.Fatal(e)
		}
	}
	if e = ed.WriteFile("/a/sub/source", bytes.NewBufferString("0123456789"), 10, true); e != nil {
		t.Fatal(e)
	}
	if e = ed.HardLink("/a/sub/source", "/b/alias"); e != nil {
		t.Fatal(e)
	}
	if e = ed.Symlink("../b/alias", "/a/link"); e != nil {
		t.Fatal(e)
	}
	if e = ed.Rename("/a/sub", "/b/moved", false); e != nil {
		t.Fatal(e)
	}
	n, _, e := ed.Resolve("/b/moved/source")
	if e != nil || n.Links() != 2 {
		t.Fatal(e, n)
	}
	if e = ed.RewriteNode(n.Number, 14, []byte("tail"), 18); e != nil {
		t.Fatal(e)
	}
	n, _ = ed.Inode(n.Number)
	b := make([]byte, 30)
	read, e := ed.ReadNodeAt(n, b, 0)
	if !errors.Is(e, io.EOF) || read != 18 || !bytes.Equal(b[:read], []byte("0123456789\x00\x00\x00\x00tail")) {
		t.Fatal(read, b, e)
	}
	if e = ed.RewriteNode(n.Number, 0, nil, 3); e != nil {
		t.Fatal(e)
	}
	alias, _, e := ed.Resolve("/b/alias")
	if e != nil {
		t.Fatal(e)
	}
	var data bytes.Buffer
	if e = ed.Data(alias, &data); e != nil || data.String() != "012" {
		t.Fatal(data.String(), e)
	}
	if e = ed.Rename("/b", "/b/moved/cycle", false); e == nil {
		t.Fatal("directory cycle allowed")
	}
	if e = ed.Remove("/b/alias", false); e != nil {
		t.Fatal(e)
	}
	if e = ed.Commit(); e != nil {
		t.Fatal(e)
	}
}
