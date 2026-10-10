package release

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDeterministicArchives(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "payload")
	os.WriteFile(p, []byte("release payload"), 0600)
	for _, win := range []bool{true, false} {
		a := filepath.Join(dir, "a")
		b := filepath.Join(dir, "b")
		entries := []Entry{{Name: "bb10mt", Source: p, Mode: 0755}, {Name: "LICENSE", Source: p, Mode: 0644}}
		if e := Archive(a, entries, win); e != nil {
			t.Fatal(e)
		}
		entries[0], entries[1] = entries[1], entries[0]
		if e := Archive(b, entries, win); e != nil {
			t.Fatal(e)
		}
		x, _ := os.ReadFile(a)
		y, _ := os.ReadFile(b)
		if !bytes.Equal(x, y) {
			t.Fatal("nondeterministic archive")
		}
		ha, _ := SHA256(a)
		hb, _ := SHA256(b)
		if ha != hb || len(ha) != 64 {
			t.Fatal("bad digest")
		}
		os.Remove(a)
		os.Remove(b)
	}
}
