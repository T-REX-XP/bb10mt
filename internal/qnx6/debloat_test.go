package qnx6

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func TestDebloatListProtectsAndroidAndDeduplicates(t *testing.T) {
	b, e := DebloatList([]string{"sys.weather", "sys.android", "sys.bbm", "sys.android.shell", "sys.bbm"})
	if e != nil || string(b) != "sys.bbm\nsys.weather\n" {
		t.Fatal(string(b), e)
	}
	for _, name := range []string{"../escape", "app\ninjected", "app name", ""} {
		if _, e := DebloatList([]string{name}); e == nil {
			t.Fatal(name)
		}
	}
}
func TestDebloatGenerationTransaction(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "source.ufs"), filepath.Join(dir, "out.ufs")
	if e := Mkfs(input, 1024, 64, 4096); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(input)
	if e := ScriptWithOptions(input, "", output, io.Discard, ScriptOptions{Debloat: true, Blacklist: []string{"sys.android", "sys.weather"}}); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(output)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	st, _ := f.Stat()
	im, e := Open(binio.Reader{ReaderAt: f, Size: st.Size()})
	if e != nil {
		t.Fatal(e)
	}
	n, bad, e := im.Resolve("/accounts/devuser/rootdata/debloat.txt")
	if e != nil || len(bad) != 0 || n.Mode()&07777 != 0777 {
		t.Fatal(e, bad)
	}
	var b bytes.Buffer
	if e = im.Data(n, &b); e != nil || b.String() != "sys.weather\n" {
		t.Fatal(b.String(), e)
	}
	after, _ := os.ReadFile(input)
	if !bytes.Equal(before, after) {
		t.Fatal("source changed")
	}
	badOut := filepath.Join(dir, "bad.ufs")
	if e = ScriptWithOptions(input, "", badOut, io.Discard, ScriptOptions{Debloat: true, Blacklist: []string{"../bad"}}); e == nil {
		t.Fatal("invalid package")
	}
	if _, e = os.Stat(badOut); !os.IsNotExist(e) {
		t.Fatal("published invalid image")
	}
}
