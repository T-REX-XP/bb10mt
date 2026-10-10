package qnx6

import (
	"bytes"
	"github.com/bb10root/bb10mt/internal/binio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScriptTransactionAndPayload(t *testing.T) {
	_, input := editor(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "file payload.txt")
	os.WriteFile(source, []byte("payload # literal"), 0600)
	script := filepath.Join(dir, "patch.txt")
	os.WriteFile(script, []byte("mkdir -p /var/payload\npush \"file payload.txt\" /var/payload/a-file-with-a-long-filename.txt\nchmod 640 /var/payload/a-file-with-a-long-filename.txt\nchown 0:427 /var/payload/a-file-with-a-long-filename.txt\ntouch /var/flag\n"), 0600)
	before, _ := os.ReadFile(input)
	output := filepath.Join(dir, "new.ufs")
	if err := Script(input, script, output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(input)
	if !bytes.Equal(before, after) {
		t.Fatal("input modified")
	}
	f, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	im, err := Open(binio.Reader{ReaderAt: f, Size: st.Size()})
	if err != nil {
		t.Fatal(err)
	}
	n, bad, err := im.Resolve("/var/payload/a-file-with-a-long-filename.txt")
	if err != nil || len(bad) > 0 || n.Mode()&07777 != 0640 || n.GID() != 427 {
		t.Fatal(err, bad, n)
	}
	var b bytes.Buffer
	if err = im.Data(n, &b); err != nil || b.String() != "payload # literal" {
		t.Fatal(err, b.String())
	}
}
func TestScriptFailureRollsBackEverything(t *testing.T) {
	_, input := editor(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "patch.txt")
	os.WriteFile(script, []byte("mkdir /new\npush missing /new/file\n"), 0600)
	output := filepath.Join(dir, "new.ufs")
	if err := Script(input, script, output, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatal(err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("partial output")
	}
}
func TestScriptPushThenEditAndRemove(t *testing.T) {
	_, input := editor(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "payload"), []byte("before"), 0600)
	script := filepath.Join(dir, "patch.txt")
	os.WriteFile(script, []byte("push payload /changed\nreplace /changed before after\naddstring /changed final\npush payload /removed\nrm /removed\n"), 0600)
	output := filepath.Join(dir, "new.ufs")
	if err := Script(input, script, output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	im, err := Open(binio.Reader{ReaderAt: f, Size: st.Size()})
	if err != nil {
		t.Fatal(err)
	}
	n, _, err := im.Resolve("/changed")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err = im.Data(n, &b); err != nil || b.String() != "after\nfinal\n" {
		t.Fatal(err, b.String())
	}
}
func TestScriptParserPreservesHashesAndWindowsPaths(t *testing.T) {
	commands, err := ParseScript([]byte("push \"C:\\my path\\file\" '/var/#name' # comment\nreplace /a \"\" x\n"))
	if err != nil || commands[0].Args[1] != `C:\my path\file` || commands[0].Args[2] != "/var/#name" || commands[1].Args[2] != "" {
		t.Fatal(commands, err)
	}
	if _, err = ParseScript([]byte("mkdir \"oops")); err == nil {
		t.Fatal("bad quote accepted")
	}
	if _, err = ParseScript([]byte("unknown /path")); err == nil {
		t.Fatal("unknown command accepted")
	}
}
