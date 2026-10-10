package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func invoke(args ...string) (string, error) {
	var out, errOut bytes.Buffer
	e := Run(args, &out, &errOut, "test")
	return out.String(), e
}
func TestPackUnpackFromDifferentWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	if e := os.Mkdir(filepath.Join(dir, "inputs"), 0700); e != nil {
		t.Fatal(e)
	}
	payload := bytes.Repeat([]byte{42}, 65536)
	os.WriteFile(filepath.Join(dir, "inputs", "data.ufs"), payload, 0600)
	list := filepath.Join(dir, "partitions.lst")
	os.WriteFile(list, []byte("inputs/data.ufs\n"), 0600)
	container := filepath.Join(dir, "p.signed")
	if _, e := invoke("pack", "-c", container, "-l", list, "-s"); e != nil {
		t.Fatal(e)
	}
	if s, e := invoke("verify", "-c", container); e != nil || !strings.Contains(s, "signatureTrailerCRCVerified\":true") {
		t.Fatal(s, e)
	}
	out := filepath.Join(dir, "unpacked")
	if _, e := invoke("unpack", "-c", container, "-o", out); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(filepath.Join(out, "p.0.ufs"))
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatal(e, "roundtrip failed")
	}
	repacked := filepath.Join(dir, "again.signed")
	if _, e := invoke("pack", "-c", repacked, "-l", filepath.Join(out, "p.lst"), "-s"); e != nil {
		t.Fatal(e)
	}
	a, _ := os.ReadFile(container)
	b, _ := os.ReadFile(repacked)
	if !bytes.Equal(a, b) {
		t.Fatal("nondeterministic roundtrip")
	}
}
func TestErrorsAndHelp(t *testing.T) {
	for _, args := range [][]string{{"pack"}, {"pack", "--oops"}, {"pack", "-c", "out", "-i", "missing", "--versions", "3"}, {"split", "-i", "missing"}, {"not-a-command"}, {"autoloader"}, {"pack", "--help", "trailing"}, {"pack", "-c", "out", "-i", "a", "-l", "b"}} {
		_, e := invoke(args...)
		if len(args) > 1 && args[1] == "--help" {
			continue
		}
		if e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, args := range [][]string{{}, {"--help"}, {"--version"}, {"pack", "--help"}} {
		if _, e := invoke(args...); e != nil {
			t.Fatal(args, e)
		}
	}
}
func TestFailedExtractionLeavesNoDirectory(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bad")
	os.WriteFile(in, []byte("mfcq"), 0600)
	out := filepath.Join(dir, "out")
	if _, e := invoke("unpack", "-c", in, "-o", out); e == nil {
		t.Fatal("bad input accepted")
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("failed output published")
	}
}
func TestCompletionUsesNativeCommandDefinitions(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{{[]string{"--complete", "qnx6", "co"}, "compact\n"}, {[]string{"--complete", "pack", "--ver"}, "--versions\n"}, {[]string{"--complete", "autoloader", ""}, "loaders\n"}, {[]string{"--help-complete"}, "-block-size"}} {
		out, err := invoke(tc.args...)
		if err != nil || !strings.Contains(out, tc.want) {
			t.Fatal(out, err)
		}
	}
}

func TestFlashValidatesBeforeLoadingUSB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.signed")
	os.WriteFile(path, []byte("mfcqbroken"), 0600)
	_, e := invoke("flash", "-i", path, "--libusb", "deliberately-missing-library")
	if e == nil || strings.Contains(e.Error(), "load libusb") {
		t.Fatal(e)
	}
}
