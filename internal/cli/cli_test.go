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

func TestBinaryDiffApplyCommands(t *testing.T) {
	dir := t.TempDir()
	base, target := bytes.Repeat([]byte{0, 1, 2, 255}, 1024), bytes.Repeat([]byte{0, 1, 2, 255}, 1024)
	target[511] = 7
	input, changed, patch, output := filepath.Join(dir, "base"), filepath.Join(dir, "target"), filepath.Join(dir, "patch"), filepath.Join(dir, "output")
	for path, b := range map[string][]byte{input: base, changed: target} {
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := invoke("binary", "diff", "--base", input, "-i", changed, "-o", patch); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke("binary", "apply", "-i", input, "--patch", patch, "-o", output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, target) {
		t.Fatal(err, "CLI reconstruction differs")
	}
	if _, err := invoke("binary", "apply", "-i", input, "--patch", patch, "-o", output); err == nil {
		t.Fatal("overwrite accepted")
	}
	if _, err := invoke("binary", "apply", "-i", changed, "--patch", patch, "-o", filepath.Join(dir, "bad")); err == nil {
		t.Fatal("wrong source accepted")
	}
}

func TestDeltaRequiresExplicitExperimentalMode(t *testing.T) {
	_, err := invoke("autoloader", "delta", "--base", "missing-base", "-i", "missing-target", "-o", filepath.Join(t.TempDir(), "out"))
	if err == nil || !strings.Contains(err.Error(), "requires --experimental") {
		t.Fatal("experimental gate was not checked before opening inputs", err)
	}
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
