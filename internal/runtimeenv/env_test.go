package runtimeenv

import (
	"path/filepath"
	"testing"
)

func TestBundledPaths(t *testing.T) {
	t.Setenv("BB10MT_RUNTIME_ROOT", t.TempDir())
	t.Setenv("BB10MT_PROGRAM_PATH", filepath.Join(t.TempDir(), "bb10mt"))
	if Library("libusb") != filepath.Join(Root(), "lib", "libusb") {
		t.Fatal("library escaped runtime root")
	}
	p, err := Program()
	if err != nil || p == "" {
		t.Fatal(p, err)
	}
	t.Setenv("BB10MT_RUNTIME_ROOT", "")
	if Library("libusb") != "libusb" {
		t.Fatal("unbundled library path changed")
	}
}
