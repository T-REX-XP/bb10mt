package runtimebundle

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func fixture(t *testing.T) ([]byte, *Bundle) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "app"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app", "bb10mt"), []byte("test app"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), []byte("license"), 0600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "payload.zip")
	if err := Pack(root, p, "test", "app/bb10mt", ""); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	return data, b
}

func TestRuntimeTamperingAndNoOverwrite(t *testing.T) {
	_, b := fixture(t)
	for _, change := range []string{"bytes", "missing", "extra", "manifest", "mode", "symlink"} {
		t.Run(change, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "runtime")
			if err := b.Extract(root); err != nil {
				t.Fatal(err)
			}
			if err := b.Extract(root); err == nil {
				t.Fatal("overwrote runtime")
			}
			app := filepath.Join(root, "app", "bb10mt")
			var err error
			switch change {
			case "bytes":
				err = os.WriteFile(app, []byte("evil app"), 0755)
			case "missing":
				err = os.Remove(app)
			case "extra":
				err = os.WriteFile(filepath.Join(root, "extra.dll"), []byte("extra"), 0644)
			case "manifest":
				err = os.Remove(filepath.Join(root, "manifest.json"))
			case "mode":
				if runtime.GOOS == "windows" {
					t.Skip("Windows has no POSIX executable mode")
				}
				err = os.Chmod(app, 0644)
			case "symlink":
				if runtime.GOOS == "windows" {
					t.Skip("Windows symlinks require optional privileges")
				}
				err = os.Remove(app)
				if err == nil {
					err = os.Symlink(filepath.Join(root, "LICENSE"), app)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = b.Verify(root); err == nil {
				t.Fatal("accepted tampered runtime")
			}
		})
	}
}

func TestManifestRejectsUnsafeAndUnlistedFiles(t *testing.T) {
	_, b := fixture(t)
	for _, name := range []string{"../escape", "/absolute", "a\\b", "C:/escape", "app/bb10mt"} {
		t.Run(name, func(t *testing.T) {
			var data bytes.Buffer
			z := zip.NewWriter(&data)
			m, _ := json.Marshal(b.Manifest)
			w, _ := z.Create("manifest.json")
			w.Write(m)
			w, _ = z.Create(name)
			w.Write([]byte("bad"))
			z.Close()
			if _, err := Open(data.Bytes()); err == nil {
				t.Fatal("accepted malformed runtime")
			}
		})
	}
}

func TestConcurrentCacheAndTampering(t *testing.T) {
	_, b := fixture(t)
	cache := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("LocalAppData", cache)
	} else if runtime.GOOS == "darwin" {
		t.Setenv("HOME", cache)
	} else {
		t.Setenv("XDG_CACHE_HOME", cache)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	paths := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Go(func() { p, err := b.Cache(); errs <- err; paths <- p })
	}
	wg.Wait()
	close(errs)
	close(paths)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var root string
	for p := range paths {
		if root != "" && p != root {
			t.Fatal("different runtime cache paths")
		}
		root = p
	}
	if err := os.WriteFile(filepath.Join(root, "app", "bb10mt"), []byte("evil app"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Cache(); err == nil {
		t.Fatal("executed tampered cache")
	}
}

func TestPackDeterministic(t *testing.T) {
	data, b := fixture(t)
	root := filepath.Join(t.TempDir(), "runtime")
	if err := b.Extract(root); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(root, "manifest.json"))
	out := filepath.Join(t.TempDir(), "repeat.zip")
	if err := Pack(root, out, "test", "app/bb10mt", ""); err != nil {
		t.Fatal(err)
	}
	repeat, _ := os.ReadFile(out)
	if !bytes.Equal(data, repeat) {
		t.Fatal("payload is not reproducible")
	}
}
