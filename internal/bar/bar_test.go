package bar

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeAssetHashAndMetadataPreserved(t *testing.T) {
	dir := t.TempDir()
	if err := Template(dir, "test"); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "sys.data.test")
	os.Mkdir(filepath.Join(root, "native"), 0755)
	os.WriteFile(filepath.Join(root, "native", "binary"), []byte("native payload"), 0644)
	path := filepath.Join(root, "META-INF", "MANIFEST.MF")
	before, _ := os.ReadFile(path)
	if err := Update(root); err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err != nil {
		t.Fatal(err)
	}
	_, _, m, err := manifestFile(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range m {
		if s.Get("Archive-Asset-Name") == "native/binary" {
			sum := sha512.Sum512([]byte("native payload"))
			want := base64.RawURLEncoding.EncodeToString(sum[:])
			if s.Get("Archive-Asset-SHA-512-Digest") != want || len(want) != 86 {
				t.Fatal("incorrect digest encoding")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("native asset omitted")
	}
	after, _ := os.ReadFile(path)
	if bytes.Equal(before, after) {
		t.Fatal("manifest unchanged")
	}
	if err = IDs(root); err != nil {
		t.Fatal(err)
	}
	if err = Verify(root); err != nil {
		t.Fatal(err)
	}
}
func TestFoldedManifestRoundtrip(t *testing.T) {
	m := Manifest{Section{{"Package-Locale", strings.Repeat("en,", 80)}, {"Name", "UTF-8 text"}}, Section{{"Archive-Asset-Name", "native/a"}, {"Archive-Asset-SHA-512-Digest", strings.Repeat("a", 86)}}}
	b := m.Bytes()
	got, err := Parse(b)
	if err != nil || got[0].Get("Package-Locale") != m[0].Get("Package-Locale") || got[1].Get("Archive-Asset-SHA-512-Digest") != m[1].Get("Archive-Asset-SHA-512-Digest") {
		t.Fatal(got, err)
	}
	for _, line := range strings.Split(string(b), "\r\n") {
		if len(line) > 72 {
			t.Fatal("line too long")
		}
	}
}
func TestVerifyRejectsUnlistedAsset(t *testing.T) {
	dir := t.TempDir()
	if err := Template(dir, "test"); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "sys.data.test")
	if err := os.WriteFile(filepath.Join(root, "extra"), []byte("unlisted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err == nil {
		t.Fatal("unlisted file accepted")
	}
	if err := Update(root); err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err != nil {
		t.Fatal(err)
	}
}
func TestUnsafeAssetNeverChangesManifest(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "META-INF"), 0755)
	p := filepath.Join(dir, "META-INF", "MANIFEST.MF")
	b := []byte("Archive-Manifest-Version: 1.5\r\n\r\nArchive-Asset-Name: ../secret\r\nArchive-Asset-SHA-512-Digest: x\r\n\r\n")
	os.WriteFile(p, b, 0600)
	if err := Update(dir); err == nil {
		t.Fatal("unsafe asset accepted")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(b, after) {
		t.Fatal("failed update changed manifest")
	}
}
func FuzzManifest(f *testing.F) {
	f.Add([]byte("Archive-Manifest-Version: 1.5\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		m, err := Parse(b)
		if err == nil {
			if _, err = Parse(m.Bytes()); err != nil {
				t.Fatal(err)
			}
		}
	})
}
