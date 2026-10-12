package qnx6

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binarypatch"
	"github.com/bb10root/bb10mt/internal/binio"
)

func TestBinaryPatchScriptMetadataAndRollback(t *testing.T) {
	for _, kind := range []string{"edits", "delta"} {
		t.Run(kind, func(t *testing.T) {
			_, input := editor(t)
			dir := t.TempDir()
			base := []byte{0, 1, 2, 3, 255}
			target := []byte{0, 1, 9, 3, 255}
			payload, seed, seeded := filepath.Join(dir, "payload"), filepath.Join(dir, "seed"), filepath.Join(dir, "seeded.ufs")
			if err := os.WriteFile(payload, base, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(seed, []byte(fmt.Sprintf("push %q /library.so\nchmod 751 /library.so\nchown 123:427 /library.so\n", filepath.ToSlash(payload))), 0600); err != nil {
				t.Fatal(err)
			}
			if err := Script(input, seed, seeded, io.Discard); err != nil {
				t.Fatal(err)
			}
			p := binarypatch.Patch{SchemaVersion: 1, Kind: "edits", BaseSHA256: binarypatch.Digest(base), TargetSHA256: binarypatch.Digest(target), BaseSize: 5, TargetSize: 5, Edits: []binarypatch.Edit{{Offset: 2, ExpectedHex: "02", ReplacementHex: "09"}}}
			if kind == "delta" {
				var err error
				target = append(target, 0, 0)
				p, err = binarypatch.Diff(base, target)
				if err != nil {
					t.Fatal(err)
				}
			}
			encoded, err := p.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "patch"), encoded, 0600); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(dir, "script")
			if err := os.WriteFile(script, []byte("binarypatch /library.so patch\n"), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(dir, "output.ufs")
			before, _ := os.ReadFile(seeded)
			if err := Script(seeded, script, output, io.Discard); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(seeded)
			if !bytes.Equal(before, after) {
				t.Fatal("source image modified")
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
			n, _, err := im.Resolve("/library.so")
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if err := im.Data(n, &got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), target) || n.Mode()&07777 != 0751 || n.UID() != 123 || n.GID() != 427 {
				t.Fatal("payload/metadata differs", n)
			}
			// Applying against the already changed binary must fail transactionally.
			failed := filepath.Join(dir, "failed.ufs")
			if err := Script(output, script, failed, io.Discard); err == nil {
				t.Fatal("wrong image base accepted")
			}
			if _, err := os.Stat(failed); !os.IsNotExist(err) {
				t.Fatal("partial image published")
			}
		})
	}
}
