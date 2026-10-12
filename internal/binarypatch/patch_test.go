package binarypatch

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recipe() (Patch, []byte, []byte) {
	base, target := []byte{0, 1, 2, 255, 0}, []byte{0, 1, 9, 8, 0}
	return Patch{SchemaVersion: 1, Kind: "edits", BaseSHA256: Digest(base), TargetSHA256: Digest(target), BaseSize: 5, TargetSize: 5, Edits: []Edit{{Offset: 2, ExpectedHex: "02ff", ReplacementHex: "0908"}}}, base, target
}

func TestByteEditsAndRejections(t *testing.T) {
	p, base, target := recipe()
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := parsed.Apply(base)
	if err != nil || !bytes.Equal(out, target) {
		t.Fatal(err, out)
	}
	if !bytes.Equal(base, []byte{0, 1, 2, 255, 0}) {
		t.Fatal("input modified")
	}
	for _, test := range []string{"base-hash", "expected-bytes", "target-hash", "overlap", "negative", "out-of-range", "resize", "odd-hex", "mixed-kind", "oversize"} {
		t.Run(test, func(t *testing.T) {
			p, b, _ := recipe()
			switch test {
			case "base-hash":
				b[0] = 99
			case "expected-bytes":
				p.Edits[0].ExpectedHex = "ffff"
			case "target-hash":
				p.TargetSHA256 = Digest(nil)
			case "overlap":
				p.Edits = append(p.Edits, p.Edits[0])
			case "negative":
				p.Edits[0].Offset = -1
			case "out-of-range":
				p.Edits[0].Offset = 5
			case "resize":
				p.Edits[0].ReplacementHex = "00"
			case "odd-hex":
				p.Edits[0].ExpectedHex = "0"
			case "mixed-kind":
				p.Chunks = []Chunk{{Offset: 0, Length: 5}}
			case "oversize":
				p.TargetSize = MaxFileBytes + 1
			}
			if _, err := p.Apply(b); err == nil {
				t.Fatal("invalid patch accepted")
			}
		})
	}
}

func TestDeltaRoundTripAndIndependentReplay(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	base := make([]byte, 16384)
	_, _ = rng.Read(base)
	modified := bytes.Clone(base)
	modified[200] ^= 255
	for _, target := range [][]byte{nil, base, modified, append([]byte("insert"), base...), append(bytes.Clone(base[:512]), base[1024:]...), append(bytes.Clone(base[8192:]), base[:4096]...), bytes.Repeat([]byte{255}, 8192)} {
		p, err := Diff(base, target)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decoded.Apply(base)
		if err != nil || !bytes.Equal(got, target) {
			t.Fatal(err, "delta reconstruction")
		}
		// Independent interpretation of serialized copy/literal commands.
		z, err := gzip.NewReader(bytes.NewReader(encoded[len(magic):]))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Chunks []struct {
				Offset, Length int
				Data           []byte
			}
		}
		if err := json.NewDecoder(z).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		_ = z.Close()
		var replay []byte
		for _, c := range doc.Chunks {
			if len(c.Data) != 0 {
				replay = append(replay, c.Data...)
			} else {
				replay = append(replay, base[c.Offset:c.Offset+c.Length]...)
			}
		}
		if !bytes.Equal(replay, target) {
			t.Fatal("independent replay differs")
		}
		if bytes.Equal(target, modified) && len(encoded) >= len(target)/4 {
			t.Fatal("small edit did not produce a compact delta", len(encoded))
		}
		if _, err := Decode(append(bytes.Clone(encoded), 0)); err == nil {
			t.Fatal("trailing delta bytes accepted")
		}
		corrupt := bytes.Clone(encoded)
		corrupt[len(corrupt)-5] ^= 1
		if _, err := Decode(corrupt); err == nil {
			t.Fatal("corrupt gzip accepted")
		}
	}
}

func TestRejectMalformedDocumentsAndCopies(t *testing.T) {
	p, _, _ := recipe()
	b, _ := p.Encode()
	for _, bad := range [][]byte{append(bytes.Clone(b), []byte(" {}")...), []byte(strings.Replace(string(b), `"kind": "edits"`, `"kind": "edits", "kind": "edits"`, 1)), []byte(strings.Replace(string(b), `"kind": "edits"`, `"unknown": 1, "kind": "edits"`, 1))} {
		if _, err := Decode(bad); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	p, _ = Diff([]byte("a"), []byte("b"))
	for _, c := range []Chunk{{Offset: -1, Length: 1}, {Offset: 1, Length: 1}, {Length: 2}, {Data: []byte("b"), Length: 1}, {}} {
		p.Chunks = []Chunk{c}
		if err := p.Validate(); err == nil {
			t.Fatal("invalid copy accepted", c)
		}
	}
}

func TestFilePublicationAndWrongBase(t *testing.T) {
	dir := t.TempDir()
	input, patch, output := filepath.Join(dir, "input"), filepath.Join(dir, "patch"), filepath.Join(dir, "output")
	p, base, target := recipe()
	encoded, _ := p.Encode()
	if err := os.WriteFile(input, base, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patch, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFile(input, patch, output); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(output)
	if !bytes.Equal(got, target) {
		t.Fatal("output differs")
	}
	if err := ApplyFile(input, patch, output); err == nil {
		t.Fatal("overwrite accepted")
	}
	if err := os.WriteFile(input, target, 0600); err != nil {
		t.Fatal(err)
	}
	badOutput := filepath.Join(dir, "bad")
	if err := ApplyFile(input, patch, badOutput); err == nil {
		t.Fatal("wrong base accepted")
	}
	if _, err := os.Stat(badOutput); !os.IsNotExist(err) {
		t.Fatal("partial output")
	}
	// Empty source -> populated target and populated source -> empty target.
	for _, pair := range [][2][]byte{{nil, target}, {base, nil}} {
		p, err := Diff(pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Apply(pair[0])
		if err != nil {
			t.Fatal(err)
		}
	}
}
