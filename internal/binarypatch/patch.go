// Package binarypatch applies exact-base file patches offline. Its compressed
// copy/literal format is BB10MT-specific, not BSDIFF, VCDIFF or a BB10 OTA package.
package binarypatch

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/bb10root/bb10mt/internal/atomicfile"
)

const MaxFileBytes = 64 << 20
const maxDocumentBytes = 96 << 20
const maxActions = 131072
const magic = "BB10MT-DELTA-1\n"

type Edit struct {
	Offset         int    `json:"offset"`
	ExpectedHex    string `json:"expectedHex"`
	ReplacementHex string `json:"replacementHex"`
}
type Chunk struct {
	Offset int    `json:"offset,omitempty"`
	Length int    `json:"length,omitempty"`
	Data   []byte `json:"data,omitempty"`
}
type Patch struct {
	SchemaVersion int     `json:"schemaVersion"`
	Kind          string  `json:"kind"`
	BaseSHA256    string  `json:"baseSha256"`
	TargetSHA256  string  `json:"targetSha256"`
	BaseSize      int     `json:"baseSize"`
	TargetSize    int     `json:"targetSize"`
	Edits         []Edit  `json:"edits,omitempty"`
	Chunks        []Chunk `json:"chunks,omitempty"`
}

func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// ReadFile bounds inputs before allocating and rejects non-regular host files.
func ReadFile(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fmt.Errorf("regular file <=%d bytes required: %s", limit, name)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("file exceeds limit")
	}
	return b, err
}

// Decode accepts a plain JSON byte-edit recipe or a magic-prefixed gzip delta.
// The bounded token pass rejects duplicate keys, excessive nesting and trailing
// JSON so a patch has one meaning before decoding its typed representation.
func Decode(data []byte) (Patch, error) {
	var p Patch
	compressed := bytes.HasPrefix(data, []byte(magic))
	if compressed {
		r := bytes.NewReader(data[len(magic):])
		z, err := gzip.NewReader(r)
		if err != nil {
			return p, err
		}
		z.Multistream(false)
		data, err = io.ReadAll(io.LimitReader(z, maxDocumentBytes+1))
		closeErr := z.Close()
		if err != nil {
			return p, err
		}
		if closeErr != nil {
			return p, closeErr
		}
		if r.Len() != 0 {
			return p, fmt.Errorf("trailing delta data")
		}
	}
	if len(data) > maxDocumentBytes {
		return p, fmt.Errorf("patch document too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 12 {
			return fmt.Errorf("patch nesting too deep")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return fmt.Errorf("duplicate/invalid patch key")
					}
					seen[s] = true
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("unexpected JSON delimiter")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return p, err
	}
	if _, err := d.Token(); err != io.EOF {
		return p, fmt.Errorf("trailing patch JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	if compressed && p.Kind != "delta" || !compressed && p.Kind != "edits" {
		return p, fmt.Errorf("patch kind does not match encoding")
	}
	return p, p.Validate()
}

func Load(name string) (Patch, error) {
	b, err := ReadFile(name, maxDocumentBytes)
	if err != nil {
		return Patch{}, err
	}
	return Decode(b)
}

func (p Patch) Validate() error {
	if p.SchemaVersion != 1 || !validHash(p.BaseSHA256) || !validHash(p.TargetSHA256) || p.BaseSize < 0 || p.BaseSize > MaxFileBytes || p.TargetSize < 0 || p.TargetSize > MaxFileBytes {
		return fmt.Errorf("invalid patch header or file size (maximum 64 MiB)")
	}
	switch p.Kind {
	case "edits":
		if len(p.Chunks) != 0 || len(p.Edits) == 0 || len(p.Edits) > maxActions || p.TargetSize != p.BaseSize {
			return fmt.Errorf("byte edits require equal sizes and nonempty edits only")
		}
		end := 0
		for _, e := range p.Edits {
			before, err := hex.DecodeString(e.ExpectedHex)
			if err != nil {
				return err
			}
			after, err := hex.DecodeString(e.ReplacementHex)
			if err != nil {
				return err
			}
			if len(before) == 0 || len(before) != len(after) || e.Offset < end || e.Offset > p.BaseSize || len(before) > p.BaseSize-e.Offset {
				return fmt.Errorf("edits must be sorted, nonoverlapping, in range and equal length")
			}
			end = e.Offset + len(before)
		}
	case "delta":
		if len(p.Edits) != 0 || len(p.Chunks) > maxActions {
			return fmt.Errorf("invalid delta actions")
		}
		total := 0
		for _, c := range p.Chunks {
			n := len(c.Data)
			if n > 0 {
				if c.Offset != 0 || c.Length != 0 {
					return fmt.Errorf("mixed literal/copy action")
				}
			} else {
				if c.Offset < 0 || c.Offset > p.BaseSize || c.Length <= 0 || c.Length > p.BaseSize-c.Offset {
					return fmt.Errorf("copy outside base")
				}
				n = c.Length
			}
			if n > p.TargetSize-total {
				return fmt.Errorf("delta exceeds target size")
			}
			total += n
		}
		if total != p.TargetSize {
			return fmt.Errorf("delta target size mismatch")
		}
	default:
		return fmt.Errorf("unsupported binary patch kind")
	}
	return nil
}

func (p Patch) Apply(base []byte) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(base) != p.BaseSize || Digest(base) != p.BaseSHA256 {
		return nil, fmt.Errorf("binary patch source SHA256/size mismatch")
	}
	var out []byte
	if p.Kind == "edits" {
		out = bytes.Clone(base)
		for _, e := range p.Edits {
			before, _ := hex.DecodeString(e.ExpectedHex)
			after, _ := hex.DecodeString(e.ReplacementHex)
			if !bytes.Equal(base[e.Offset:e.Offset+len(before)], before) {
				return nil, fmt.Errorf("expected bytes mismatch at offset %d", e.Offset)
			}
			copy(out[e.Offset:], after)
		}
	} else {
		out = make([]byte, 0, p.TargetSize)
		for _, c := range p.Chunks {
			if len(c.Data) > 0 {
				out = append(out, c.Data...)
			} else {
				out = append(out, base[c.Offset:c.Offset+c.Length]...)
			}
		}
	}
	if Digest(out) != p.TargetSHA256 {
		return nil, fmt.Errorf("binary patch target SHA256 mismatch")
	}
	return out, nil
}

// Diff indexes aligned 64-byte source blocks, then scans the target for reusable
// spans. Insertions/deletions and moved spans are supported. Gzip compresses the
// remaining literals. This is deliberately a bounded file delta, not an image
// differ or a claim of optimal/minimum-size encoding.
func Diff(base, target []byte) (Patch, error) {
	p := Patch{SchemaVersion: 1, Kind: "delta", BaseSHA256: Digest(base), TargetSHA256: Digest(target), BaseSize: len(base), TargetSize: len(target)}
	if len(base) > MaxFileBytes || len(target) > MaxFileBytes {
		return p, fmt.Errorf("binary files exceed 64 MiB")
	}
	const block = 64
	index := map[[32]byte]int{}
	for off := 0; off+block <= len(base); off += block {
		h := sha256.Sum256(base[off : off+block])
		if _, ok := index[h]; !ok {
			index[h] = off
		}
	}
	start := 0
	for pos := 0; pos+block <= len(target); {
		off, ok := index[sha256.Sum256(target[pos:pos+block])]
		if !ok || !bytes.Equal(base[off:off+block], target[pos:pos+block]) {
			pos++
			continue
		}
		if pos > start {
			p.Chunks = append(p.Chunks, Chunk{Data: bytes.Clone(target[start:pos])})
		}
		n := block
		for off+n < len(base) && pos+n < len(target) && base[off+n] == target[pos+n] {
			n++
		}
		p.Chunks = append(p.Chunks, Chunk{Offset: off, Length: n})
		pos += n
		start = pos
	}
	if start < len(target) {
		p.Chunks = append(p.Chunks, Chunk{Data: bytes.Clone(target[start:])})
	}
	if err := p.Validate(); err != nil {
		return p, err
	}
	_, err := p.Apply(base)
	return p, err
}

func (p Patch) Encode() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Kind == "edits" {
		return json.MarshalIndent(p, "", "  ")
	}
	var b bytes.Buffer
	b.WriteString(magic)
	z := gzip.NewWriter(&b)
	if err := json.NewEncoder(z).Encode(p); err != nil {
		return nil, err
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func Create(basePath, targetPath, output string) error {
	base, err := ReadFile(basePath, MaxFileBytes)
	if err != nil {
		return err
	}
	target, err := ReadFile(targetPath, MaxFileBytes)
	if err != nil {
		return err
	}
	p, err := Diff(base, target)
	if err != nil {
		return err
	}
	b, err := p.Encode()
	if err != nil {
		return err
	}
	decoded, err := Decode(b)
	if err != nil {
		return err
	}
	replay, err := decoded.Apply(base)
	if err != nil {
		return err
	}
	if !bytes.Equal(replay, target) {
		return fmt.Errorf("serialized binary delta reconstruction differs")
	}
	return atomicfile.Write(output, func(f *os.File) error { _, err := f.Write(b); return err })
}

func ApplyFile(input, patch, output string) error {
	p, err := Load(patch)
	if err != nil {
		return err
	}
	b, err := ReadFile(input, MaxFileBytes)
	if err != nil {
		return err
	}
	out, err := p.Apply(b)
	if err != nil {
		return err
	}
	return atomicfile.Write(output, func(f *os.File) error { _, err := f.Write(out); return err })
}
