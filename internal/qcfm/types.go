// Package qcfm reads and writes BlackBerry QCFM V1/V2/hybrid sparse containers.
package qcfm

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const BlockSize = 65536
const maxHeader = 64 << 20

type Run struct{ Offset, Count uint32 }
type Chunk struct {
	Type       uint32 `json:"type"`
	Flags      uint32 `json:"flags"`
	BlockSize  uint32 `json:"blockSize"`
	Runs       []Run  `json:"runs"`
	DataOffset int64  `json:"dataOffset"`
	DataSize   int64  `json:"dataSize"`
}
type Container struct {
	Version    int     `json:"version"`
	HeaderSize int64   `json:"headerSize"`
	PayloadEnd int64   `json:"payloadEnd"`
	Signed     bool    `json:"signatureTrailerCRCVerified"`
	V1         []Chunk `json:"v1,omitempty"`
	V2         []Chunk `json:"v2,omitempty"`
}

func (c Container) Chunks() []Chunk {
	if len(c.V2) > 0 {
		return c.V2
	}
	return c.V1
}

var extensions = map[string]uint32{
	".nvram": 3, ".ufs": 5, ".mbr": 6, ".sig": 7, ".ifs": 8, ".rcfs": 9,
	".radio.mbr": 10, ".radio.sig": 11, ".radio.rcfs": 12, ".calwork": 15,
	".calbackup": 16, ".dmi": 17, ".dmi.mbr": 18, ".dmi.fsys": 19, ".os": 24,
	".sig2": 137, ".radio.sig2": 140, ".dmi.sig2": 147,
}

func TypeFor(path string) uint32 {
	// Match the longest suffix so radio and DMI partition identities survive.
	keys := make([]string, 0, len(extensions))
	for k := range extensions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		if strings.HasSuffix(strings.ToLower(path), k) {
			return extensions[k]
		}
	}
	return 0
}
func Extension(t uint32) string {
	for ext, v := range extensions {
		if t == v {
			return ext
		}
	}
	return ".unk"
}

type Input struct {
	Path  string
	Delta uint32
	Flags uint32
}

// ParseInput accepts legacy file=offset,flags list rows. Paths are relative to
// the list file, including paths with subdirectories, never the process cwd.
func ParseInput(row, base string) (Input, error) {
	var in Input
	row = strings.TrimSpace(strings.TrimPrefix(row, "\ufeff"))
	if row == "" {
		return in, fmt.Errorf("empty input row")
	}
	name, params, has := strings.Cut(row, "=")
	name = strings.TrimSpace(name)
	if name == "" {
		return in, fmt.Errorf("empty input path")
	}
	if !filepath.IsAbs(name) {
		name = filepath.Join(base, name)
	}
	in.Path = filepath.Clean(name)
	if has {
		p := strings.Split(params, ",")
		if len(p) > 2 {
			return in, fmt.Errorf("invalid input metadata: %q", row)
		}
		for i, s := range p {
			v, e := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
			if e != nil {
				return in, fmt.Errorf("invalid input metadata: %w", e)
			}
			if i == 0 {
				in.Delta = uint32(v)
			} else {
				in.Flags = uint32(v)
			}
		}
	}
	return in, nil
}
