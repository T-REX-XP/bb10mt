package qnx6

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

type NameIssue struct {
	Directory        uint32 `json:"directoryInode"`
	Name             string `json:"name"`
	Offset           int64  `json:"offset"`
	Stored, Expected uint32
}
type Audit struct {
	SuperOffset int64       `json:"superblockOffset"`
	BlockSize   uint32      `json:"blockSize"`
	UsedInodes  int         `json:"usedInodes"`
	Directories int         `json:"directories"`
	Names       int         `json:"names"`
	Issues      []NameIssue `json:"incorrectLongNames"`
}

// AuditNames checks every allocated directory, including unreachable ones.
// It intentionally does not claim bitmap/link-count fsck or OEM acceptance.
func (im *Image) AuditNames() (Audit, error) {
	a := Audit{SuperOffset: im.SuperOffset, BlockSize: im.BlockSize, Issues: []NameIssue{}}
	for i := uint32(1); i <= im.Inodes; i++ {
		n, e := im.Inode(i)
		if e != nil {
			return a, e
		}
		if n.Mode() == 0 {
			continue
		}
		a.UsedInodes++
		if n.Mode()&0xf000 != 0x4000 {
			continue
		}
		a.Directories++
		entries, e := im.Entries(n)
		if e != nil {
			return a, fmt.Errorf("directory %d: %w", i, e)
		}
		for _, v := range entries {
			a.Names++
			if v.ChecksumOffset >= 0 && v.Stored != v.Expected {
				a.Issues = append(a.Issues, NameIssue{i, v.Name, v.ChecksumOffset, v.Stored, v.Expected})
			}
		}
	}
	sort.Slice(a.Issues, func(i, j int) bool { return a.Issues[i].Offset < a.Issues[j].Offset })
	return a, nil
}

type Expected struct {
	Path     string  `json:"path"`
	SHA256   string  `json:"sha256"`
	Mode     *uint16 `json:"mode,omitempty"`
	UID, GID *uint32
}

func (im *Image) VerifyPayloads(expected []Expected) error {
	for _, v := range expected {
		n, bad, e := im.Resolve(v.Path)
		if e != nil {
			return e
		}
		if len(bad) > 0 {
			return fmt.Errorf("bad pathname checksum: %s", v.Path)
		}
		if v.Mode != nil && n.Mode()&07777 != *v.Mode {
			return fmt.Errorf("mode mismatch: %s", v.Path)
		}
		if v.UID != nil && n.UID() != *v.UID {
			return fmt.Errorf("uid mismatch: %s", v.Path)
		}
		if v.GID != nil && n.GID() != *v.GID {
			return fmt.Errorf("gid mismatch: %s", v.Path)
		}
		if v.SHA256 != "" {
			digest, e := hex.DecodeString(v.SHA256)
			if e != nil || len(digest) != 32 {
				return fmt.Errorf("invalid expected SHA256")
			}
			if n.Mode()&0xf000 != 0x8000 {
				return fmt.Errorf("payload is not a regular file")
			}
			h := sha256.New()
			if e = im.Data(n, h); e != nil {
				return e
			}
			if hex.EncodeToString(h.Sum(nil)) != v.SHA256 {
				return fmt.Errorf("payload SHA256 mismatch: %s", v.Path)
			}
		}
	}
	return nil
}
