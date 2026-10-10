package rcfs

import (
	"encoding/json"
	"fmt"
	"github.com/bb10root/bb10mt/internal/binio"
	"os"
	"path/filepath"
)

// Extract writes files/directories only into a newly staged directory. Links and
// original uid/gid/modes are recorded, so extraction is usable without root or
// Windows symlink privileges and cannot follow image-supplied links.
func (im *Image) Extract(dir string) error {
	if _, err := im.Verify(); err != nil {
		return err
	}
	type metadata struct {
		Path     string
		Mode     uint16
		UID, GID uint32
		Link     string `json:",omitempty"`
	}
	var records []metadata
	var walk func(Node, string) error
	walk = func(n Node, p string) error {
		if n.Index != 1 {
			if !filepath.IsLocal(n.Name) || n.Name == ".bb10mt-rcfs.json" {
				return fmt.Errorf("RCFS name unavailable on this host: %s", n.Name)
			}
			p = filepath.Join(p, n.Name)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		record := metadata{Path: filepath.ToSlash(rel), Mode: n.Mode, UID: binio.U32(n.Raw, 24), GID: binio.U32(n.Raw, 28)}
		switch n.Mode & 0xf000 {
		case 0x4000:
			if err = os.MkdirAll(p, 0755); err != nil {
				return err
			}
			children, err := im.Children(n)
			if err != nil {
				return err
			}
			for _, c := range children {
				if err = walk(c, p); err != nil {
					return err
				}
			}
		case 0x8000:
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(n.Mode&0777))
			if err != nil {
				return err
			}
			err = im.Data(n, f)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		case 0xa000:
			if n.Size > 4096 {
				return fmt.Errorf("symlink target too long")
			}
			var b stringWriter
			if err = im.Data(n, &b); err != nil {
				return err
			}
			record.Link = string(b)
		}
		records = append(records, record)
		return nil
	}
	root, err := im.Node(1)
	if err != nil {
		return err
	}
	if err = walk(root, dir); err != nil {
		return err
	}
	b, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ".bb10mt-rcfs.json"), append(b, '\n'), 0644)
}

type stringWriter []byte

func (b *stringWriter) Write(p []byte) (int, error) { *b = append(*b, p...); return len(p), nil }
