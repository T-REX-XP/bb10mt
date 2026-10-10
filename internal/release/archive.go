// Package release produces deterministic distribution archives and hashes.
package release

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/bb10root/bb10mt/internal/atomicfile"
)

type Entry struct {
	Name, Source string
	Mode         int64
}

func Archive(output string, entries []Entry, windows bool) error {
	entries = append([]Entry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for i, e := range entries {
		if !filepath.IsLocal(e.Name) || filepath.ToSlash(e.Name) != e.Name {
			return fmt.Errorf("invalid archive path")
		}
		if i > 0 && entries[i-1].Name == e.Name {
			return fmt.Errorf("duplicate archive entry")
		}
	}
	return atomicfile.Write(output, func(out *os.File) error {
		if windows {
			z := zip.NewWriter(out)
			for _, v := range entries {
				f, e := os.Open(v.Source)
				if e != nil {
					return e
				}
				st, e := f.Stat()
				if e != nil {
					f.Close()
					return e
				}
				h := &zip.FileHeader{Name: v.Name, Method: zip.Deflate, Modified: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)}
				h.SetMode(os.FileMode(v.Mode))
				h.UncompressedSize64 = uint64(st.Size())
				w, e := z.CreateHeader(h)
				if e == nil {
					_, e = io.Copy(w, f)
				}
				f.Close()
				if e != nil {
					return e
				}
			}
			return z.Close()
		}
		gz := gzip.NewWriter(out)
		gz.Header.OS = 255
		tw := tar.NewWriter(gz)
		for _, v := range entries {
			f, e := os.Open(v.Source)
			if e != nil {
				return e
			}
			st, e := f.Stat()
			if e != nil {
				f.Close()
				return e
			}
			h := &tar.Header{Name: v.Name, Mode: v.Mode, Size: st.Size(), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
			e = tw.WriteHeader(h)
			if e == nil {
				_, e = io.Copy(tw, f)
			}
			f.Close()
			if e != nil {
				return e
			}
		}
		if e := tw.Close(); e != nil {
			return e
		}
		return gz.Close()
	})
}
func SHA256(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
