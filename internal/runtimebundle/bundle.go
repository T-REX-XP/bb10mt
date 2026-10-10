// Package runtimebundle verifies and extracts the runtime embedded in a release.
package runtimebundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/release"
)

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}
type Manifest struct {
	Schema      int    `json:"schema"`
	Version     string `json:"version,omitempty"`
	Target      string `json:"target"`
	Application string `json:"application"`
	Loader      string `json:"loader,omitempty"`
	Files       []File `json:"files"`
}

func validPath(name string) bool {
	return name != "." && path.Clean(name) == name && filepath.IsLocal(name) && !strings.ContainsAny(name, "\\:") && !strings.HasPrefix(name, "/")
}

// Pack records every payload file, with deterministic modes and SHA256 hashes.
func Pack(root, output, target, app, loader string) error {
	return PackVersion(root, output, target, app, loader, "")
}

func PackVersion(root, output, target, app, loader, version string) error {
	m := Manifest{Schema: 1, Version: version, Target: target, Application: app, Loader: loader}
	var entries []release.Entry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("nonregular payload file: %s", p)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" || !validPath(rel) {
			return fmt.Errorf("invalid payload path: %s", rel)
		}
		hash, err := release.SHA256(p)
		if err != nil {
			return err
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		mode := uint32(0644)
		if rel == app || strings.HasPrefix(rel, "bin/") || strings.HasPrefix(rel, "lib/") {
			mode = 0755
		}
		m.Files = append(m.Files, File{rel, hash, st.Size(), mode})
		entries = append(entries, release.Entry{Name: rel, Source: p, Mode: int64(mode)})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(output), ".runtime-manifest-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	_, err = temp.Write(append(data, '\n'))
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	entries = append(entries, release.Entry{Name: "manifest.json", Source: temp.Name(), Mode: 0644})
	return release.Archive(output, entries, true)
}

type Bundle struct {
	Manifest     Manifest
	ID           string
	archive      *zip.Reader
	manifestData []byte
}

func Open(data []byte) (*Bundle, error) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	b := &Bundle{archive: z, ID: fmt.Sprintf("%x", sha256.Sum256(data))}
	names := map[string]*zip.File{}
	for _, f := range z.File {
		if !validPath(f.Name) || !f.Mode().IsRegular() || names[f.Name] != nil {
			return nil, fmt.Errorf("invalid runtime archive entry: %q", f.Name)
		}
		names[f.Name] = f
	}
	mf := names["manifest.json"]
	if mf == nil || mf.UncompressedSize64 > 8<<20 {
		return nil, fmt.Errorf("runtime manifest missing or oversized")
	}
	r, err := mf.Open()
	if err != nil {
		return nil, err
	}
	b.manifestData, err = io.ReadAll(io.LimitReader(r, 8<<20))
	r.Close()
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(b.manifestData))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&b.Manifest)
	if err != nil {
		return nil, err
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("trailing runtime manifest data")
	}
	m := b.Manifest
	if m.Schema != 1 || !validPath(m.Application) || (m.Loader != "" && !validPath(m.Loader)) {
		return nil, fmt.Errorf("invalid runtime manifest")
	}
	seen := map[string]bool{"manifest.json": true}
	var total int64
	for _, f := range m.Files {
		hash, e := hex.DecodeString(f.SHA256)
		if !validPath(f.Path) || seen[f.Path] || e != nil || len(hash) != 32 || f.Size < 0 || f.Size > 1<<30 || (f.Mode != 0644 && f.Mode != 0755) {
			return nil, fmt.Errorf("invalid runtime file: %q", f.Path)
		}
		entry := names[f.Path]
		if entry == nil || entry.UncompressedSize64 != uint64(f.Size) || uint32(entry.Mode().Perm()) != f.Mode {
			return nil, fmt.Errorf("runtime file metadata mismatch: %s", f.Path)
		}
		total += f.Size
		if total > 2<<30 {
			return nil, fmt.Errorf("runtime too large")
		}
		seen[f.Path] = true
	}
	if len(seen) != len(names) || !seen[m.Application] || (m.Loader != "" && !seen[m.Loader]) {
		return nil, fmt.Errorf("runtime inventory mismatch")
	}
	return b, nil
}

// Extract publishes into a new directory; existing files are never overwritten.
func (b *Bundle) Extract(destination string) error {
	parent := filepath.Dir(destination)
	stage, err := os.MkdirTemp(parent, ".bb10mt-runtime-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, f := range b.archive.File {
		p := filepath.Join(stage, filepath.FromSlash(f.Name))
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, f.Mode().Perm())
		if err != nil {
			r.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(r, int64(f.UncompressedSize64)+1))
		ce := out.Close()
		re := r.Close()
		if err != nil {
			return err
		}
		if ce != nil {
			return ce
		}
		if re != nil {
			return re
		}
		if err = os.Chmod(p, f.Mode().Perm()); err != nil {
			return err
		}
	}
	if err = b.Verify(stage); err != nil {
		return err
	}
	return atomicfile.PublishDirectory(stage, destination)
}

// Verify refuses changed files, symlinks and unlisted additions in the cache.
func (b *Bundle) Verify(root string) error {
	st, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime root is not a directory")
	}
	expected := map[string]File{}
	for _, f := range b.Manifest.Files {
		expected[f.Path] = f
	}
	seen := 0
	manifestSeen := false
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			return fmt.Errorf("nonregular runtime file: %s", rel)
		}
		if rel == "manifest.json" {
			manifestSeen = true
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if !bytes.Equal(data, b.manifestData) {
				return fmt.Errorf("changed runtime manifest")
			}
			return nil
		}
		f, ok := expected[rel]
		if !ok {
			return fmt.Errorf("unexpected runtime file: %s", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() != f.Size {
			return fmt.Errorf("runtime size mismatch: %s", rel)
		}
		if runtime.GOOS != "windows" && uint32(info.Mode().Perm()) != f.Mode {
			return fmt.Errorf("runtime mode mismatch: %s", rel)
		}
		hash, err := release.SHA256(p)
		if err != nil {
			return err
		}
		if hash != f.SHA256 {
			return fmt.Errorf("runtime SHA256 mismatch: %s", rel)
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(expected) || !manifestSeen {
		return fmt.Errorf("runtime files missing")
	}
	return nil
}

func (b *Bundle) Cache() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	parent := filepath.Join(base, "bb10mt", "runtimes")
	if err = os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	// Refuse links in the application-controlled part of the cache path.
	for _, p := range []string{filepath.Join(base, "bb10mt"), parent} {
		if err = os.Mkdir(p, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
		if err = privateDirectory(p); err != nil {
			return "", err
		}
	}
	root := filepath.Join(parent, b.ID)
	if _, err = os.Lstat(root); os.IsNotExist(err) {
		if err = b.Extract(root); err != nil {
			// Another concurrent launch may have published the same verified bundle.
			if verifyErr := b.Verify(root); verifyErr != nil {
				return "", err
			}
		}
	} else if err != nil {
		return "", err
	}
	if err = privateDirectory(root); err != nil {
		return "", err
	}
	if err = b.Verify(root); err != nil {
		return "", fmt.Errorf("cached runtime failed verification (remove %s to recreate it): %w", root, err)
	}
	return root, nil
}
