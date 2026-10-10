// Package atomicfile publishes verified files without overwriting existing data.
package atomicfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Write builds a temporary sibling and publishes it only after build succeeds.
// Hard-link publication provides atomic no-replace semantics on supported local
// filesystems. Unsupported filesystems fail instead of weakening that guarantee.
func Write(path string, build func(*os.File) error) (err error) {
	if _, e := os.Lstat(path); e == nil {
		return fmt.Errorf("output already exists: %s: %w", path, os.ErrExist)
	} else if !os.IsNotExist(e) {
		return e
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".bb10mt-*")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	if err = build(f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Link(f.Name(), path); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	return nil
}

// Replace is for small metadata files: compare the original bytes, then commit
// a synced sibling with a single rename. Binary image mutations use Write.
func Replace(path string, before, after []byte) error {
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, before) {
		return fmt.Errorf("metadata changed before update: %s", path)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("metadata must be a regular file")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".bb10mt-meta-*")
	if err != nil {
		return err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if _, err = f.Write(after); err != nil {
		return err
	}
	if err = f.Chmod(st.Mode().Perm()); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	current, err = os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, before) {
		return fmt.Errorf("metadata changed during update: %s", path)
	}
	return os.Rename(f.Name(), path)
}
