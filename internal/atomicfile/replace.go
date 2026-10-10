package atomicfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

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
