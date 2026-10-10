//go:build linux || darwin

package runtimebundle

import (
	"fmt"
	"os"
	"syscall"
)

func privateDirectory(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("unsafe runtime cache directory: %s", path)
	}
	info, ok := st.Sys().(*syscall.Stat_t)
	if !ok || info.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("runtime cache directory belongs to another user: %s", path)
	}
	return nil
}
