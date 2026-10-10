package runtimebundle

import (
	"fmt"
	"os"
)

func privateDirectory(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe runtime cache directory: %s", path)
	}
	return nil
}
