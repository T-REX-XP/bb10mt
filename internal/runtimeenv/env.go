// Package runtimeenv locates assets supplied by the single-file launcher.
package runtimeenv

import (
	"os"
	"path/filepath"
)

func Root() string { return os.Getenv("BB10MT_RUNTIME_ROOT") }
func Program() (string, error) {
	if p := os.Getenv("BB10MT_PROGRAM_PATH"); p != "" {
		return p, nil
	}
	return os.Executable()
}
func Library(name string) string {
	if root := Root(); root != "" {
		return filepath.Join(root, "lib", name)
	}
	return name
}
