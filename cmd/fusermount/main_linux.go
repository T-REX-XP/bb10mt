// fusermount invokes the bundled helper through its bundled ELF loader. It is
// deliberately unprivileged; mounting still requires appropriate OS permissions.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func main() {
	p, err := os.Executable()
	if err == nil {
		root := filepath.Dir(filepath.Dir(p))
		loader := "ld-linux-x86-64.so.2"
		if runtime.GOARCH == "arm64" {
			loader = "ld-linux-aarch64.so.1"
		}
		bin := filepath.Join(root, "lib", loader)
		args := []string{bin, "--library-path", filepath.Join(root, "lib"), filepath.Join(root, "lib", "fusermount3.real")}
		err = syscall.Exec(bin, append(args, os.Args[1:]...), os.Environ())
	}
	fmt.Fprintln(os.Stderr, "bundled fusermount3:", err)
	os.Exit(1)
}
