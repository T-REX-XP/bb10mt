package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func helperEnvironment(root string, env []string) []string {
	// An unprivileged bundled helper cannot grant mount privileges. Prefer an
	// administrator-installed, root-owned setuid helper when running unprivileged.
	if os.Geteuid() != 0 {
		if p, err := exec.LookPath("fusermount3"); err == nil {
			if st, err := os.Stat(p); err == nil && st.Mode()&os.ModeSetuid != 0 {
				if stat, ok := st.Sys().(*syscall.Stat_t); ok && stat.Uid == 0 {
					return env
				}
			}
		}
	}
	for i, v := range env {
		if strings.HasPrefix(v, "PATH=") {
			env[i] = "PATH=" + filepath.Join(root, "bin") + ":" + strings.TrimPrefix(v, "PATH=")
			return env
		}
	}
	return append(env, "PATH="+filepath.Join(root, "bin"))
}
