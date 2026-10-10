// launcher is a static bootstrap carrying the application and native libraries.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bb10root/bb10mt/internal/runtimebundle"
)

//go:embed payload.zip
var payload []byte

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "runtime:", err)
		os.Exit(1)
	}
}
func run() error {
	b, err := runtimebundle.Open(payload)
	if err != nil {
		return err
	}
	if b.Manifest.Target != runtime.GOOS+"-"+runtime.GOARCH {
		return fmt.Errorf("runtime target mismatch")
	}
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--runtime-info" {
		return json.NewEncoder(os.Stdout).Encode(b.Manifest)
	}
	if len(args) > 0 && args[0] == "--extract-runtime" {
		if len(args) != 2 {
			return fmt.Errorf("usage: --extract-runtime NEW_DIRECTORY")
		}
		return b.Extract(args[1])
	}
	var root string
	if len(args) > 0 && args[0] == "--runtime-dir" {
		if len(args) < 2 {
			return fmt.Errorf("usage: --runtime-dir DIRECTORY [arguments...]")
		}
		root, err = filepath.Abs(args[1])
		args = args[2:]
	} else {
		root, err = b.Cache()
	}
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	app := filepath.Join(root, filepath.FromSlash(b.Manifest.Application))
	env := []string{}
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(key) {
		case "BB10MT_RUNTIME_ROOT", "BB10MT_PROGRAM_PATH":
			continue
		}
		env = append(env, v)
	}
	env = append(env, "BB10MT_RUNTIME_ROOT="+root, "BB10MT_PROGRAM_PATH="+executable)
	appArgs := append([]string{executable}, args...)
	if b.Manifest.Loader != "" {
		loader := filepath.Join(root, filepath.FromSlash(b.Manifest.Loader))
		appArgs = append([]string{loader, "--library-path", filepath.Join(root, "lib"), app}, args...)
		app = loader
	}
	env = helperEnvironment(root, env)
	return launch(app, appArgs, env)
}
