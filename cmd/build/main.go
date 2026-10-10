// build is the numbered source-development binary build entrypoint.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/bb10root/bb10mt/internal/apperror"
	"github.com/bb10root/bb10mt/internal/buildversion"
)

func main() {
	if err := run(); err != nil {
		os.Exit(apperror.Print(os.Stderr, err))
	}
}
func run() error {
	output := flag.String("output", "", "NEW development binary path (host libraries; use cmd/release for bundled binaries)")
	version := flag.String("version", "", "Optional NEW version; otherwise increment automatically")
	flag.Parse()
	if *output == "" {
		suffix := ""
		if runtime.GOOS == "windows" {
			suffix = ".exe"
		}
		*output = filepath.Join("bin", "bb10mt"+suffix)
	}
	if _, err := os.Lstat(*output); err == nil {
		return apperror.New(apperror.OutputExists, "output already exists: "+*output, "Choose a new binary path.")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
		return err
	}
	r, err := buildversion.Reserve("VERSION", ".build-version.json", *version, "")
	if err != nil {
		return apperror.New(apperror.Version, err.Error(), "Omit --version to reserve the next number.")
	}
	fmt.Println("Building", r.Version)
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-X main.version="+r.Version, "-o", *output, "./cmd/bb10mt")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err = cmd.Run(); err != nil {
		return apperror.New(apperror.Tool, err.Error(), "Fix the compiler error and rebuild; the next attempt gets a new version.")
	}
	fmt.Printf("Built %s: %s\n", r.Version, *output)
	return nil
}
