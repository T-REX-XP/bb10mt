// release builds all portable targets and writes deterministic distribution files.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/release"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "error:", e)
		os.Exit(1)
	}
}
func run() error {
	version := flag.String("version", "", "Release version (e.g. v0.7.0-go.1)")
	output := flag.String("output", "dist", "New output directory")
	flag.Parse()
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?$`).MatchString(*version) {
		return fmt.Errorf("invalid release version")
	}
	if _, e := os.Lstat(*output); e == nil {
		return fmt.Errorf("output already exists")
	} else if !os.IsNotExist(e) {
		return e
	}
	tmp, e := os.MkdirTemp(filepath.Dir(*output), ".bb10mt-release-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	// Record a portable, deterministic module inventory. Host paths and module
	// cache timestamps must not leak into release artifacts.
	list := exec.Command("go", "list", "-m", "-json", "all")
	modules, e := list.Output()
	if e != nil {
		return e
	}
	inventory, sbom, e := dependencyArtifacts(modules, *version, runtime.Version())
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(tmp, "DEPENDENCIES.md"), inventory, 0644); e != nil {
		return e
	}
	targets := [][2]string{{"darwin", "amd64"}, {"darwin", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}}
	var checksums []string
	for _, target := range targets {
		goos, arch := target[0], target[1]
		binary := "bb10mt"
		ext := ".tar.gz"
		if goos == "windows" {
			binary += ".exe"
			ext = ".zip"
		}
		path := filepath.Join(tmp, "build-"+goos+"-"+arch)
		if e = os.Mkdir(path, 0700); e != nil {
			return e
		}
		bin := filepath.Join(path, binary)
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid= -X main.version="+*version, "-o", bin, "./cmd/bb10mt")
		env := []string{}
		for _, v := range os.Environ() {
			key, _, _ := strings.Cut(v, "=")
			switch strings.ToUpper(key) {
			case "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS":
				continue
			}
			env = append(env, v)
		}
		cmd.Env = append(env, "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			return e
		}
		entries := []release.Entry{{Name: binary, Source: bin, Mode: 0755}}
		for _, name := range []string{"LICENSE", "README_GO.md", "bb10mt.ini", "docs/MIGRATION.md", "docs/COMPATIBILITY.md", "docs/VALIDATION.md", "docs/REAL_IMAGE_VALIDATION.json", "docs/REAL_BUILD_VALIDATION.json", "docs/WRAPPER_BUILD_VALIDATION.json", "THIRD_PARTY_NOTICES.md"} {
			entries = append(entries, release.Entry{Name: name, Source: filepath.FromSlash(name), Mode: 0644})
		}
		licenses, err := os.ReadDir("third_party/licenses")
		if err != nil {
			return err
		}
		for _, license := range licenses {
			if !license.Type().IsRegular() {
				return fmt.Errorf("license inventory contains nonregular entry")
			}
			name := "third_party/licenses/" + license.Name()
			entries = append(entries, release.Entry{Name: name, Source: filepath.FromSlash(name), Mode: 0644})
		}
		entries = append(entries, release.Entry{Name: "DEPENDENCIES.md", Source: filepath.Join(tmp, "DEPENDENCIES.md"), Mode: 0644})
		archive := "bb10mt-" + *version + "-" + goos + "-" + arch + ext
		fmt.Println("Packaging", archive)
		if e = release.Archive(filepath.Join(tmp, archive), entries, goos == "windows"); e != nil {
			return e
		}
		digest, e := release.SHA256(filepath.Join(tmp, archive))
		if e != nil {
			return e
		}
		checksums = append(checksums, digest+"  "+archive)
		direct := "bb10mt-" + *version + "-" + goos + "-" + arch
		if goos == "windows" {
			direct += ".exe"
		}
		directPath := filepath.Join(tmp, direct)
		if e = os.Rename(bin, directPath); e != nil {
			return e
		}
		if e = os.Chmod(directPath, 0755); e != nil {
			return e
		}
		digest, e = release.SHA256(directPath)
		if e != nil {
			return e
		}
		checksums = append(checksums, digest+"  "+direct)
		if e = os.Remove(path); e != nil {
			return e
		}
	}
	sbomPath := filepath.Join(tmp, "sbom.cdx.json")
	if e = atomicfile.Write(sbomPath, func(f *os.File) error { _, e := f.Write(sbom); return e }); e != nil {
		return e
	}
	for _, name := range []string{"sbom.cdx.json", "DEPENDENCIES.md"} {
		digest, e := release.SHA256(filepath.Join(tmp, name))
		if e != nil {
			return e
		}
		checksums = append(checksums, digest+"  "+name)
	}
	sort.Strings(checksums)
	if e = os.WriteFile(filepath.Join(tmp, "SHA256SUMS"), []byte(strings.Join(checksums, "\n")+"\n"), 0644); e != nil {
		return e
	}
	return atomicfile.PublishDirectory(tmp, *output)
}
