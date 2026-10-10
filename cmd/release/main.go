// release builds all portable targets and writes deterministic distribution files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/bb10root/bb10mt/internal/apperror"
	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/buildversion"
	"github.com/bb10root/bb10mt/internal/release"
)

func main() {
	if e := run(); e != nil {
		os.Exit(apperror.Print(os.Stderr, e))
	}
}
func run() error {
	version := flag.String("version", "", "Reserve this NEW version, or omit to increment automatically")
	buildID := flag.String("build-id", "", "Optional unique CI build identity (also taken from GitHub Actions)")
	output := flag.String("output", "dist", "New output directory")
	runtimeRoot := flag.String("runtime-root", "out/runtimes", "Verified runtime inputs prepared by scripts/vendor_runtime.py")
	flag.Parse()
	if _, e := os.Lstat(*output); e == nil {
		return apperror.New(apperror.OutputExists, "output already exists: "+*output, "Choose a new release output directory.")
	} else if !os.IsNotExist(e) {
		return e
	}
	tmp, e := os.MkdirTemp(filepath.Dir(*output), ".bb10mt-release-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	if *buildID == "" && os.Getenv("GITHUB_RUN_ID") != "" {
		*buildID = os.Getenv("GITHUB_RUN_ID") + "." + os.Getenv("GITHUB_RUN_ATTEMPT") + "." + os.Getenv("GITHUB_JOB")
	}
	record, e := buildversion.Reserve("VERSION", ".build-version.json", *version, *buildID)
	if e != nil {
		return apperror.New(apperror.Version, e.Error(), "Keep the build counter state; omit --version for the next available version.")
	}
	*version = record.Version
	fmt.Printf("Building %s (previous allocation %s)\n", *version, record.Previous)
	versionData, e := json.MarshalIndent(record, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(tmp, "build-version.json"), append(versionData, '\n'), 0644); e != nil {
		return e
	}
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
	sbom, e = nativeArtifacts(sbom, *runtimeRoot)
	if e != nil {
		return e
	}
	inventory = append(inventory, []byte("\nNative runtime archives, versions, hashes and source locations: runtime.lock.json.\nLibraries and helpers are embedded in each executable. Extract with --extract-runtime.\nMatching source archives and distro patches: runtime-sources.zip.\n")...)
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
		bin, err := bundleTarget(*runtimeRoot, path, goos, arch, binary, *version)
		if err != nil {
			return err
		}
		entries := []release.Entry{{Name: binary, Source: bin, Mode: 0755}}
		for _, name := range []string{"LICENSE", "README_GO.md", "bb10mt.ini", "docs/BUNDLED_RUNTIME.md", "docs/ERROR_CODES.md", "docs/PACKAGES.md", "docs/PACKAGE_BUILD_VALIDATION.json", "docs/PACKAGE_CAP_VALIDATION.json", "docs/PACKAGE_CAP_IMAGE_VALIDATION.json", "docs/MIGRATION.md", "docs/COMPATIBILITY.md", "docs/VALIDATION.md", "docs/REAL_IMAGE_VALIDATION.json", "docs/REAL_BUILD_VALIDATION.json", "docs/WRAPPER_BUILD_VALIDATION.json", "THIRD_PARTY_NOTICES.md"} {
			source, err := stageText(name, path)
			if err != nil {
				return err
			}
			entries = append(entries, release.Entry{Name: name, Source: source, Mode: 0644})
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
		if e = os.RemoveAll(path); e != nil {
			return e
		}
	}
	// Publish the exact native source archives and distro patches alongside binaries.
	var sources []release.Entry
	if e = filepath.WalkDir(filepath.Join(*runtimeRoot, "sources"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("nonregular source archive")
		}
		sources = append(sources, release.Entry{Name: d.Name(), Source: p, Mode: 0644})
		return nil
	}); e != nil {
		return e
	}
	lockPath := filepath.Join(*runtimeRoot, "runtime.lock.json")
	lockData, e := os.ReadFile(lockPath)
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(tmp, "runtime.lock.json"), lockData, 0644); e != nil {
		return e
	}
	sources = append(sources, release.Entry{Name: "runtime.lock.json", Source: lockPath, Mode: 0644}, release.Entry{Name: "vendor_runtime.py", Source: "scripts/vendor_runtime.py", Mode: 0644}, release.Entry{Name: "RUNTIME.md", Source: "docs/BUNDLED_RUNTIME.md", Mode: 0644})
	if e = release.Archive(filepath.Join(tmp, "runtime-sources.zip"), sources, true); e != nil {
		return e
	}
	sbomPath := filepath.Join(tmp, "sbom.cdx.json")
	if e = atomicfile.Write(sbomPath, func(f *os.File) error { _, e := f.Write(sbom); return e }); e != nil {
		return e
	}
	for _, name := range []string{"sbom.cdx.json", "DEPENDENCIES.md", "runtime.lock.json", "runtime-sources.zip", "build-version.json"} {
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
