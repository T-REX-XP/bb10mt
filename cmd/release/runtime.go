package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bb10root/bb10mt/internal/release"
	"github.com/bb10root/bb10mt/internal/runtimebundle"
)

func buildTarget(goos, arch, output, pkg, overlay, version string) error {
	args := []string{"build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid= -X main.version=" + version, "-o", output}
	if overlay != "" {
		args = append(args, "-overlay", overlay)
	}
	args = append(args, pkg)
	cmd := exec.Command("go", args...)
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(key) {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS":
			continue
		}
		cmd.Env = append(cmd.Env, v)
	}
	cmd.Env = append(cmd.Env, "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Legacy Windows worktrees can retain CRLF despite updated Git attributes.
// Canonicalize project-owned text; upstream third-party notices stay byte exact.
func canonicalText(source string) ([]byte, error) {
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")), nil
}

func stageText(source, root string) (string, error) {
	data, err := canonicalText(source)
	if err != nil {
		return "", err
	}
	output := filepath.Join(root, "release-docs", filepath.FromSlash(source))
	if err = os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return "", err
	}
	err = os.WriteFile(output, data, 0644)
	return output, err
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, p)
		if err != nil {
			return err
		}
		out := filepath.Join(destination, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0700)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("nonregular runtime input: %s", p)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		file, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		_, err = io.Copy(file, in)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}

// Native imports must resolve to the payload or standard OS libraries. This
// catches accidental Homebrew paths, missing ELF libraries and MSVC runtimes.
func validateNative(root, goos, arch string) error {
	return filepath.WalkDir(filepath.Join(root, "lib"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch goos {
		case "linux":
			f, err := elf.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			want := elf.EM_X86_64
			if arch == "arm64" {
				want = elf.EM_AARCH64
			}
			if f.Machine != want {
				return fmt.Errorf("wrong ELF architecture: %s", p)
			}
			deps, err := f.ImportedLibraries()
			if err != nil {
				return err
			}
			for _, dep := range deps {
				if filepath.Base(dep) != dep {
					return fmt.Errorf("absolute native dependency: %s", dep)
				}
				st, err := os.Stat(filepath.Join(root, "lib", dep))
				if err != nil || !st.Mode().IsRegular() {
					return fmt.Errorf("unbundled ELF dependency %s in %s", dep, p)
				}
			}
		case "windows":
			f, err := pe.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			want := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
			if arch == "arm64" {
				want = pe.IMAGE_FILE_MACHINE_ARM64
			}
			if f.Machine != want {
				return fmt.Errorf("wrong PE architecture: %s", p)
			}
			symbols, err := f.ImportedSymbols()
			if err != nil {
				return err
			}
			allowed := map[string]bool{"kernel32.dll": true, "user32.dll": true, "advapi32.dll": true, "ole32.dll": true, "setupapi.dll": true, "cfgmgr32.dll": true, "winusb.dll": true}
			for _, s := range symbols {
				_, dep, _ := strings.Cut(s, ":")
				name := strings.ToLower(dep)
				_, bundledErr := os.Stat(filepath.Join(root, "lib", name))
				if !allowed[name] && bundledErr != nil && !strings.HasPrefix(name, "api-ms-win-crt-") {
					return fmt.Errorf("unbundled Windows dependency: %s", dep)
				}
			}
		case "darwin":
			f, err := macho.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			want := macho.CpuAmd64
			if arch == "arm64" {
				want = macho.CpuArm64
			}
			if f.Cpu != want {
				return fmt.Errorf("wrong Mach-O architecture: %s", p)
			}
			deps, err := f.ImportedLibraries()
			if err != nil {
				return err
			}
			for _, dep := range deps {
				if !strings.HasPrefix(dep, "/usr/lib/") && !strings.HasPrefix(dep, "/System/Library/") {
					return fmt.Errorf("unbundled macOS dependency: %s", dep)
				}
			}
		}
		return nil
	})
}

func bundleTarget(runtimeRoot, buildDir, goos, arch, binary, version string) (string, error) {
	root := filepath.Join(buildDir, "payload")
	if err := copyTree(filepath.Join(runtimeRoot, goos+"-"+arch), root); err != nil {
		return "", err
	}
	if err := validateNative(root, goos, arch); err != nil {
		return "", err
	}
	app := filepath.Join("app", binary)
	if err := os.Mkdir(filepath.Join(root, "app"), 0700); err != nil {
		return "", err
	}
	if err := buildTarget(goos, arch, filepath.Join(root, app), "./cmd/bb10mt", "", version); err != nil {
		return "", err
	}
	var loader string
	if goos == "linux" {
		loader = "lib/ld-linux-x86-64.so.2"
		if arch == "arm64" {
			loader = "lib/ld-linux-aarch64.so.1"
		}
		if err := os.Mkdir(filepath.Join(root, "bin"), 0700); err != nil {
			return "", err
		}
		if err := buildTarget(goos, arch, filepath.Join(root, "bin", "fusermount3"), "./cmd/fusermount", "", version); err != nil {
			return "", err
		}
	}
	for _, name := range []string{"LICENSE", "bb10mt.ini"} {
		data, err := canonicalText(name)
		if err != nil {
			return "", err
		}
		if err = os.WriteFile(filepath.Join(root, name), data, 0644); err != nil {
			return "", err
		}
	}
	for _, item := range [][2]string{{"docs/BUNDLED_RUNTIME.md", "RUNTIME.md"}, {"third_party/runtime.lock.json", "runtime.lock.json"}} {
		data, err := os.ReadFile(item[0])
		if err != nil {
			return "", err
		}
		if err = os.WriteFile(filepath.Join(root, item[1]), data, 0644); err != nil {
			return "", err
		}
	}
	payload := filepath.Join(buildDir, "payload.zip")
	if err := runtimebundle.PackVersion(root, payload, goos+"-"+arch, filepath.ToSlash(app), loader, version); err != nil {
		return "", err
	}
	placeholder, err := filepath.Abs("cmd/launcher/payload.zip")
	if err != nil {
		return "", err
	}
	payload, err = filepath.Abs(payload)
	if err != nil {
		return "", err
	}
	overlay := filepath.Join(buildDir, "overlay.json")
	data, err := json.Marshal(map[string]any{"Replace": map[string]string{placeholder: payload}})
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(overlay, data, 0600); err != nil {
		return "", err
	}
	output := filepath.Join(buildDir, binary)
	if err = buildTarget(goos, arch, output, "./cmd/launcher", overlay, version); err != nil {
		return "", err
	}
	if goos == "linux" {
		f, err := elf.Open(output)
		if err != nil {
			return "", err
		}
		defer f.Close()
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				return "", fmt.Errorf("launcher requires a host ELF loader")
			}
		}
		deps, err := f.ImportedLibraries()
		if err != nil {
			return "", err
		}
		if len(deps) != 0 {
			return "", fmt.Errorf("launcher has native library dependencies")
		}
	}
	return output, nil
}

func nativeArtifacts(sbom []byte, runtimeRoot string) ([]byte, error) {
	lock, err := os.ReadFile(filepath.Join(runtimeRoot, "runtime.lock.json"))
	if err != nil {
		return nil, err
	}
	expectedLock, err := os.ReadFile("third_party/runtime.lock.json")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(lock, expectedLock) {
		return nil, fmt.Errorf("runtime inputs do not match the committed lock; rerun scripts/vendor_runtime.py")
	}
	var native struct {
		Assets  []struct{ ID, Package, Version, URL, SHA256, Source string }
		Sources []struct{ Filename, SHA256 string }
	}
	if err = json.Unmarshal(lock, &native); err != nil {
		return nil, err
	}
	for _, source := range native.Sources {
		if filepath.Base(source.Filename) != source.Filename {
			return nil, fmt.Errorf("invalid source archive name")
		}
		digest, err := release.SHA256(filepath.Join(runtimeRoot, "sources", source.Filename))
		if err != nil {
			return nil, err
		}
		if digest != source.SHA256 {
			return nil, fmt.Errorf("native source SHA256 mismatch: %s", source.Filename)
		}
	}
	var bom map[string]any
	if err = json.Unmarshal(sbom, &bom); err != nil {
		return nil, err
	}
	components := bom["components"].([]any)
	dependencies := bom["dependencies"].([]any)[0].(map[string]any)
	refs := dependencies["dependsOn"].([]any)
	for _, asset := range native.Assets {
		ref := "native:" + asset.ID
		refs = append(refs, ref)
		notice := "embedded runtime licenses/; matching source in runtime-sources.zip"
		if asset.Package == "Microsoft-VC-Runtime" {
			notice = "embedded Microsoft proprietary redistributable license; source not available"
		}
		components = append(components, map[string]any{"bom-ref": ref, "type": "library", "name": asset.Package, "version": asset.Version,
			"hashes":             []any{map[string]string{"alg": "SHA-256", "content": asset.SHA256}},
			"externalReferences": []any{map[string]string{"type": "distribution", "url": asset.URL}},
			"properties":         []any{map[string]string{"name": "bb10mt:source-package", "value": asset.Source}, map[string]string{"name": "bb10mt:licenses", "value": notice}}})
	}
	dependencies["dependsOn"] = refs
	bom["components"] = components
	data, err := json.MarshalIndent(bom, "", "  ")
	return append(data, '\n'), err
}
