package cli

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/patchpkg"
)

func copyPackTree(source, target string) error {
	return filepath.WalkDir(source, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink assembly input: %s", p)
		}
		if entry.Name() == "__pycache__" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		relative, err := filepath.Rel(source, p)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0755)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			return err
		}
		return copyPackFile(p, destination)
	})
}

// exportWeather keeps the existing three-package boundary and declarative
// manifests. No host hooks or root installation are exported into app packages.
func exportWeather(root, output string) error {
	var weather struct {
		Contract string            `json:"contractVersion"`
		Files    map[string]string `json:"files"`
	}
	if err := packJSON(root, "patched_services/weather.manifest.json", &weather); err != nil {
		return err
	}
	var trust struct {
		Files  map[string]string `json:"files"`
		Copies map[string]string `json:"copies"`
	}
	if err := packJSON(root, "certs/manifest.json", &trust); err != nil {
		return err
	}
	bootHash, err := fileDigest(filepath.Join(root, filepath.FromSlash(bootSource)), nil)
	if err != nil {
		return err
	}
	certHash := trust.Files[certificateSource]
	// Hash the actual manifest bytes. A changed contract gets a new exact version.
	weatherHash, err := fileDigest(filepath.Join(root, "patched_services/weather.manifest.json"), nil)
	if err != nil {
		return err
	}
	foundation := patchpkg.Manifest{SchemaVersion: 1, ID: "foundation.existing-boot", Version: "1.0.0-" + bootHash[:12], Kind: "foundation", Provides: []string{"boot.geoweather-tls-pin/v1"}, Assertions: []patchpkg.Assertion{{Path: "/" + strings.TrimPrefix(bootSource, "patchdata/"), SHA256: bootHash}}}
	ca := patchpkg.Manifest{SchemaVersion: 1, ID: "trust.isrg-root-x1", Version: "1.0.0-" + certHash[:12], Kind: "shared"}
	app := patchpkg.Manifest{SchemaVersion: 1, ID: "app.sys-weather", Version: weather.Contract + "-" + weatherHash[:12], Kind: "app", App: "sys.weather", Requires: []patchpkg.Requirement{{ID: foundation.ID, Version: foundation.Version}, {ID: ca.ID, Version: ca.Version}}, RequiresCapabilities: []string{"boot.geoweather-tls-pin/v1"}}
	for _, p := range []patchpkg.Manifest{foundation, ca, app} {
		if err := os.MkdirAll(filepath.Join(output, p.ID), 0755); err != nil {
			return err
		}
	}
	if err := copyPackFile(filepath.Join(root, certificateSource), filepath.Join(output, ca.ID, "isrgrootx1.pem")); err != nil {
		return err
	}
	destinations := make([]string, 0, len(trust.Copies))
	for target := range trust.Copies {
		destinations = append(destinations, target)
	}
	sort.Strings(destinations)
	for _, target := range destinations {
		if strings.HasPrefix(target, "/apps/sys.appworld.") {
			parts := strings.SplitN(target, "/", 4)
			if len(parts) != 4 {
				return fmt.Errorf("invalid trust destination")
			}
			target = "app:/sys.appworld/" + parts[3]
		} else if !strings.HasPrefix(target, "/var/") {
			return fmt.Errorf("unsupported trust destination")
		}
		ca.Owns = append(ca.Owns, target)
		ca.Operations = append(ca.Operations, patchpkg.Operation{Type: "put-file", Path: target, Source: "isrgrootx1.pem", SHA256: certHash, Mode: "0644", AllowAbsent: true})
	}
	sources := make([]string, 0, len(weather.Files))
	for source := range weather.Files {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	copied := map[string]bool{}
	for _, source := range sources {
		name := filepath.Base(source)
		if copied[name] {
			return fmt.Errorf("duplicate Weather payload basename: %s", name)
		}
		copied[name] = true
		p, err := packPath(root, source)
		if err != nil {
			return err
		}
		digest, err := fileDigest(p, nil)
		if err != nil {
			return err
		}
		if digest != weather.Files[source] {
			return fmt.Errorf("Weather source changed during export: %s", source)
		}
		if err := copyPackFile(p, filepath.Join(output, app.ID, name)); err != nil {
			return err
		}
		op := patchpkg.Operation{Type: "put-file", Source: name, SHA256: digest, Mode: "0755", AllowAbsent: true}
		switch {
		case strings.HasPrefix(source, "patchdata/apps/sys.weather.") && strings.Contains(source, "/native/lib/"):
			op.Path = "app:/sys.weather/native/lib/" + name
			op.OriginalSHA256 = []string{"156d52b4468819fede2c2e22fea82c6982916da5a255f40ee1b8a656c826ad2f"}
		case strings.HasPrefix(source, "patchdata/var/weather-libs/"):
			op.Path = "/var/weather-libs/" + name
		case source == "patchdata/var/pps/services/carrier_config/lib/geoweather/weatherdata/metars":
			op.Path = "/" + strings.TrimPrefix(source, "patchdata/")
			op.Mode, op.UID, op.GID = "0640", 379, 379
		default:
			return fmt.Errorf("unexpected Weather source: %s", source)
		}
		app.Owns = append(app.Owns, op.Path)
		app.Operations = append(app.Operations, op)
	}
	if len(app.Operations) != 5 {
		return fmt.Errorf("expected five Weather payloads")
	}
	for _, p := range []patchpkg.Manifest{foundation, ca, app} {
		if err := writePackJSON(filepath.Join(output, p.ID, "manifest.json"), p); err != nil {
			return err
		}
	}
	profile := patchpkg.Profile{SchemaVersion: 1, Packages: []patchpkg.Requirement{{ID: foundation.ID, Version: foundation.Version}, {ID: app.ID, Version: app.Version}}}
	if err := writePackJSON(filepath.Join(output, "weather.json"), profile); err != nil {
		return err
	}
	_, err = patchpkg.Load(output)
	return err
}

func assemblePatcher(pack, release, source, commit, output string, log io.Writer) error {
	var err error
	pack, err = filepath.Abs(pack)
	if err != nil {
		return err
	}
	release, err = filepath.Abs(release)
	if err != nil {
		return err
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return err
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	for _, input := range []string{pack, release, source} {
		relative, err := filepath.Rel(input, output)
		if err != nil || relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return fmt.Errorf("output must be outside input directories")
		}
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output already exists: %s: %w", output, os.ErrExist)
	} else if !os.IsNotExist(err) {
		return err
	}
	fmt.Fprintln(log, "Assembly 1/4: validating source manifests and release SHA256 inventory")
	if _, err := foundationExpected(pack); err != nil {
		return err
	}
	var sbom struct {
		Metadata struct {
			Component struct {
				Version string `json:"version"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := packJSON(release, "sbom.cdx.json", &sbom); err != nil {
		return err
	}
	version := sbom.Metadata.Component.Version
	if !strings.HasPrefix(version, "v0.7.") || strings.ContainsAny(version, "/\\:\r\n ") {
		return fmt.Errorf("unsupported release version: %s", version)
	}
	sumsPath, err := packPath(release, "SHA256SUMS")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	sums := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		digest, name, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "  ")
		raw, e := hex.DecodeString(digest)
		if !ok || e != nil || len(raw) != sha256.Size || filepath.Base(name) != name || sums[name] != "" {
			return fmt.Errorf("invalid release SHA256 inventory")
		}
		p, e := packPath(release, name)
		if e != nil {
			return e
		}
		actual, e := fileDigest(p, nil)
		if e != nil {
			return e
		}
		if actual != digest {
			return fmt.Errorf("release SHA256 mismatch: %s", name)
		}
		sums[name] = digest
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".v4-neo-assemble-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, name := range []string{"patch.txt", "patchdata", "certs", "patched_apps", "patched_services"} {
		if err := copyPackTree(filepath.Join(pack, name), filepath.Join(stage, "foundation", name)); err != nil {
			return err
		}
	}
	// Copy templates explicitly; old wrappers and host-side tests never ship.
	for _, name := range []string{"README.md", "DESIGN.md", ".github/workflows/validate.yml"} {
		target := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := copyPackFile(filepath.Join(source, "patchers/v4-neo", filepath.FromSlash(name)), target); err != nil {
			return err
		}
	}
	if st, e := os.Stat(filepath.Join(source, "patchers/v4-neo/docs")); e == nil && st.IsDir() {
		if err := copyPackTree(filepath.Join(source, "patchers/v4-neo/docs"), filepath.Join(stage, "docs")); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(stage, "docs"), 0755); err != nil {
		return err
	}
	for _, name := range []string{"PACKAGES.md", "ERROR_CODES.md", "PERFORMANCE.md", "PERFORMANCE_VALIDATION.json"} {
		if err := copyPackFile(filepath.Join(source, "docs", name), filepath.Join(stage, "docs", name)); err != nil {
			return err
		}
	}
	fmt.Fprintln(log, "Assembly 2/4: copying six bundled executables and verified notices")
	executables := map[string]string{}
	releaseCopy := func(name, target string) error {
		if sums[name] == "" {
			return fmt.Errorf("release inventory missing: %s", name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := copyPackFile(filepath.Join(release, name), target); err != nil {
			return err
		}
		digest, err := fileDigest(target, nil)
		if err != nil {
			return err
		}
		if digest != sums[name] {
			return fmt.Errorf("release changed during copy: %s", name)
		}
		return nil
	}
	for _, target := range []string{"windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"} {
		suffix := ""
		if strings.HasPrefix(target, "windows-") {
			suffix = ".exe"
		}
		relative := "bin/" + target + "/bb10mt" + suffix
		if err := releaseCopy("bb10mt-"+version+"-"+target+suffix, filepath.Join(stage, filepath.FromSlash(relative))); err != nil {
			return err
		}
		if suffix == "" {
			if err := os.Chmod(filepath.Join(stage, relative), 0755); err != nil {
				return err
			}
		}
		executables[target] = relative
	}
	for _, name := range []string{"DEPENDENCIES.md", "runtime.lock.json", "sbom.cdx.json", "runtime-sources.zip", "build-version.json"} {
		if err := releaseCopy(name, filepath.Join(stage, "toolchain", name)); err != nil {
			return err
		}
	}
	archive := "bb10mt-" + version + "-windows-amd64.zip"
	if sums[archive] == "" {
		return fmt.Errorf("release license archive missing")
	}
	z, err := zip.OpenReader(filepath.Join(release, archive))
	if err != nil {
		return err
	}
	defer z.Close()
	for _, entry := range z.File {
		if entry.Name != "LICENSE" && entry.Name != "THIRD_PARTY_NOTICES.md" && !strings.HasPrefix(entry.Name, "third_party/licenses/") {
			continue
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if pathIsUnsafe(entry.Name) || entry.Mode()&os.ModeSymlink != 0 || entry.UncompressedSize64 > 4<<20 {
			return fmt.Errorf("unsafe release license entry: %s", entry.Name)
		}
		target := filepath.Join(stage, "toolchain", filepath.FromSlash(entry.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		r, err := entry.Open()
		if err != nil {
			return err
		}
		err = atomicfile.Write(target, func(f *os.File) error { _, e := binio.BulkCopyN(f, r, int64(entry.UncompressedSize64)); return e })
		r.Close()
		if err != nil {
			return err
		}
	}
	// Recheck the archive because the ZIP reader and inventory read are separate.
	archiveHash, err := fileDigest(filepath.Join(release, archive), nil)
	if err != nil {
		return err
	}
	if archiveHash != sums[archive] {
		return fmt.Errorf("release archive changed during assembly")
	}
	fmt.Fprintln(log, "Assembly 3/4: exporting manifests and sealing the source snapshot")
	if _, err := foundationExpected(filepath.Join(stage, "foundation")); err != nil {
		return err
	}
	before, err := packInventory(filepath.Join(stage, "foundation"))
	if err != nil {
		return err
	}
	sourceFiles := 1 // patch.txt plus the four selected source trees
	for _, name := range []string{"patch.txt", "patchdata", "certs", "patched_apps", "patched_services"} {
		original := filepath.Join(pack, name)
		if name == "patch.txt" {
			digest, e := fileDigest(original, nil)
			if e != nil {
				return e
			}
			if digest != before[name] {
				return fmt.Errorf("source changed during assembly: %s", name)
			}
			continue
		}
		files, e := packInventory(original)
		if e != nil {
			return e
		}
		sourceFiles += len(files)
		for p, digest := range files {
			if before[name+"/"+p] != digest {
				return fmt.Errorf("source changed during assembly: %s", p)
			}
		}
	}
	if sourceFiles != len(before) {
		return fmt.Errorf("source inventory changed during assembly")
	}
	if err := exportWeather(filepath.Join(stage, "foundation"), filepath.Join(stage, "packages")); err != nil {
		return err
	}
	files, err := packInventory(stage)
	if err != nil {
		return err
	}
	for relative := range files {
		if strings.HasPrefix(relative, "packages/") {
			delete(files, relative)
		}
	}
	lock := patcherLock{SchemaVersion: 1, Patcher: "v4-neo", ToolVersion: version, SourceCommit: commit, SourcePack: pack, BootHash: before[bootSource], CertificateHash: before[certificateSource], Executables: executables, Files: files, Private: true, HostKey: true}
	if err := writePackJSON(filepath.Join(stage, "neo.lock.json"), lock); err != nil {
		return err
	}
	fmt.Fprintln(log, "Assembly 4/4: validating and atomically publishing the pack")
	if _, _, err := validatePatcher(stage, log); err != nil {
		return err
	}
	return atomicfile.PublishDirectory(stage, output)
}

func pathIsUnsafe(name string) bool {
	return name == "" || filepath.IsAbs(name) || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") || strings.Contains("/"+name+"/", "/../") || strings.Contains("/"+name+"/", "/./")
}
