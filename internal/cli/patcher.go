package cli

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bb10root/bb10mt/internal/apperror"
	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/autoloader"
	"github.com/bb10root/bb10mt/internal/batch"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/patchpkg"
	"github.com/bb10root/bb10mt/internal/qnx6"
)

const bootSource = "patchdata/apps/sys.android.gYABgKAOw1czN6neiAT72SGO.ns/native/system/xbin/btool"
const certificateSource = "certs/isrgrootx1.pem"

type patcherLock struct {
	SchemaVersion   int               `json:"schemaVersion"`
	Patcher         string            `json:"patcher"`
	ToolVersion     string            `json:"toolVersion"`
	SourceCommit    string            `json:"sourceCommit"`
	SourcePack      string            `json:"sourcePack"`
	BootHash        string            `json:"bootHookSha256"`
	CertificateHash string            `json:"canonicalCertificateSha256"`
	Executables     map[string]string `json:"executables"`
	Files           map[string]string `json:"files"`
	Private         bool              `json:"privateLocalPack"`
	LoginKey        bool              `json:"handsetLoginKeyIncluded"`
	HostKey         bool              `json:"firmwareSSHHostKeyIncluded"`
}

// All pack reads use portable relative paths and reject links in every component.
func packPath(root, relative string) (string, error) {
	if relative == "" || path.Clean(relative) != relative || strings.ContainsAny(relative, "\\:\x00\r\n") || strings.HasPrefix(relative, "/") {
		return "", fmt.Errorf("unsafe pack path %q", relative)
	}
	p := root
	for _, part := range append([]string{""}, strings.Split(relative, "/")...) {
		if part == "." || part == ".." {
			return "", fmt.Errorf("unsafe pack path %q", relative)
		}
		p = filepath.Join(p, part)
		st, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink pack input: %s", relative)
		}
	}
	st, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("pack input is not a regular file: %s", relative)
	}
	return p, nil
}

func packJSON(root, relative string, value any) error {
	p, err := packPath(root, relative)
	if err != nil {
		return err
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return fmt.Errorf("pack JSON exceeds 4 MiB: %s", relative)
	}
	return json.Unmarshal(data, value)
}

func writePackJSON(p string, value any) error {
	return atomicfile.Write(p, func(f *os.File) error { e := json.NewEncoder(f); e.SetIndent("", "  "); return e.Encode(value) })
}

func fileDigest(p string, log io.Writer) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("regular file required: %s", p)
	}
	h := sha256.New()
	var copied int64
	for copied < st.Size() {
		n := min(int64(64<<20), st.Size()-copied)
		if _, err = binio.BulkCopyN(h, f, n); err != nil {
			return "", err
		}
		copied += n
		if log != nil && st.Size() >= 256<<20 {
			fmt.Fprintf(log, "SHA256 %s: %d%% (%d/%d MiB)\n", filepath.Base(p), copied*100/st.Size(), copied>>20, st.Size()>>20)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func packInventory(root string) (map[string]string, error) {
	files := map[string]string{}
	err := filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink pack input: %s", p)
		}
		if entry.Name() == "__pycache__" {
			return fmt.Errorf("generated host cache in pack: %s", p)
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		h, err := fileDigest(p, nil)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = h
		return nil
	})
	return files, err
}

type serviceManifest struct {
	Files  map[string]string `json:"files"`
	Bundle *serviceManifest  `json:"bundle"`
}

// foundationExpected checks declared payloads and derives the final verification
// manifest, including last-assignment permissions from the legacy patch script.
// Binary transformation authoring tests remain in the maintained source pack;
// delivered snapshots carry their exact bytes, not host-side Python validators.
func foundationExpected(root string) ([]qnx6.Expected, error) {
	var app struct {
		PackageName string `json:"packageName"`
		PackageID   string `json:"packageId"`
		Files       []struct {
			Path     string  `json:"path"`
			Source   string  `json:"source"`
			SHA256   string  `json:"sha256"`
			Original *string `json:"originalSha256"`
		} `json:"files"`
	}
	if err := packJSON(root, "patched_apps/sys.appworld.manifest.json", &app); err != nil {
		return nil, err
	}
	expected := map[string]qnx6.Expected{}
	declared := map[string]string{}
	add := func(source, target, digest string) error {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || digest != strings.ToLower(digest) {
			return fmt.Errorf("invalid payload SHA256: %s", source)
		}
		if !strings.HasPrefix(target, "/") || path.Clean(target) != target {
			return fmt.Errorf("invalid firmware path: %s", target)
		}
		p, err := packPath(root, source)
		if err != nil {
			return err
		}
		actual, err := fileDigest(p, nil)
		if err != nil {
			return err
		}
		if actual != digest {
			return fmt.Errorf("staged SHA256 mismatch: %s", source)
		}
		if old, ok := expected[target]; ok && old.SHA256 != digest {
			return fmt.Errorf("conflicting payload: %s", target)
		}
		expected[target] = qnx6.Expected{Path: target, SHA256: digest}
		declared[source] = digest
		return nil
	}
	appBase := "/apps/" + app.PackageName + "." + app.PackageID + "/"
	if app.PackageName != "sys.appworld" || app.PackageID == "" || strings.ContainsAny(app.PackageID, "/\\:") || len(app.Files) == 0 {
		return nil, fmt.Errorf("invalid App World identity/manifest")
	}
	for _, row := range app.Files {
		source := row.Source
		if source == "" {
			source = "patchdata" + appBase + row.Path
		}
		if err := add(source, appBase+row.Path, row.SHA256); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"bbid.manifest.json", "bbid-autostart.json", "weather.manifest.json", "bbm.manifest.json", "ukrainian.manifest.json"} {
		var m serviceManifest
		if err := packJSON(root, "patched_services/"+name, &m); err != nil {
			return nil, err
		}
		if m.Bundle != nil {
			m = *m.Bundle
		}
		if len(m.Files) == 0 {
			return nil, fmt.Errorf("empty service manifest: %s", name)
		}
		for source, digest := range m.Files {
			if !strings.HasPrefix(source, "patchdata/") {
				return nil, fmt.Errorf("invalid service source: %s", source)
			}
			if err := add(source, "/"+strings.TrimPrefix(source, "patchdata/"), digest); err != nil {
				return nil, err
			}
		}
	}
	var cert struct {
		Files  map[string]string `json:"files"`
		Copies map[string]string `json:"copies"`
	}
	if err := packJSON(root, "certs/manifest.json", &cert); err != nil {
		return nil, err
	}
	if len(cert.Files) != 1 || len(cert.Copies) != 3 || cert.Files[certificateSource] == "" {
		return nil, fmt.Errorf("expected one canonical certificate and three destinations")
	}
	p, err := packPath(root, certificateSource)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("canonical certificate must contain one public PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA {
		return nil, fmt.Errorf("invalid public CA certificate")
	}
	var weather struct {
		Certificate string `json:"certificateSHA256"`
	}
	if err := packJSON(root, "patched_services/weather.manifest.json", &weather); err != nil {
		return nil, err
	}
	if weather.Certificate != cert.Files[certificateSource] {
		return nil, fmt.Errorf("Weather certificate hash differs from canonical certificate")
	}
	for _, target := range []string{appBase + "native/assets/certs/isrgrootx1.pem", "/var/certmgr/common/user_trusted/isrgrootx1.pem", "/var/newcert/cert_E0AB059420725493056062023670F7CD2EFC6666.pem"} {
		if cert.Copies[target] != certificateSource {
			return nil, fmt.Errorf("missing shared certificate destination: %s", target)
		}
		if _, err := os.Lstat(filepath.Join(root, "patchdata", filepath.FromSlash(strings.TrimPrefix(target, "/")))); !os.IsNotExist(err) {
			return nil, fmt.Errorf("certificate must have a single canonical source: %s", target)
		}
		if err := add(certificateSource, target, cert.Files[certificateSource]); err != nil {
			return nil, err
		}
	}
	if declared[bootSource] == "" {
		return nil, fmt.Errorf("maintained boot hook missing from service manifests")
	}
	var bbm struct {
		BootHash string `json:"bootHookSha256"`
	}
	if err := packJSON(root, "patched_services/bbm.manifest.json", &bbm); err != nil {
		return nil, err
	}
	if bbm.BootHash != declared[bootSource] {
		return nil, fmt.Errorf("boot hook differs from BBM startup contract")
	}
	script, err := os.ReadFile(filepath.Join(root, "patch.txt"))
	if err != nil {
		return nil, err
	}
	commands, err := qnx6.ParseScript(script)
	if err != nil {
		return nil, err
	}
	appsPush := -1
	copied := map[string]int{}
	parents := map[string]bool{}
	removed := map[string]bool{}
	for i, command := range commands {
		row := command.Args
		if row[0] == "mkdir" && len(row) == 3 && row[1] == "-p" {
			parents[row[2]] = true
		}
		if row[0] == "rm" && len(row) == 2 {
			removed[row[1]] = true
		}
		if row[0] == "removeapp" {
			for _, app := range row[1:] {
				if app == "sys.appworld" || app == "sys.weather" || app == "sys.bbm" {
					return nil, fmt.Errorf("required application registration removed: %s", app)
				}
			}
		}
		if row[0] == "push" && len(row) == 3 {
			if row[1] == "patchdata/apps" && row[2] == "/apps" {
				appsPush = i
				for _, item := range app.Files {
					if item.Original != nil && !removed[appBase+item.Path] {
						return nil, fmt.Errorf("stock App World target would be skipped: %s", item.Path)
					}
				}
			}
			if row[1] == certificateSource {
				if cert.Copies[row[2]] != certificateSource || appsPush < 0 || !parents[path.Dir(row[2])] {
					return nil, fmt.Errorf("invalid shared certificate staging: %s", row[2])
				}
				copied[row[2]]++
			}
		}
		if (row[0] != "chmod" && row[0] != "chown") || len(row) != 3 {
			continue
		}
		target := row[2]
		item := expected[target]
		item.Path = target
		if row[0] == "chmod" {
			value, err := strconv.ParseUint(row[1], 8, 16)
			if err != nil || value > 07777 {
				return nil, fmt.Errorf("invalid script mode at line %d", command.Line)
			}
			mode := uint16(value)
			item.Mode = &mode
		} else {
			pair := strings.Split(row[1], ":")
			if len(pair) != 2 {
				return nil, fmt.Errorf("invalid script owner at line %d", command.Line)
			}
			uid, err := strconv.ParseUint(pair[0], 10, 32)
			if err != nil {
				return nil, err
			}
			gid, err := strconv.ParseUint(pair[1], 10, 32)
			if err != nil {
				return nil, err
			}
			u, g := uint32(uid), uint32(gid)
			item.UID, item.GID = &u, &g
		}
		expected[target] = item
	}
	if appsPush < 0 {
		return nil, fmt.Errorf("missing foundation application push")
	}
	for target := range cert.Copies {
		if copied[target] != 1 {
			return nil, fmt.Errorf("missing or duplicate certificate copy: %s", target)
		}
	}
	rows := make([]qnx6.Expected, 0, len(expected))
	for _, item := range expected {
		rows = append(rows, item)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
	return rows, nil
}

func validatePatcher(root string, log io.Writer) (patcherLock, []qnx6.Expected, error) {
	var lock patcherLock
	if err := packJSON(root, "neo.lock.json", &lock); err != nil {
		return lock, nil, err
	}
	if lock.SchemaVersion != 1 || lock.Patcher != "v4-neo" || len(lock.Files) == 0 || len(lock.Executables) != 6 || !lock.Private || lock.LoginKey {
		return lock, nil, fmt.Errorf("invalid v4-neo snapshot lock")
	}
	fmt.Fprintln(log, "Validate snapshot: pinned foundation, binaries and toolchain SHA256")
	for relative, digest := range lock.Files {
		p, err := packPath(root, relative)
		if err != nil {
			return lock, nil, err
		}
		actual, err := fileDigest(p, nil)
		if err != nil {
			return lock, nil, err
		}
		if actual != digest {
			return lock, nil, fmt.Errorf("snapshot SHA256 mismatch: %s", relative)
		}
	}
	for _, name := range lock.Executables {
		if lock.Files[name] == "" {
			return lock, nil, fmt.Errorf("unsealed executable: %s", name)
		}
	}
	files, err := packInventory(filepath.Join(root, "foundation"))
	if err != nil {
		return lock, nil, err
	}
	sealed := map[string]string{}
	for relative, digest := range lock.Files {
		if strings.HasPrefix(relative, "foundation/") {
			sealed[strings.TrimPrefix(relative, "foundation/")] = digest
		}
	}
	if !reflect.DeepEqual(files, sealed) {
		return lock, nil, fmt.Errorf("foundation inventory differs from snapshot")
	}
	if files[bootSource] != lock.BootHash || files[certificateSource] != lock.CertificateHash {
		return lock, nil, fmt.Errorf("foundation boot/certificate pin differs")
	}
	rows, err := foundationExpected(filepath.Join(root, "foundation"))
	if err != nil {
		return lock, nil, err
	}
	catalog, err := patchpkg.Load(filepath.Join(root, "packages"))
	if err != nil {
		return lock, nil, err
	}
	fmt.Fprintf(log, "Validated v4-neo %s: %d foundation entries, %d final paths, %d packages\n", lock.ToolVersion, len(files), len(rows), len(catalog.Packages))
	return lock, rows, nil
}

// The same writer serializes stage output and heartbeat output into console and
// log. There is no subprocess pipe or shell invocation in the build path.
type patcherProgress struct {
	context       context.Context
	mu            sync.Mutex
	writer        io.Writer
	started, last time.Time
}

func (p *patcherProgress) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = time.Now()
	prefix := fmt.Sprintf("[v4-neo +%.1fs] ", time.Since(p.started).Seconds())
	if _, err := io.WriteString(p.writer, prefix); err != nil {
		return 0, err
	}
	return p.writer.Write(b)
}
func (p *patcherProgress) heartbeat(done <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			p.mu.Lock()
			if time.Since(p.last) >= 5*time.Second {
				message := "Working; verification or I/O still in progress"
				if p.context.Err() != nil {
					message = "Interrupt requested; finishing the current operation before cleanup"
				}
				fmt.Fprintf(p.writer, "[v4-neo +%.1fs] %s\n", time.Since(p.started).Seconds(), message)
				p.last = time.Now()
			}
			p.mu.Unlock()
		}
	}
}

func buildPatcher(root, input, output, version string, console io.Writer) (err error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	interrupted := func() error {
		if ctx.Err() != nil {
			return apperror.New(130, "Build interrupted", "Private staging is removed; choose a new output and retry.")
		}
		return nil
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	input, err = filepath.Abs(input)
	if err != nil {
		return err
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	// Output existence is checked before any large input reads.
	if _, e := os.Lstat(output); e == nil {
		return apperror.New(apperror.OutputExists, "output already exists: "+output, "Choose a NEW subfolder, for example: "+filepath.Join(output, "v4-neo-z30"))
	} else if !os.IsNotExist(e) {
		return e
	}
	if err = withReader(input, func(r binio.Reader) error { _, e := autoloader.Read(r); return e }); err != nil {
		return apperror.New(apperror.Input, "Invalid firmware CAP: "+err.Error(), "Choose the original supported BB10 .exe autoloader.")
	}
	st, err := os.Stat(input)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	available, err := atomicfile.AvailableSpace(filepath.Dir(output))
	if err != nil {
		return err
	}
	needed := uint64(st.Size())*3 + (256 << 20)
	if available < needed {
		return apperror.New(apperror.Space, fmt.Sprintf("Insufficient output-volume space: need %.1f GiB, available %.1f GiB", float64(needed)/(1<<30), float64(available)/(1<<30)), "Free space or choose an output folder on another drive.")
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".v4-neo-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	logPath := filepath.Join(stage, "build.log")
	log, err := os.Create(logPath)
	if err != nil {
		return err
	}
	progress := &patcherProgress{context: ctx, writer: io.MultiWriter(console, log), started: time.Now(), last: time.Now()}
	done, stopped := make(chan struct{}), make(chan struct{})
	go progress.heartbeat(done, stopped)
	stop := func() {
		if done != nil {
			close(done)
			<-stopped
			done = nil
		}
	}
	defer func() {
		stop()
		if err != nil {
			apperror.Print(progress, err)
		}
		log.Close()
		if err != nil {
			failure := output + ".failed.log"
			if e := copyPackFile(logPath, failure); e == nil {
				fmt.Fprintln(console, "Failure log:", failure)
			}
		}
	}()
	fmt.Fprintln(progress, "Phase 1/6: checking pinned snapshot and foundation contracts")
	lock, expected, err := validatePatcher(root, progress)
	if err != nil {
		return err
	}
	if lock.ToolVersion != version {
		return apperror.New(apperror.Version, "Tool version differs from snapshot: "+version+" / "+lock.ToolVersion, "Run the executable supplied in this pack.")
	}
	fmt.Fprintln(progress, "Phase 2/6: hashing original firmware")
	inputHash, err := fileDigest(input, progress)
	if err != nil {
		return err
	}
	if err := interrupted(); err != nil {
		return err
	}
	result := filepath.Join(stage, "result")
	fmt.Fprintln(progress, "Phase 3/6: native patching and packing")
	if err = batch.Build(input, filepath.Join(root, "foundation", "patch.txt"), result, progress); err != nil {
		return err
	}
	if err := interrupted(); err != nil {
		return err
	}
	fmt.Fprintln(progress, "Phase 4/6: verifying final payloads, metadata, filesystem and container contents")
	images, err := filepath.Glob(filepath.Join(result, "*.ufs"))
	if err != nil {
		return err
	}
	if len(images) != 1 {
		return apperror.New(apperror.Verification, "Expected exactly one output filesystem", "")
	}
	err = withReader(images[0], func(r binio.Reader) error {
		image, e := qnx6.Open(r)
		if e != nil {
			return e
		}
		if e = image.VerifyPayloads(expected); e != nil {
			return e
		}
		check, e := image.Check()
		if e != nil {
			return e
		}
		if len(check.Errors) > 0 {
			return fmt.Errorf("final filesystem: %s", check.Errors[0])
		}
		return nil
	})
	if err != nil {
		return apperror.New(apperror.Verification, err.Error(), "Do not use failed artifacts; inspect the failure log.")
	}
	container, err := batch.VerifyBuild(input, result, progress)
	if err != nil {
		return apperror.New(apperror.Verification, err.Error(), "Do not use failed artifacts; inspect the failure log.")
	}
	fmt.Fprintln(progress, "Phase 5/6: rechecking input/snapshot and recording output SHA256")
	after, err := fileDigest(input, progress)
	if err != nil {
		return err
	}
	if after != inputHash {
		return fmt.Errorf("input changed during build")
	}
	afterLock, _, err := validatePatcher(root, progress)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(lock, afterLock) {
		return fmt.Errorf("snapshot lock changed during build")
	}
	payloads, metadata := 0, 0
	for _, item := range expected {
		if item.SHA256 != "" {
			payloads++
		}
		if item.Mode != nil || item.UID != nil || item.GID != nil {
			metadata++
		}
	}
	fmt.Fprintf(progress, "Verified %d payloads, %d metadata paths, filesystem and embedded UFS equality; handset acceptance not tested\n", payloads, metadata)
	fmt.Fprintln(progress, "Phase 6/6: hashing autoloaders, removing intermediates and publishing checked firmware")
	// Publish only the verified autoloaders. Loose partitions and reports stay
	// private and are removed before publication; failed builds keep their log.
	delivery := filepath.Join(stage, "delivery")
	if err = os.Mkdir(delivery, 0700); err != nil {
		return err
	}
	names := []string{container.OS}
	if container.Radio != "" {
		names = append(names, strings.TrimSuffix(container.OS, "_os.exe")+"_radio.exe")
	}
	for _, name := range names {
		source := filepath.Join(result, name)
		digest, e := fileDigest(source, progress)
		if e != nil {
			return e
		}
		fmt.Fprintf(progress, "SHA256 %s: %s\n", name, digest)
		if err = os.Rename(source, filepath.Join(delivery, name)); err != nil {
			return err
		}
	}
	if err = os.RemoveAll(result); err != nil {
		return fmt.Errorf("remove private build intermediates: %w", err)
	}
	if err := interrupted(); err != nil {
		return err
	}
	if err = atomicfile.PublishDirectory(delivery, output); err != nil {
		return err
	}
	fmt.Fprintf(console, "v4-neo build complete in %.1fs: %s\n", time.Since(progress.started).Seconds(), output)
	return nil
}

func copyPackFile(source, target string) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("regular source file required: %s", source)
	}
	return atomicfile.Write(target, func(out *os.File) error { _, err := binio.BulkCopyN(out, f, st.Size()); return err })
}
