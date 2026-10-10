package cli

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bb10root/bb10mt/internal/apperror"
	"github.com/bb10root/bb10mt/internal/autoloader"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qcfm"
	"github.com/bb10root/bb10mt/internal/qnx6"
)

func patcherFixture(t *testing.T) (string, patcherLock) {
	t.Helper()
	root := t.TempDir()
	foundation := filepath.Join(root, "foundation")
	put := func(relative string, data []byte) string {
		p := filepath.Join(foundation, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:])
	}
	write := func(relative string, value any) {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		put(relative, data)
	}
	bootHash := put(bootSource, []byte("maintained boot fixture\n"))
	appPath := "native/download"
	appBase := "apps/sys.appworld.fixture/"
	appHash := put("patchdata/"+appBase+appPath, []byte("app fixture"))
	write("patched_apps/sys.appworld.manifest.json", map[string]any{"packageName": "sys.appworld", "packageId": "fixture", "files": []any{map[string]any{"path": appPath, "sha256": appHash}}})
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certHash := put(certificateSource, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	copies := map[string]string{"/" + appBase + "native/assets/certs/isrgrootx1.pem": certificateSource, "/var/certmgr/common/user_trusted/isrgrootx1.pem": certificateSource, "/var/newcert/cert_E0AB059420725493056062023670F7CD2EFC6666.pem": certificateSource}
	write("certs/manifest.json", map[string]any{"files": map[string]string{certificateSource: certHash}, "copies": copies})
	services := map[string]string{"patchdata/var/service": put("patchdata/var/service", []byte("service fixture"))}
	for _, name := range []string{"bbid.manifest.json", "bbid-autostart.json", "bbm.manifest.json", "ukrainian.manifest.json"} {
		files := services
		if name == "bbid-autostart.json" {
			files = map[string]string{bootSource: bootHash}
		}
		write("patched_services/"+name, map[string]any{"files": files, "bootHookSha256": bootHash, "automaticEnrollment": true})
	}
	weatherFiles := map[string]string{}
	for _, relative := range []string{"patchdata/apps/sys.weather.fixture/native/lib/libweatherlib.so", "patchdata/apps/sys.weather.fixture/native/lib/libweatherlib.so.1", "patchdata/var/weather-libs/libgeoweather.so", "patchdata/var/weather-libs/libgeoweather.so.1", "patchdata/var/pps/services/carrier_config/lib/geoweather/weatherdata/metars"} {
		weatherFiles[relative] = put(relative, []byte("weather fixture "+relative))
	}
	write("patched_services/weather.manifest.json", map[string]any{"files": weatherFiles, "contractVersion": "2026-test", "certificateSHA256": certHash})
	script := "mkdir -p /apps\nmkdir -p /var\npush patchdata/apps /apps\npush patchdata/var /var\n"
	for target := range copies {
		script += "mkdir -p " + filepath.ToSlash(filepath.Dir(target)) + "\npush " + certificateSource + " " + target + "\n"
	}
	script += "chmod 777 /var/service\nchmod 640 /var/service\nchown 0:427 /var/service\n"
	put("patch.txt", []byte(script))
	if err := exportWeather(foundation, filepath.Join(root, "packages")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"} {
		p := filepath.Join(root, "bin", target, "bb10mt")
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(target), 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := packInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	executables := map[string]string{}
	for p := range files {
		if strings.HasPrefix(p, "packages/") {
			delete(files, p)
		}
		if strings.HasPrefix(p, "bin/") {
			executables[strings.Split(p, "/")[1]] = p
		}
	}
	lock := patcherLock{SchemaVersion: 1, Patcher: "v4-neo", ToolVersion: "v0.7.0-go.999", SourceCommit: "fixture", BootHash: bootHash, CertificateHash: certHash, Files: files, Executables: executables, Private: true}
	if err := writePackJSON(filepath.Join(root, "neo.lock.json"), lock); err != nil {
		t.Fatal(err)
	}
	return root, lock
}

func patcherInput(t *testing.T, dir string) string {
	t.Helper()
	image := filepath.Join(dir, "input.ufs")
	if err := qnx6.Mkfs(image, 1024, 128, 4096); err != nil {
		t.Fatal(err)
	}
	packed := filepath.Join(dir, "input.signed")
	if err := qcfm.Pack(packed, []qcfm.Input{{Path: image}}, qcfm.Options{Version: 2, Sign: true}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1024)
	copy(b, "MZ")
	binio.Put32(b, 60, 128)
	copy(b[128:], "PE\x00\x00")
	binio.LE.PutUint16(b[132:], 0x14c)
	binio.LE.PutUint16(b[134:], 1)
	binio.LE.PutUint16(b[148:], 224)
	binio.LE.PutUint16(b[152:], 0x10b)
	binio.Put32(b, 212, 512)
	binio.Put32(b, 244, 16)
	copy(b[376:], ".text")
	binio.Put32(b, 392, 512)
	binio.Put32(b, 396, 512)
	stub := filepath.Join(dir, "cap.exe")
	if err := os.WriteFile(stub, b, 0600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "firmware.exe")
	if err := autoloader.Create(input, stub, []string{packed}, 2); err != nil {
		t.Fatal(err)
	}
	return input
}

func TestPatcherNativeBuild(t *testing.T) {
	root, lock := patcherFixture(t)
	dir := t.TempDir()
	input := patcherInput(t, dir)
	output := filepath.Join(dir, "new output")
	before, err := fileDigest(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	var progress bytes.Buffer
	if err := buildPatcher(root, input, output, lock.ToolVersion, &progress); err != nil {
		t.Fatal(err, progress.String())
	}
	after, err := fileDigest(input, nil)
	if err != nil || before != after {
		t.Fatal("input changed", err)
	}
	for _, name := range []string{"neo-acceptance.json", "container-verification.json", "snapshot-used.json", "neo-build.log", "SHA256SUMS"} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Fatal(err)
		}
	}
	var report map[string]any
	if err := packJSON(output, "container-verification.json", &report); err != nil || report["embeddedUFSMatchesImage"] != true {
		t.Fatal(report, err)
	}
	if !strings.Contains(progress.String(), "Phase 6/6") || !strings.Contains(progress.String(), "Stage 8/8") {
		t.Fatal(progress.String())
	}
	sums, err := os.ReadFile(filepath.Join(output, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		digest, name, _ := strings.Cut(line, "  ")
		actual, err := fileDigest(filepath.Join(output, name), nil)
		if err != nil || actual != digest {
			t.Fatal(name, err)
		}
	}
	if err := buildPatcher(root, input, output, lock.ToolVersion, io.Discard); apperror.Classify(err).Code != 4 {
		t.Fatal(err)
	}
}

func TestPatcherRejectsMutationAndInvalidInputs(t *testing.T) {
	for _, kind := range []string{"payload", "extra foundation", "boot pin", "certificate pin", "version", "invalid CAP", "failure log"} {
		t.Run(kind, func(t *testing.T) {
			root, lock := patcherFixture(t)
			dir := t.TempDir()
			input := patcherInput(t, dir)
			output := filepath.Join(dir, "output")
			expectedCode := 5
			switch kind {
			case "payload":
				os.WriteFile(filepath.Join(root, "foundation/patchdata/var/service"), []byte("changed"), 0600)
			case "extra foundation":
				os.WriteFile(filepath.Join(root, "foundation/extra"), []byte("unsealed"), 0600)
			case "boot pin":
				lock.BootHash = strings.Repeat("0", 64)
			case "certificate pin":
				lock.CertificateHash = strings.Repeat("0", 64)
			case "version":
				lock.ToolVersion = "v0.7.0-go.998"
				expectedCode = 10
			case "invalid CAP":
				os.WriteFile(input, []byte("not a CAP"), 0600)
				expectedCode = 3
			case "failure log":
				expectedCode = 3
				script := filepath.Join(root, "foundation/patch.txt")
				data, _ := os.ReadFile(script)
				data = append(data, []byte("push missing /var/missing\n")...)
				os.WriteFile(script, data, 0600)
				digest, _ := fileDigest(script, nil)
				lock.Files["foundation/patch.txt"] = digest
				os.WriteFile(output+".failed.log", []byte("previous failure"), 0600)
			}
			os.Remove(filepath.Join(root, "neo.lock.json"))
			if err := writePackJSON(filepath.Join(root, "neo.lock.json"), lock); err != nil {
				t.Fatal(err)
			}
			err := buildPatcher(root, input, output, "v0.7.0-go.999", io.Discard)
			if err == nil || apperror.Classify(err).Code != expectedCode {
				t.Fatal(err, apperror.Classify(err))
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("partial output published")
			}
			if kind == "failure log" {
				data, err := os.ReadFile(output + ".failed.log")
				if err != nil || string(data) != "previous failure" {
					t.Fatal(string(data), err)
				}
			}
			entries, _ := filepath.Glob(filepath.Join(dir, ".v4-neo-*"))
			if len(entries) != 0 {
				t.Fatal("staging leaked", entries)
			}
		})
	}
	for _, args := range [][]string{{"patcher"}, {"patcher", "build"}, {"patcher", "validate", "--oops"}} {
		_, err := invoke(args...)
		if apperror.Classify(err).Code != 2 {
			t.Fatal(args, err)
		}
	}
}

func TestPatcherPathConfinement(t *testing.T) {
	root, _ := patcherFixture(t)
	for _, relative := range []string{"../outside", "a/../outside", "/absolute", "C:/absolute", "a\\file", "foundation"} {
		if _, err := packPath(root, relative); err == nil {
			t.Fatal(relative)
		}
	}
	if err := os.Symlink(filepath.Join(root, "foundation"), filepath.Join(root, "linked")); err == nil {
		if _, err := packPath(root, "linked/patch.txt"); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestPatcherNativeAssembly(t *testing.T) {
	root, lock := patcherFixture(t)
	release := t.TempDir()
	source := t.TempDir()
	output := filepath.Join(t.TempDir(), "assembled")
	write := func(name string, data []byte) {
		p := filepath.Join(source, name)
		os.MkdirAll(filepath.Dir(p), 0700)
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"README.md", "DESIGN.md", ".github/workflows/validate.yml"} {
		write("patchers/v4-neo/"+name, []byte("template"))
	}
	for _, name := range []string{"PACKAGES.md", "ERROR_CODES.md", "PERFORMANCE.md", "PERFORMANCE_VALIDATION.json"} {
		write("docs/"+name, []byte("documentation"))
	}
	for _, target := range []string{"windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"} {
		suffix := ""
		if strings.HasPrefix(target, "windows") {
			suffix = ".exe"
		}
		os.WriteFile(filepath.Join(release, "bb10mt-"+lock.ToolVersion+"-"+target+suffix), []byte(target), 0600)
	}
	for _, name := range []string{"DEPENDENCIES.md", "runtime.lock.json", "runtime-sources.zip", "build-version.json"} {
		os.WriteFile(filepath.Join(release, name), []byte("metadata"), 0600)
	}
	writePackJSON(filepath.Join(release, "sbom.cdx.json"), map[string]any{"metadata": map[string]any{"component": map[string]any{"version": lock.ToolVersion}}})
	archive, err := os.Create(filepath.Join(release, "bb10mt-"+lock.ToolVersion+"-windows-amd64.zip"))
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(archive)
	f, err := z.Create("LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("license"))
	z.Close()
	archive.Close()
	inventory, err := packInventory(release)
	if err != nil {
		t.Fatal(err)
	}
	var sums strings.Builder
	for name, digest := range inventory {
		sums.WriteString(digest + "  " + name + "\n")
	}
	os.WriteFile(filepath.Join(release, "SHA256SUMS"), []byte(sums.String()), 0600)
	if err := assemblePatcher(filepath.Join(root, "foundation"), release, source, "test revision", output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validatePatcher(output, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"build.py", "build.ps1", "foundation/scripts", "foundation/tests"} {
		if _, err := os.Stat(filepath.Join(output, name)); !os.IsNotExist(err) {
			t.Fatal("host wrapper shipped", name)
		}
	}
	if err := assemblePatcher(filepath.Join(root, "foundation"), release, source, "test revision", output, io.Discard); apperror.Classify(err).Code != 4 {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(release, "DEPENDENCIES.md"), []byte("tampered"), 0600)
	if err := assemblePatcher(filepath.Join(root, "foundation"), release, source, "test revision", output+"-bad", io.Discard); err == nil || !strings.Contains(err.Error(), "SHA256 mismatch") {
		t.Fatal(err)
	}
}
