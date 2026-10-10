package patchpkg

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bb10root/bb10mt/internal/autoloader"
	"github.com/bb10root/bb10mt/internal/batch"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qcfm"
	"github.com/bb10root/bb10mt/internal/qnx6"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func writeJSON(t *testing.T, p string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	must(t, err)
	must(t, os.WriteFile(p, b, 0600))
}

type fixture struct {
	root, input, catalog, profile string
	manifests                     map[string]Manifest
}

func (f fixture) save(t *testing.T) {
	t.Helper()
	for id, m := range f.manifests {
		writeJSON(t, filepath.Join(f.catalog, id, "manifest.json"), m)
	}
}
func setup(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	catalog := filepath.Join(root, "catalog")
	must(t, os.Mkdir(catalog, 0700))
	f := fixture{root: root, catalog: catalog, input: filepath.Join(root, "source.ufs"), profile: filepath.Join(root, "profile.json"), manifests: map[string]Manifest{}}
	must(t, qnx6.Mkfs(f.input, 1024, 128, 4096))
	boot := []byte("vanilla boot foundation and public TLS pin\n")
	stock := []byte("original weather library")
	must(t, os.WriteFile(filepath.Join(root, "boot"), boot, 0600))
	must(t, os.WriteFile(filepath.Join(root, "stock"), stock, 0600))
	script := "mkdir -p /apps/sys.weather.opaque/native/lib\nmkdir -p /apps/sys.appworld.opaque/native/assets\nmkdir -p /apps/sys.android.opaque/native/system/xbin\npush boot /apps/sys.android.opaque/native/system/xbin/btool\npush stock /apps/sys.weather.opaque/native/lib/libweatherlib.so\n"
	must(t, os.WriteFile(filepath.Join(root, "seed.txt"), []byte(script), 0600))
	seed := filepath.Join(root, "seed.ufs")
	must(t, qnx6.Script(f.input, filepath.Join(root, "seed.txt"), seed, io.Discard))
	must(t, os.Remove(f.input))
	must(t, os.Rename(seed, f.input))
	f.manifests["foundation"] = Manifest{SchemaVersion: 1, ID: "foundation", Version: "1", Kind: "foundation", Provides: []string{"boot.weather/v1"}, Assertions: []Assertion{{Path: "app:/sys.android/native/system/xbin/btool", SHA256: hashBytes(boot)}}}
	trust := Manifest{SchemaVersion: 1, ID: "trust", Version: "1", Kind: "shared"}
	weather := Manifest{SchemaVersion: 1, ID: "weather", Version: "1", Kind: "app", App: "sys.weather", Requires: []Requirement{{"foundation", "1"}, {"trust", "1"}}, RequiresCapabilities: []string{"boot.weather/v1"}}
	for id, m := range map[string]Manifest{"foundation": f.manifests["foundation"], "trust": trust, "weather": weather} {
		must(t, os.Mkdir(filepath.Join(catalog, id), 0700))
		f.manifests[id] = m
	}
	add := func(id, p, source string, data []byte, mode string, uid, gid uint32, original []string) {
		m := f.manifests[id]
		m.Owns = append(m.Owns, p)
		m.Operations = append(m.Operations, Operation{Type: "put-file", Path: p, Source: source, SHA256: hashBytes(data), Mode: mode, UID: uid, GID: gid, AllowAbsent: true, OriginalSHA256: original})
		f.manifests[id] = m
		must(t, os.WriteFile(filepath.Join(catalog, id, source), data, 0600))
	}
	for _, p := range []string{"app:/sys.appworld/native/assets/root.pem", "/var/certmgr/common/user_trusted/root.pem", "/var/newcert/root.pem"} {
		add("trust", p, "root.pem", []byte("public test certificate"), "0644", 0, 0, nil)
	}
	for _, name := range []string{"libweatherlib.so", "libweatherlib.so.1"} {
		add("weather", "app:/sys.weather/native/lib/"+name, name, []byte("patched weather library"), "0755", 0, 0, []string{hashBytes(stock)})
	}
	for _, name := range []string{"libgeoweather.so", "libgeoweather.so.1"} {
		add("weather", "/var/weather-libs/"+name, name, []byte("patched geoweather library"), "0755", 0, 0, nil)
	}
	add("weather", "/var/pps/services/carrier_config/lib/geoweather/weatherdata/metars", "metars", []byte("@metars\nservice_enabled:b:true\n"), "0640", 379, 379, nil)
	f.save(t)
	writeJSON(t, f.profile, Profile{1, []Requirement{{"foundation", "1"}, {"weather", "1"}}})
	return f
}
func makePlan(t *testing.T, f fixture) (Plan, string) {
	t.Helper()
	p, err := NewPlan(f.input, f.catalog, f.profile)
	must(t, err)
	filename := filepath.Join(f.root, "plan.json")
	must(t, WritePlan(filename, p))
	return p, filename
}
func checkOutput(t *testing.T, image string, plan Plan) {
	t.Helper()
	must(t, openImage(image, func(im *qnx6.Image, _ string) error {
		if err := im.VerifyPayloads(expectedRows(plan)); err != nil {
			return err
		}
		c, err := im.Check()
		if len(c.Errors) > 0 {
			t.Fatal(c.Errors)
		}
		return err
	}))
}

func TestBuildParityAndIdempotence(t *testing.T) {
	f := setup(t)
	plan, lock := makePlan(t, f)
	if len(plan.Packages) != 3 || len(plan.Actions) != 9 {
		t.Fatal(plan)
	}
	second, err := NewPlan(f.input, f.catalog, f.profile)
	must(t, err)
	a, _ := json.Marshal(plan)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatal("nondeterministic lock")
	}
	before, _, err := fileHash(f.input)
	must(t, err)
	output := filepath.Join(f.root, "built")
	must(t, Build(lock, output, io.Discard))
	image := filepath.Join(output, "firmware.ufs")
	checkOutput(t, image, plan)
	after, _, err := fileHash(f.input)
	must(t, err)
	if before != after {
		t.Fatal("input changed")
	}
	// Independent legacy script uses the same declared files and metadata.
	var legacy strings.Builder
	for _, action := range plan.Actions {
		if action.Operation == nil {
			continue
		}
		op := action.Operation
		if !action.Before.Absent {
			legacy.WriteString("rm " + action.Path + "\n")
		}
		source, err := quoteScript(filepath.Join(f.catalog, action.Package, op.Source))
		must(t, err)
		legacy.WriteString("mkdir -p " + path.Dir(action.Path) + "\npush " + source + " " + action.Path + "\nchmod " + op.Mode + " " + action.Path + "\nchown " + strconvOwner(op.UID, op.GID) + " " + action.Path + "\n")
	}
	script := filepath.Join(f.root, "legacy.txt")
	must(t, os.WriteFile(script, []byte(legacy.String()), 0600))
	legacyImage := filepath.Join(f.root, "legacy.ufs")
	must(t, qnx6.Script(f.input, script, legacyImage, io.Discard))
	checkOutput(t, legacyImage, plan)
	p, err := NewPlan(image, f.catalog, f.profile)
	must(t, err)
	next := filepath.Join(f.root, "next.json")
	must(t, WritePlan(next, p))
	repeated := filepath.Join(f.root, "repeated")
	must(t, Build(next, repeated, io.Discard))
	checkOutput(t, filepath.Join(repeated, "firmware.ufs"), p)
	var report BuildReport
	_, err = readJSON(filepath.Join(repeated, "package-report.json"), &report)
	must(t, err)
	if report.Files != 8 || report.AlreadyPresent != 8 {
		t.Fatal(report)
	}
}
func strconvOwner(uid, gid uint32) string {
	b, _ := json.Marshal([]uint32{uid, gid})
	return strings.ReplaceAll(strings.Trim(string(b), "[]"), ",", ":")
}

func TestBuildRejectsChangedLockSources(t *testing.T) {
	for _, test := range []string{"payload", "manifest", "input", "action", "package-directory", "extra-action"} {
		t.Run(test, func(t *testing.T) {
			f := setup(t)
			plan, lock := makePlan(t, f)
			switch test {
			case "payload":
				must(t, os.WriteFile(filepath.Join(f.catalog, "weather", "metars"), []byte("changed"), 0600))
			case "manifest":
				m := f.manifests["weather"]
				m.Operations[0].Mode = "0600"
				f.manifests["weather"] = m
				f.save(t)
			case "input":
				file, err := os.OpenFile(f.input, os.O_APPEND|os.O_WRONLY, 0)
				must(t, err)
				_, err = file.Write([]byte("changed"))
				must(t, err)
				must(t, file.Close())
			case "action":
				plan.Actions[len(plan.Actions)-1].Path = "/var/other"
				writeJSON(t, lock, plan)
			case "package-directory":
				plan.Packages[0].Directory = "../../outside"
				writeJSON(t, lock, plan)
			case "extra-action":
				plan.Actions = append(plan.Actions, plan.Actions[0])
				writeJSON(t, lock, plan)
			}
			output := filepath.Join(f.root, "out")
			if err := Build(lock, output, io.Discard); err == nil {
				t.Fatal("accepted changed lock sources")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("published failed transaction")
			}
		})
	}
}

type failingLog struct{}

func (failingLog) Write([]byte) (int, error) { return 0, errors.New("forced logging failure") }
func TestBuildFailureAndExistingOutput(t *testing.T) {
	f := setup(t)
	_, lock := makePlan(t, f)
	output := filepath.Join(f.root, "out")
	before, _, err := fileHash(f.input)
	must(t, err)
	if err = Build(lock, output, failingLog{}); err == nil {
		t.Fatal("ignored transaction failure")
	}
	if _, err = os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("partial output")
	}
	after, _, err := fileHash(f.input)
	must(t, err)
	if before != after {
		t.Fatal("input changed on failure")
	}
	stages, err := filepath.Glob(filepath.Join(f.root, ".bb10mt-packages-*"))
	must(t, err)
	if len(stages) != 0 {
		t.Fatal("working files leaked", stages)
	}
	must(t, os.Mkdir(output, 0700))
	sentinel := filepath.Join(output, "sentinel")
	must(t, os.WriteFile(sentinel, []byte("keep"), 0600))
	if err = Build(lock, output, io.Discard); err == nil {
		t.Fatal("replaced existing output")
	}
	data, err := os.ReadFile(sentinel)
	must(t, err)
	if string(data) != "keep" {
		t.Fatal("existing output changed")
	}
}
func TestIncompatiblePlan(t *testing.T) {
	for _, test := range []string{"unknown-original", "missing-foundation", "missing-capability", "ambiguous-app", "ownership", "ancestor-ownership", "assertion-write"} {
		t.Run(test, func(t *testing.T) {
			f := setup(t)
			m := f.manifests["weather"]
			switch test {
			case "unknown-original":
				m.Operations[0].OriginalSHA256 = []string{hashBytes([]byte("wrong"))}
			case "missing-foundation":
				writeJSON(t, f.profile, Profile{1, []Requirement{{"weather", "1"}}})
			case "missing-capability":
				m.RequiresCapabilities = []string{"missing/v1"}
			case "ambiguous-app":
				script := filepath.Join(f.root, "ambiguous.txt")
				must(t, os.WriteFile(script, []byte("mkdir -p /apps/sys.weather.other/native/lib\n"), 0600))
				image := filepath.Join(f.root, "ambiguous.ufs")
				must(t, qnx6.Script(f.input, script, image, io.Discard))
				f.input = image
			case "ownership":
				m.Owns = append(m.Owns, "/var/newcert/root.pem")
				op := m.Operations[0]
				op.Path = "/var/newcert/root.pem"
				m.Operations = append(m.Operations, op)
			case "ancestor-ownership":
				m.Owns[2] = "/var/newcert/root.pem/child"
				m.Operations[2].Path = m.Owns[2]
			case "assertion-write":
				m.Assertions = []Assertion{{Path: m.Operations[0].Path, SHA256: hashBytes([]byte("original weather library"))}}
			}
			f.manifests["weather"] = m
			f.save(t)
			if _, err := NewPlan(f.input, f.catalog, f.profile); err == nil {
				t.Fatal("accepted incompatible plan")
			}
		})
	}
}
func TestCatalogRejectsUnsafeContracts(t *testing.T) {
	for _, test := range []string{"cycle", "exact-version", "foundation-write", "foreign-app", "android-write", "root-write", "traversal", "source-traversal", "setuid", "conflict", "duplicate-owner", "unowned", "bad-hash"} {
		t.Run(test, func(t *testing.T) {
			f := setup(t)
			m := f.manifests["weather"]
			switch test {
			case "cycle":
				m.Requires = append(m.Requires, Requirement{"weather", "1"})
			case "exact-version":
				m.Requires[0].Version = "missing"
			case "foundation-write":
				m.Kind = "foundation"
			case "foreign-app":
				m.Owns[0] = "app:/sys.appworld/native/foreign"
				m.Operations[0].Path = m.Owns[0]
			case "android-write":
				m.Owns[0] = "app:/sys.android/native/system/xbin/btool"
				m.Operations[0].Path = m.Owns[0]
			case "root-write":
				m.Owns[0] = "/etc/ssh/sshd_config"
				m.Operations[0].Path = m.Owns[0]
			case "traversal":
				m.Owns[0] = "/var/../etc/file"
				m.Operations[0].Path = m.Owns[0]
			case "source-traversal":
				m.Operations[0].Source = "../weather/metars"
			case "setuid":
				m.Operations[0].Mode = "4755"
			case "conflict":
				m.Conflicts = []string{"trust"}
			case "duplicate-owner":
				m.Owns = append(m.Owns, m.Owns[0])
			case "unowned":
				m.Owns = m.Owns[1:]
			case "bad-hash":
				m.Operations[0].SHA256 = "bad"
			}
			f.manifests["weather"] = m
			f.save(t)
			if _, err := Load(f.catalog); err == nil {
				t.Fatal("accepted unsafe contract")
			}
		})
	}
}
func TestStrictJSONAndSymlink(t *testing.T) {
	for _, data := range []string{`{"schemaVersion":1,"schemaVersion":2}`, `{"schemaVersion":1,"unknown":true}`, `{} {}`} {
		var m Manifest
		if err := decode([]byte(data), &m); err == nil {
			t.Fatal("accepted ambiguous JSON", data)
		}
	}
	f := setup(t)
	p := filepath.Join(f.catalog, "weather", "metars")
	must(t, os.Remove(p))
	if err := os.Symlink(filepath.Join(f.catalog, "trust", "root.pem"), p); err != nil {
		t.Skip("symlinks unavailable", err)
	}
	if _, err := Load(f.catalog); err == nil {
		t.Fatal("accepted symlink payload")
	}
}

func TestAppIdentityDisambiguatesLongerNames(t *testing.T) {
	f := setup(t)
	// sys.weather.extra is a different package, despite sharing a prefix.
	manifest := "Package-Name: sys.weather.extra\nPackage-Id: opaque\n\n"
	must(t, os.WriteFile(filepath.Join(f.root, "extra.MF"), []byte(manifest), 0600))
	script := filepath.Join(f.root, "extra.txt")
	must(t, os.WriteFile(script, []byte("mkdir -p /apps/sys.weather.extra.opaque/META-INF\npush extra.MF /apps/sys.weather.extra.opaque/META-INF/MANIFEST.MF\n"), 0600))
	image := filepath.Join(f.root, "extra.ufs")
	must(t, qnx6.Script(f.input, script, image, io.Discard))
	f.input = image
	if _, err := NewPlan(f.input, f.catalog, f.profile); err != nil {
		t.Fatal(err)
	}
}

func TestNoSpacePublishesNothing(t *testing.T) {
	f := setup(t)
	must(t, os.WriteFile(filepath.Join(f.root, "filler"), bytes.Repeat([]byte{0x61}, 2<<20), 0600))
	script := filepath.Join(f.root, "fill.txt")
	must(t, os.WriteFile(script, []byte("mkdir -p /var\npush filler /var/filler\n"), 0600))
	filled := filepath.Join(f.root, "filled.ufs")
	must(t, qnx6.Script(f.input, script, filled, io.Discard))
	f.input = filled
	m := f.manifests["weather"]
	data := bytes.Repeat([]byte{0x73}, 3<<20)
	m.Operations[4].SHA256 = hashBytes(data)
	f.manifests["weather"] = m
	f.save(t)
	must(t, os.WriteFile(filepath.Join(f.catalog, "weather", "metars"), data, 0600))
	_, lock := makePlan(t, f)
	output := filepath.Join(f.root, "out")
	if err := Build(lock, output, io.Discard); err == nil || !strings.Contains(err.Error(), "no free") {
		t.Fatal("expected allocation failure", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("published partial filesystem")
	}
}

func TestRelativeOutputAndSpaces(t *testing.T) {
	f := setup(t)
	plan, lock := makePlan(t, f)
	t.Chdir(f.root)
	must(t, os.Mkdir("output with space", 0700))
	output := filepath.Join("output with space", "result")
	must(t, Build(lock, output, io.Discard))
	checkOutput(t, filepath.Join(output, "firmware.ufs"), plan)
}

func capStub() []byte {
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
	return b
}
func TestCAPPackageTransaction(t *testing.T) {
	f := setup(t)
	bundle := filepath.Join(f.root, "os.signed")
	must(t, qcfm.Pack(bundle, []qcfm.Input{{Path: f.input}}, qcfm.Options{Version: 2, Sign: true}))
	radio := filepath.Join(f.root, "test.radio.rcfs")
	must(t, os.WriteFile(radio, []byte("unchanged radio"), 0600))
	radioBundle := filepath.Join(f.root, "radio.signed")
	must(t, qcfm.Pack(radioBundle, []qcfm.Input{{Path: radio}}, qcfm.Options{Version: 2, Sign: true}))
	stub := filepath.Join(f.root, "cap.exe")
	must(t, os.WriteFile(stub, capStub(), 0600))
	f.input = filepath.Join(f.root, "firmware.exe")
	must(t, autoloader.Create(f.input, stub, []string{bundle, radioBundle}, 2))
	plan, lock := makePlan(t, f)
	if plan.Input.Format != "cap" {
		t.Fatal(plan.Input)
	}
	output := filepath.Join(f.root, "out")
	must(t, Build(lock, output, io.Discard))
	var containerReport batch.Report
	_, err := readJSON(filepath.Join(output, "build-report.json"), &containerReport)
	must(t, err)
	if containerReport.Input != f.input {
		t.Fatal("report refers to a temporary input", containerReport.Input)
	}
	checkOutput(t, filepath.Join(output, "firmware_os.exe"), plan)
	// The signed radio container is copied byte-for-byte, not reconstructed.
	a, _, err := fileHash(radioBundle)
	must(t, err)
	b, _, err := fileHash(filepath.Join(output, "firmware.radio.signed"))
	must(t, err)
	if a != b {
		t.Fatal("radio changed")
	}
	for _, name := range []string{"firmware_os.exe", "firmware_radio.exe"} {
		file, err := os.Open(filepath.Join(output, name))
		must(t, err)
		st, err := file.Stat()
		must(t, err)
		_, err = autoloader.Read(binio.Reader{ReaderAt: file, Size: st.Size()})
		file.Close()
		must(t, err)
	}
}
func FuzzManifest(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":1,"id":"test","version":"1","kind":"shared"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var m Manifest
		if decode(b, &m) == nil {
			_ = validateManifest(m)
		}
	})
}
