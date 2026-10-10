package bar

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qnx6"
)

func installFixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	if e := Template(dir, "test"); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(dir, "sys.data.test")
	os.Mkdir(filepath.Join(root, "native"), 0755)
	os.WriteFile(filepath.Join(root, "native", "app"), []byte("\x7fELF native executable"), 0644)
	os.WriteFile(filepath.Join(root, "native", "service"), []byte("#!/bin/sh\nservice\n"), 0644)
	if e := Update(root); e != nil {
		t.Fatal(e)
	}
	manifest, _, m, e := manifestFile(root)
	if e != nil {
		t.Fatal(e)
	}
	pkg, e := packageSection(m)
	if e != nil {
		t.Fatal(e)
	}
	pkg.Set("Display-Name", "Test app")
	pkg.Set("Entry-Point", "app/native/app")
	for i := range m {
		if m[i].Get("Package-Name") == pkg.Get("Package-Name") {
			m[i] = pkg
		}
	}
	m = append(m, Section{{"Entry-Point-Key", "service"}, {"Entry-Point", "app/native/service [timeout=15 path=/a:/b]"}})
	os.WriteFile(manifest, m.Bytes(), 0644)
	dname := pkg.Get("Package-Name") + "." + pkg.Get("Package-Id")
	image := filepath.Join(dir, "source.ufs")
	if e = qnx6.Mkfs(image, 4096, 256, 4096); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(image, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	ed, e := qnx6.NewEditor(f)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"/apps/other", "/var/etc/id", "/accounts/1000/_startup_data/appdata/other/data", "/var/pps/system/installer/appdetails"} {
		if e = ed.Mkdir(p, true); e != nil {
			t.Fatal(e)
		}
	}
	if e = ed.SetAttributes("/apps/other", 0755, 89, 10000); e != nil {
		t.Fatal(e)
	}
	if e = ed.SetAttributes("/accounts/1000/_startup_data/appdata/other/data", 0700, 1000, 10000); e != nil {
		t.Fatal(e)
	}
	for p, s := range map[string]string{"/var/etc/id/10000": "reserved", "/var/pps/system/installer/appdetails/applications.000": "@applications\n" + dname + ":json:old\n" + dname + "EXTRA:json:keep\n", "/var/pps/system/installer/appdetails/applications.001": "@applications\n" + dname + ":json:duplicate\n"} {
		if e = ed.WriteFile(p, strings.NewReader(s), uint64(len(s)), true); e != nil {
			t.Fatal(e)
		}
	}
	if e = ed.Commit(); e != nil {
		t.Fatal(e)
	}
	f.Close()
	return root, image, dir, dname
}
func image(t *testing.T, p string) *qnx6.Image {
	t.Helper()
	f, e := os.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	st, _ := f.Stat()
	im, e := qnx6.Open(binio.Reader{ReaderAt: f, Size: st.Size()})
	if e != nil {
		t.Fatal(e)
	}
	return im
}
func TestInstallImageRegistrationPermissionsAndDataIsolation(t *testing.T) {
	root, source, dir, dname := installFixture(t)
	before, _ := os.ReadFile(source)
	out := filepath.Join(dir, "out.ufs")
	report, e := InstallImage(root, source, out, InstallOptions{})
	if e != nil || report.GID != 10001 || report.Package != dname {
		t.Fatal(report, e)
	}
	after, _ := os.ReadFile(source)
	if !bytes.Equal(before, after) {
		t.Fatal("source modified")
	}
	im := image(t, out)
	for _, tc := range []struct {
		p        string
		mode     uint16
		uid, gid uint32
	}{{"/apps/" + dname + "/native/app", 0755, 89, 10001}, {"/apps/" + dname + "/META-INF/MANIFEST.MF", 0644, 89, 10001}, {"/accounts/1000/_startup_data/appdata/other/data", 0700, 1000, 10000}, {"/accounts/1000/_startup_data/appdata/" + dname + "/data", 0755, 1000, 10001}} {
		n, _, e := im.Resolve(tc.p)
		if e != nil || n.Mode()&07777 != tc.mode || n.UID() != tc.uid || n.GID() != tc.gid {
			t.Fatal(tc, n, e)
		}
	}
	link, _, e := im.Resolve("/apps/gid2app/10001")
	if e != nil || link.Mode()&0xf000 != 0xa000 {
		t.Fatal(e)
	}
	var target bytes.Buffer
	if e = im.Data(link, &target); e != nil || target.String() != "/apps/"+dname {
		t.Fatal(target.String(), e)
	}
	var registrations string
	for _, name := range []string{"applications.000", "applications.001"} {
		data, e := im.ReadFile("/var/pps/system/installer/appdetails/"+name, 1<<20)
		if e != nil {
			t.Fatal(e)
		}
		registrations += string(data)
	}
	if strings.Count(registrations, dname+":json:") != 1 || !strings.Contains(registrations, dname+"EXTRA:json:keep") {
		t.Fatal(registrations)
	}
	services, e := im.ReadFile("/var/pps/system/bslauncher", 1<<20)
	if e != nil || !strings.Contains(string(services), dname+"..service..json:") || !strings.Contains(string(services), `"timeout":15`) {
		t.Fatal(string(services), e)
	}
	if _, e = InstallImage(root, out, filepath.Join(dir, "exists.ufs"), InstallOptions{}); e == nil {
		t.Fatal("existing package silently overwritten")
	}
}
func TestReinstallPreservesGIDAndPrivateData(t *testing.T) {
	root, source, dir, dname := installFixture(t)
	first := filepath.Join(dir, "first.ufs")
	a, e := InstallImage(root, source, first, InstallOptions{})
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(first, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	ed, e := qnx6.NewEditor(f)
	if e != nil {
		t.Fatal(e)
	}
	private := "/accounts/1000/_startup_data/appdata/" + dname + "/data/keep"
	if e = ed.WriteFile(private, strings.NewReader("private"), 7, true); e != nil {
		t.Fatal(e)
	}
	if e = ed.Commit(); e != nil {
		t.Fatal(e)
	}
	f.Close()
	manifestPath, _, manifest, e := manifestFile(root)
	if e != nil {
		t.Fatal(e)
	}
	var withoutService Manifest
	for _, section := range manifest {
		if section.Get("Entry-Point-Key") != "service" {
			withoutService = append(withoutService, section)
		}
	}
	if e = os.WriteFile(manifestPath, withoutService.Bytes(), 0644); e != nil {
		t.Fatal(e)
	}
	second := filepath.Join(dir, "second.ufs")
	b, e := InstallImage(root, first, second, InstallOptions{Replace: true})
	if e != nil || a.GID != b.GID {
		t.Fatal(a, b, e)
	}
	data, e := image(t, second).ReadFile(private, 1<<20)
	if e != nil || string(data) != "private" {
		t.Fatal(string(data), e)
	}
	services, e := image(t, second).ReadFile("/var/pps/system/bslauncher", 1<<20)
	if e != nil || strings.Contains(string(services), dname+"..service..json:") {
		t.Fatal(string(services), e)
	}
}

func TestPackageSectionRejectsAmbiguityAndOversize(t *testing.T) {
	pkg := Section{{"Package-Name", "a"}, {"Package-Id", "id"}, {"Package-Version", "1"}, {"Package-Version-Id", "v"}}
	if _, e := packageSection(Manifest{pkg, pkg}); e == nil {
		t.Fatal("ambiguous package accepted")
	}
	pkg.Set("Package-Name", strings.Repeat("a", 255))
	pkg.Set("Package-Id", strings.Repeat("b", 255))
	if _, e := packageSection(Manifest{pkg}); e == nil {
		t.Fatal("oversize directory accepted")
	}
}
func TestInstallFailurePublishesNothing(t *testing.T) {
	root, source, dir, _ := installFixture(t)
	p, _, m, e := manifestFile(root)
	if e != nil {
		t.Fatal(e)
	}
	pkg, e := packageSection(m)
	if e != nil {
		t.Fatal(e)
	}
	pkg.Set("Display-Name", "unsupported,comma")
	for i := range m {
		if m[i].Get("Package-Name") == pkg.Get("Package-Name") {
			m[i] = pkg
		}
	}
	os.WriteFile(p, m.Bytes(), 0644)
	out := filepath.Join(dir, "bad.ufs")
	if _, e = InstallImage(root, source, out, InstallOptions{}); e == nil {
		t.Fatal("invalid CSV accepted")
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("partial image published")
	}
}
