package autoloader

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qcfm"
)

func deltaFixture(t *testing.T, dir, name string, stub []byte, ufs, kernel byte) string {
	t.Helper()
	root := filepath.Join(dir, name)
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	cap := filepath.Join(root, "stub")
	os.WriteFile(cap, stub, 0600)
	p := filepath.Join(root, "image.ufs")
	data := bytes.Repeat([]byte{1}, 4*qcfm.BlockSize)
	data[2*qcfm.BlockSize+9] = ufs
	os.WriteFile(p, data, 0600)
	k := filepath.Join(root, "kernel.ifs")
	os.WriteFile(k, bytes.Repeat([]byte{kernel}, qcfm.BlockSize), 0600)
	c := filepath.Join(root, "os.signed")
	if err := qcfm.Pack(c, []qcfm.Input{{Path: k}, {Path: p}}, qcfm.Options{Version: 2, Sign: true}); err != nil {
		t.Fatal(err)
	}
	loader := filepath.Join(root, "os.exe")
	if err := Create(loader, cap, []string{c}, 2); err != nil {
		t.Fatal(err)
	}
	return loader
}

func TestDeltaAutoloaderPreservesOriginalStubAndPublishesOnlyArtifacts(t *testing.T) {
	dir := t.TempDir()
	stub := append(fixturePE(), bytes.Repeat([]byte{0xa5}, 112)...)
	base := deltaFixture(t, dir, "base", stub, 1, 7)
	target := deltaFixture(t, dir, "target", stub, 2, 7)
	out := filepath.Join(dir, "out")
	report, err := BuildDelta(base, target, out, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Experimental || report.Delta.ChangedBlocks != 1 || report.Delta.OverlaySHA256 != report.Delta.TargetSHA256 || len(report.Limitations) < 4 {
		t.Fatal(report)
	}
	files, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatal("intermediates left", files)
	}
	b, err := os.ReadFile(filepath.Join(out, "patch-only-EXPERIMENTAL.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[:len(stub)], stub) {
		t.Fatal("CAP stub changed")
	}
	h, err := Read(binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))})
	if err != nil || len(h.Files) != 1 {
		t.Fatal(h, err)
	}
	m, err := os.ReadFile(filepath.Join(out, "validation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recorded DeltaBuildReport
	if err = json.Unmarshal(m, &recorded); err != nil || recorded.OutputSHA256 != report.OutputSHA256 {
		t.Fatal(err)
	}
	if _, err = BuildDelta(base, target, out, dir); err == nil {
		t.Fatal("output replaced")
	}
}

func TestDeltaAutoloaderRejectsChangedKernelOrCAP(t *testing.T) {
	for _, kind := range []string{"kernel", "stub", "noop"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			stub := fixturePE()
			base := deltaFixture(t, dir, "base", stub, 1, 7)
			other := bytes.Clone(stub)
			kernel := byte(7)
			ufs := byte(2)
			if kind == "kernel" {
				kernel = 8
			}
			if kind == "stub" {
				other[600] ^= 1
			}
			if kind == "noop" {
				ufs = 1
			}
			target := deltaFixture(t, dir, "target", other, ufs, kernel)
			out := filepath.Join(dir, "out")
			if _, err := BuildDelta(base, target, out, dir); err == nil {
				t.Fatal("accepted", kind)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("published failed output")
			}
			files, _ := filepath.Glob(filepath.Join(dir, "bb10mt-delta-*"))
			if len(files) != 0 {
				t.Fatal("scratch not cleaned")
			}
		})
	}
}

func TestDeltaRejectsExtraTargetBundles(t *testing.T) {
	dir := t.TempDir()
	stub := fixturePE()
	base := deltaFixture(t, dir, "base", stub, 1, 7)
	target := deltaFixture(t, dir, "target", stub, 2, 7)
	combined := filepath.Join(dir, "combined.exe")
	container := filepath.Join(filepath.Dir(target), "os.signed")
	if err := Create(combined, filepath.Join(filepath.Dir(target), "stub"), []string{container, container}, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildDelta(base, combined, filepath.Join(dir, "out"), dir); err == nil {
		t.Fatal("extra target bundle accepted")
	}
}
