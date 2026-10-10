package batch

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bb10root/bb10mt/internal/autoloader"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qcfm"
	"github.com/bb10root/bb10mt/internal/qnx6"
)

func stub() []byte {
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
func source(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	im := filepath.Join(dir, "p.ufs")
	if err := qnx6.Mkfs(im, 1024, 64, 4096); err != nil {
		t.Fatal(err)
	}
	osBundle := filepath.Join(dir, "os.signed")
	nonUFS := filepath.Join(dir, "p.ifs")
	os.WriteFile(nonUFS, []byte("preserve this OS partition"), 0600)
	if err := qcfm.Pack(osBundle, []qcfm.Input{{Path: im}, {Path: nonUFS}}, qcfm.Options{Version: 2, Sign: true}); err != nil {
		t.Fatal(err)
	}
	radio := filepath.Join(dir, "p.radio.rcfs")
	os.WriteFile(radio, []byte("radio"), 0600)
	radioBundle := filepath.Join(dir, "radio.signed")
	if err := qcfm.Pack(radioBundle, []qcfm.Input{{Path: radio}}, qcfm.Options{Version: 2, Sign: true}); err != nil {
		t.Fatal(err)
	}
	cap := filepath.Join(dir, "cap.exe")
	os.WriteFile(cap, stub(), 0600)
	input := filepath.Join(dir, "firmware.exe")
	if err := autoloader.Create(input, cap, []string{osBundle, radioBundle}, 2); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "payload"), []byte("verified native batch"), 0600)
	script := filepath.Join(dir, "patch.txt")
	os.WriteFile(script, []byte("mkdir -p /var/data\npush payload /var/data/a-long-payload-filename.txt\nchmod 640 /var/data/a-long-payload-filename.txt\nchown 0:427 /var/data/a-long-payload-filename.txt\n"), 0600)
	return input, script, dir
}
func TestNativeBatchFinalImage(t *testing.T) {
	for _, compact := range []bool{false, true} {
		t.Run(fmt.Sprintf("compact=%v", compact), func(t *testing.T) { nativeBatchFinalImage(t, Options{Compact: compact}) })
	}
}
func nativeBatchFinalImage(t *testing.T, opt Options) {
	input, script, dir := source(t)
	output := filepath.Join(dir, "out")
	if err := BuildWithOptions(input, script, output, &bytes.Buffer{}, opt); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(output, "firmware_os.exe"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	h, err := autoloader.Read(binio.Reader{ReaderAt: f, Size: st.Size()})
	if err != nil {
		t.Fatal(err)
	}
	span := h.Files[0]
	r := binio.Reader{ReaderAt: io.NewSectionReader(f, span.Offset, span.Size), Size: span.Size}
	c, err := qcfm.Read(r)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err = qcfm.Extract(r, c.V2[0], false, &b); err != nil {
		t.Fatal(err)
	}
	im, err := qnx6.Open(binio.Reader{ReaderAt: bytes.NewReader(b.Bytes()), Size: int64(b.Len())})
	if err != nil {
		t.Fatal(err)
	}
	report, err := im.Check()
	if err != nil || len(report.Errors) > 0 {
		t.Fatal(report, err)
	}
	n, bad, err := im.Resolve("/var/data/a-long-payload-filename.txt")
	if err != nil || len(bad) > 0 || n.Mode()&07777 != 0640 || n.GID() != 427 {
		t.Fatal(err, bad)
	}
	var payload bytes.Buffer
	if err = im.Data(n, &payload); err != nil || payload.String() != "verified native batch" {
		t.Fatal(err, payload.String())
	}
	if _, err = os.Stat(filepath.Join(output, "firmware_radio.exe")); err != nil {
		t.Fatal(err)
	}
	verification, err := VerifyBuild(input, output, io.Discard)
	if err != nil || !verification.UFSMatches || len(verification.Preserved) != 1 || verification.Preserved[0] != 8 || verification.Radio == "" {
		t.Fatal(verification, err)
	}
}

func TestVerifyBuildRejectsStaleImageAndChangedRadio(t *testing.T) {
	for _, kind := range []string{"loose image", "radio", "non-UFS"} {
		t.Run(kind, func(t *testing.T) {
			input, script, dir := source(t)
			output := filepath.Join(dir, "out")
			if err := Build(input, script, output, io.Discard); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "loose image":
				image := filepath.Join(output, "firmware.0.0.ufs")
				data, err := os.ReadFile(image)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				if err := os.WriteFile(image, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "radio":
				p := filepath.Join(output, "firmware_radio.exe")
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				if err := os.WriteFile(p, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "non-UFS":
				// Repack a valid signed container after altering a preserved partition.
				if err := os.WriteFile(filepath.Join(output, "firmware.0.1.ifs"), []byte("changed partition"), 0600); err != nil {
					t.Fatal(err)
				}
				packed := filepath.Join(dir, "changed.signed")
				if err := qcfm.Pack(packed, []qcfm.Input{{Path: filepath.Join(output, "firmware.0.0.ufs")}, {Path: filepath.Join(output, "firmware.0.1.ifs")}}, qcfm.Options{Version: 2, Sign: true}); err != nil {
					t.Fatal(err)
				}
				osPath := filepath.Join(output, "firmware_os.exe")
				if err := os.Remove(osPath); err != nil {
					t.Fatal(err)
				}
				if err := autoloader.Create(osPath, filepath.Join(dir, "cap.exe"), []string{packed}, 2); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := VerifyBuild(input, output, io.Discard); err == nil {
				t.Fatal("accepted changed " + kind)
			}
		})
	}
}
func TestNativeBatchScriptFailurePublishesNothing(t *testing.T) {
	input, script, dir := source(t)
	os.WriteFile(script, []byte("mkdir /new\npush missing /new/file\n"), 0600)
	out := filepath.Join(dir, "out")
	if err := Build(input, script, out, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("partial batch output")
	}
}
