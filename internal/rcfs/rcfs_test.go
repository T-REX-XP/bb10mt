package rcfs

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func fixture(compressed bool) []byte {
	b := make([]byte, 128<<10)
	copy(b, "rimh")
	copy(b[8:], "fs-os   ")
	binio.Put32(b, 4, 2)
	s := b[4096:4176]
	copy(s[32:], "r-c-f-s\x00")
	for p, v := range map[int]uint32{48: uint32(len(b)), 52: 3, 56: 8192, 60: 96, 64: 12288, 68: 64, 72: 16384, 76: uint32(len(b) - 16384)} {
		binio.Put32(s, p, v)
	}
	copy(b[12288:], "\x00payload\x00verifier.log\x00")
	data := bytes.Repeat([]byte("payload text"), 6000)
	encoded, err := packed(data, compressed)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 3; i++ {
		n := b[8192+i*32 : 8192+(i+1)*32]
		mode := uint16(0x8000 | 0644)
		if i == 0 {
			mode = 0x4000 | 0755
		}
		binio.LE.PutUint16(n[4:], mode)
		switch i {
		case 0:
			binio.Put32(n, 8, 12288)
			binio.Put32(n, 12, 8224)
			binio.Put32(n, 16, 64)
		case 1:
			binio.Put32(n, 8, 12289)
			binio.Put32(n, 12, 16384)
			binio.Put32(n, 16, uint32(len(data)))
			if compressed {
				binio.LE.PutUint16(n[6:], 0x80)
			}
		case 2:
			binio.Put32(n, 8, 12297)
			binio.Put32(n, 12, 100000)
			binio.Put32(n, 16, 60)
		}
	}
	copy(b[16384:], encoded)
	copy(b[100000:], "VSIG")
	binio.Put32(b, 100004, 1)
	binio.Put32(b, 100012, 2)
	binio.Put32(b, 100020, uint32(len(encoded)))
	sum := sha256.Sum256(encoded)
	copy(b[100024:], sum[:])
	return b
}
func reader(b []byte) binio.Reader {
	return binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))}
}
func TestRCFSVerifyReadAndExtraction(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		b := fixture(compressed)
		im, err := Open(reader(b))
		if err != nil {
			t.Fatal(err)
		}
		report, err := im.Verify()
		if err != nil || report.VerifiedHashes != 1 {
			t.Fatal(report, err)
		}
		n, err := im.Resolve("/payload")
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err = im.Data(n, &out); err != nil || out.String() != string(bytes.Repeat([]byte("payload text"), 6000)) {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err = im.Extract(dir); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "payload"))
		if err != nil || !bytes.Equal(data, out.Bytes()) {
			t.Fatal(err)
		}
		b[16390] ^= 1
		im, err = Open(reader(b))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = im.Verify(); err == nil {
			t.Fatal("bad packed SHA accepted")
		}
	}
}
func TestRCFSModifyPublishesOnlyVerifiedCopy(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	before := fixture(true)
	os.WriteFile(input, before, 0600)
	os.WriteFile(filepath.Join(dir, "replacement"), []byte("replacement content"), 0600)
	script := filepath.Join(dir, "script")
	os.WriteFile(script, []byte("push replacement /payload\nchmod 600 /payload\n"), 0600)
	output := filepath.Join(dir, "output")
	if _, err := Modify(input, output, script, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(output)
	im, err := Open(reader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = im.Verify(); err != nil {
		t.Fatal(err)
	}
	n, _ := im.Resolve("/payload")
	var data bytes.Buffer
	if err = im.Data(n, &data); err != nil || data.String() != "replacement content" || n.Mode&0777 != 0600 {
		t.Fatal(data.String(), err)
	}
	after, _ := os.ReadFile(input)
	if !bytes.Equal(before, after) {
		t.Fatal("source changed")
	}
	os.WriteFile(script, []byte("push missing /payload\n"), 0600)
	failed := filepath.Join(dir, "failed")
	if _, err = Modify(input, failed, script, ""); err == nil {
		t.Fatal("missing source accepted")
	}
	if _, err = os.Stat(failed); !os.IsNotExist(err) {
		t.Fatal("partial published")
	}
	corrupted := filepath.Join(dir, "corrupt")
	if _, err = Modify(input, corrupted, "", "/payload"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(corrupted)
	im, err = Open(reader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = im.Verify(); err == nil {
		t.Fatal("intentional corruption not detected")
	}
}
func FuzzRCFS(f *testing.F) {
	f.Add(fixture(true))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		im, err := Open(reader(b))
		if err == nil {
			_, _ = im.Verify()
		}
	})
}
func TestModifyDiskSelectsRCFSByHeader(t *testing.T) {
	dir := t.TempDir()
	image := fixture(true)
	disk := make([]byte, 512<<10)
	copy(disk[4096:], image)
	disk[510] = 0x55
	disk[511] = 0xaa
	disk[450] = 0x83
	binio.Put32(disk, 454, 8)
	binio.Put32(disk, 458, uint32(len(image)/512))
	disk[466] = 0x83
	binio.Put32(disk, 470, 700)
	binio.Put32(disk, 474, 20)
	input := filepath.Join(dir, "disk")
	os.WriteFile(input, disk, 0600)
	script := filepath.Join(dir, "script")
	os.WriteFile(script, []byte("chmod 600 /payload\n"), 0600)
	output := filepath.Join(dir, "output")
	if _, err := ModifyDisk(input, output, script); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(output)
	im, err := Open(reader(after[4096 : 4096+len(image)]))
	if err != nil {
		t.Fatal(err)
	}
	n, err := im.Resolve("/payload")
	if err != nil || n.Mode&0777 != 0600 {
		t.Fatal(n, err)
	}
	if !bytes.Equal(disk[:4096], after[:4096]) || !bytes.Equal(disk[4096+len(image):], after[4096+len(image):]) {
		t.Fatal("other disk regions changed")
	}
}
