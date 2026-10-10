package qnx6

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func fixture() ([]byte, string, int64) {
	b := make([]byte, 12288+8*4096)
	sb := b[8192:8704]
	binio.Put32(sb, 0, Magic)
	binio.Put32(sb, 24, 0x100)
	binio.LE.PutUint16(sb[28:], 4)
	binio.Put32(sb, 48, 4096)
	binio.Put32(sb, 52, 2)
	binio.Put32(sb, 60, 8)
	pointers := func(raw []byte, size uint64, block uint32, ptr, level int) {
		binio.Put64(raw, 0, size)
		for i := 0; i < 16; i++ {
			binio.Put32(raw, ptr+i*4, Missing)
		}
		binio.Put32(raw, ptr, block)
		raw[level] = 0
	}
	pointers(sb[72:152], 256, 0, 8, 72)
	pointers(sb[232:312], 4096, 1, 8, 72)
	root := b[12288:12416]
	pointers(root, 32, 2, 36, 100)
	binio.LE.PutUint16(root[32:], 0x4000)
	file := b[12416:12544]
	pointers(file, 14, 3, 36, 100)
	binio.LE.PutUint16(file[32:], 0x8000)
	name := "libAppWorldStoreFront.so.1.0.0"
	p := 12288 + 4096
	binio.LE.PutUint16(b[p:], uint16(len(name)))
	copy(b[p+2:], name)
	p = 12288 + 2*4096
	binio.Put32(b, p, 2)
	b[p+4] = 255
	binio.Put32(b, p+8, 0)
	binio.Put32(b, p+12, 0xfffffd77)
	copy(b[12288+3*4096:], "pinned payload")
	binio.Put32(sb, 4, CRC(sb[8:]))
	return b, name, int64(p + 12)
}
func reader(b []byte) binio.Reader {
	return binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))}
}
func TestKnownKernelChecksums(t *testing.T) {
	for name, v := range map[string]uint32{"libAppWorldStoreFront.so.1.0.0": 0x7fffc8d0, "cert_E0AB059420725493056062023670F7CD2EFC6666.pem": 0x994a99a0} {
		if got := LongNameChecksum([]byte(name)); got != v {
			t.Fatalf("%s: %x != %x", name, got, v)
		}
	}
	if CRC([]byte("123456789")) != 0x89a1897f {
		t.Fatal("QNX CRC vector mismatch")
	}
}
func TestAuditAndPayload(t *testing.T) {
	b, name, off := fixture()
	im, e := Open(reader(b))
	if e != nil {
		t.Fatal(e)
	}
	a, e := im.AuditNames()
	if e != nil {
		t.Fatal(e)
	}
	if len(a.Issues) != 1 || a.Issues[0].Offset != off || a.Names != 1 {
		t.Fatal(a)
	}
	n, bad, e := im.Resolve("/" + name)
	if e != nil || len(bad) != 1 {
		t.Fatal(e, bad)
	}
	var out bytes.Buffer
	if e = im.Data(n, &out); e != nil || out.String() != "pinned payload" {
		t.Fatal(e, out.String())
	}
	binio.Put32(b, int(off), LongNameChecksum([]byte(name)))
	im, e = Open(reader(b))
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte("pinned payload"))
	if e = im.VerifyPayloads([]Expected{{Path: name, SHA256: fmt.Sprintf("%x", sum)}}); e != nil {
		t.Fatal(e)
	}
}
func TestRepairIsCopyAndChangesOnlyChecksum(t *testing.T) {
	b, _, off := fixture()
	dir := t.TempDir()
	in := filepath.Join(dir, "original")
	out := filepath.Join(dir, "fixed")
	os.WriteFile(in, b, 0600)
	a, e := RepairNames(in, out)
	if e != nil || len(a.Issues) != 1 {
		t.Fatal(a, e)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got[:off], b[:off]) || !bytes.Equal(got[off+4:], b[off+4:]) {
		t.Fatal("changed unrelated bytes")
	}
	before, _ := os.ReadFile(in)
	if !bytes.Equal(before, b) {
		t.Fatal("input changed")
	}
	im, e := Open(reader(got))
	if e != nil {
		t.Fatal(e)
	}
	a, e = im.AuditNames()
	if e != nil || len(a.Issues) != 0 {
		t.Fatal(a, e)
	}
}
func TestRejectsBadCRCAndTruncation(t *testing.T) {
	b, _, _ := fixture()
	bad := bytes.Clone(b)
	bad[8192+8] ^= 1
	if _, e := Open(reader(bad)); e == nil {
		t.Fatal("bad CRC accepted")
	}
	im, e := Open(reader(b[:len(b)-6*4096]))
	if e == nil {
		if _, e = im.AuditNames(); e == nil {
			t.Fatal("truncated directory accepted")
		}
	}
}
func TestInvalidLongNameDoesNotPublishRepair(t *testing.T) {
	b, _, _ := fixture()
	binio.LE.PutUint16(b[12288+4096:], 511)
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	out := filepath.Join(dir, "out")
	os.WriteFile(in, b, 0600)
	if _, e := RepairNames(in, out); e == nil {
		t.Fatal("invalid name accepted")
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("published invalid repair")
	}
}
func FuzzOpen(f *testing.F) {
	b, _, _ := fixture()
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		if im, e := Open(reader(b)); e == nil && im.Inodes < 1000 {
			_, _ = im.AuditNames()
		}
	})
}
