package vmdk

import (
	"bytes"
	"hash/crc32"
	"io"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func reader(b []byte) binio.Reader {
	return binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))}
}
func sparse() []byte {
	b := make([]byte, 6*512)
	copy(b, "KDMV")
	binio.Put32(b, 4, 1)
	binio.Put64(b, 12, 16)
	binio.Put64(b, 20, 2)
	binio.Put32(b, 44, 4)
	binio.Put64(b, 56, 1)
	binio.Put32(b, 512, 2)
	binio.Put32(b, 1024, 4)
	copy(b[2048:], "first grain")
	return b
}
func TestSparseHolesAndBounds(t *testing.T) {
	b := sparse()
	d, err := Open(reader(b))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 1200)
	if n, err := d.ReadAt(out, 0); err != nil || n != len(out) || string(out[:11]) != "first grain" || !bytes.Equal(out[1024:], make([]byte, 176)) {
		t.Fatal(err)
	}
	if _, err = d.ReadAt(out, d.Size-1); err != io.EOF {
		t.Fatal("EOF expected", err)
	}
	binio.Put32(b, 1024, 0xffffffff)
	d, err = Open(reader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ReadAt(out, 0); err == nil {
		t.Fatal("out-of-file grain accepted")
	}
	binio.Put64(b, 20, 0)
	if _, err = Open(reader(b)); err == nil {
		t.Fatal("zero grain size accepted")
	}
}
func gpt() []byte {
	b := make([]byte, 100*512)
	b[510] = 0x55
	b[511] = 0xaa
	b[450] = 0xee
	binio.Put32(b, 454, 1)
	binio.Put32(b, 458, 99)
	h := b[512:1024]
	copy(h, "EFI PART")
	binio.Put32(h, 8, 0x10000)
	binio.Put32(h, 12, 92)
	binio.Put64(h, 24, 1)
	binio.Put64(h, 32, 99)
	binio.Put64(h, 40, 34)
	binio.Put64(h, 48, 97)
	binio.Put64(h, 72, 2)
	binio.Put32(h, 80, 4)
	binio.Put32(h, 84, 128)
	e := b[1024:1536]
	e[0] = 1
	binio.Put64(e, 32, 40)
	binio.Put64(e, 40, 50)
	binio.LE.PutUint16(e[56:], 'A')
	binio.Put32(h, 88, crc32.ChecksumIEEE(e))
	binio.Put32(h, 16, crc32.ChecksumIEEE(h[:92]))
	return b
}
func TestGPTChecksBothCRCs(t *testing.T) {
	b := gpt()
	d, err := Open(reader(b))
	if err != nil {
		t.Fatal(err)
	}
	parts, err := d.Partitions()
	if err != nil || len(parts) != 1 || parts[0].Name != "A" || parts[0].Size != 11*512 {
		t.Fatal(parts, err)
	}
	for _, at := range []int{530, 1060} {
		bad := bytes.Clone(b)
		bad[at] ^= 1
		d, _ := Open(reader(bad))
		if _, err = d.Partitions(); err == nil {
			t.Fatal("bad GPT CRC accepted")
		}
	}
}
func TestEBRCycleRejected(t *testing.T) {
	b := make([]byte, 100*512)
	b[510] = 0x55
	b[511] = 0xaa
	b[450] = 5
	binio.Put32(b, 454, 1)
	binio.Put32(b, 458, 99)
	e := b[512:1024]
	e[510] = 0x55
	e[511] = 0xaa
	e[450] = 0x83
	binio.Put32(e, 454, 1)
	binio.Put32(e, 458, 1)
	e[466] = 5
	d, _ := Open(reader(b))
	if _, err := d.Partitions(); err == nil {
		t.Fatal("EBR cycle accepted")
	}
}
func FuzzDisk(f *testing.F) {
	f.Add(gpt())
	f.Add(sparse())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		d, err := Open(reader(b))
		if err == nil {
			_, _ = d.Partitions()
			p := make([]byte, 512)
			_, _ = d.ReadAt(p, 0)
		}
	})
}

type memory []byte

func (b memory) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(b)) {
		return 0, io.ErrShortWrite
	}
	return copy(b[off:], p), nil
}
func TestSparseWritesRejectUnallocatedNonzeroData(t *testing.T) {
	b := sparse()
	d, err := Open(reader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.WriteAt(memory(b), []byte("new"), 0); err != nil {
		t.Fatal(err)
	}
	var got [3]byte
	if _, err = d.ReadAt(got[:], 0); err != nil || string(got[:]) != "new" {
		t.Fatal(err)
	}
	if _, err = d.WriteAt(memory(b), make([]byte, 10), 1024); err != nil {
		t.Fatal(err)
	}
	if _, err = d.WriteAt(memory(b), []byte("new"), 1024); err == nil {
		t.Fatal("hole allocation silently accepted")
	}
}
