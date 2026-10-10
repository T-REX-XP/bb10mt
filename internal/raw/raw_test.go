package raw

import (
	"bytes"
	"github.com/bb10root/bb10mt/internal/binio"
	"hash/crc32"
	"testing"
)

func reader(b []byte) binio.Reader {
	return binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))}
}
func nvram(data []byte) []byte {
	b := make([]byte, 28+len(data)+4)
	binio.LE.PutUint16(b, 1)
	binio.LE.PutUint16(b[2:], 7)
	binio.Put32(b, 4, 9)
	binio.Put32(b, 8, crc32.ChecksumIEEE(data))
	binio.Put32(b, 16, uint32(len(b)))
	binio.Put32(b, 20, uint32(len(data)))
	binio.Put32(b, 24, crc32.ChecksumIEEE(b[:24]))
	copy(b[28:], data)
	copy(b[len(b)-4:], "NVRE")
	return b
}
func TestNVRECRCAndDuplicateNames(t *testing.T) {
	record := nvram([]byte("payload"))
	b := append(append([]byte{}, record...), record...)
	records, err := NVRE(reader(b))
	if err != nil || len(records) != 2 || records[1].Name != "0007+00000009_2.bin" {
		t.Fatal(records, err)
	}
	for _, pos := range []int{4, 28, len(b) - 1} {
		bad := bytes.Clone(b)
		bad[pos] ^= 1
		if _, err = NVRE(reader(bad)); err == nil {
			t.Fatal("bad CRC accepted")
		}
	}
}
func TestMCTBoundsAndCRC(t *testing.T) {
	b := make([]byte, 3*BlockSize)
	binio.Put32(b, 0, 0x92be564a)
	binio.LE.PutUint16(b[6:], 1)
	p := 8
	b[p] = 0x39
	b[p+1] = 24
	b[p+2] = 3
	copy(b[p+4:], "nvram")
	binio.Put32(b, p+16, 1)
	binio.Put32(b, p+20, 2)
	p += 24
	b[p] = 9
	b[p+1] = 8
	binio.Put32(b, p+4, crc32.ChecksumIEEE(b[:p]))
	b[p+8] = 255
	b[p+9] = 2
	parts, err := MCT(reader(b), 0)
	if err != nil || len(parts) != 1 || parts[0].Offset != BlockSize || parts[0].Size != 2*BlockSize {
		t.Fatal(parts, err)
	}
	bad := bytes.Clone(b)
	bad[10] ^= 1
	if _, err = MCT(reader(bad), 0); err == nil {
		t.Fatal("MCT CRC ignored")
	}
	if _, err = MCT(reader(b[:2*BlockSize]), 0); err == nil {
		t.Fatal("truncated partition accepted")
	}
}
func FuzzRaw(f *testing.F) {
	f.Add(nvram([]byte("data")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, _ = NVRE(reader(b))
		_, _ = MCT(reader(b), 0)
	})
}
