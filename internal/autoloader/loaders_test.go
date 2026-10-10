package autoloader

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func loaderPE() []byte {
	b := fixturePE()
	copy(b[376:384], ".data\x00\x00\x00")
	binio.Put32(b, 152+28, 0x400000)
	binio.Put32(b, 376+12, 0x1000)
	binio.Put32(b, 512, 2)
	binio.Put32(b, 516, 0x70000)
	binio.Put32(b, 520, 0x04000b04)
	binio.Put32(b, 536, 0x401080)
	binio.Put32(b, 568, 0x04000b04)
	binio.Put32(b, 584, 0x401080)
	var z bytes.Buffer
	gz := gzip.NewWriter(&z)
	gz.Write([]byte("test loader"))
	gz.Close()
	copy(b[640:], z.Bytes())
	return b
}
func TestLoadersGzipAndDescriptorBounds(t *testing.T) {
	b := loaderPE()
	r := func(b []byte) binio.Reader { return binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))} }
	got, err := Loaders(r(b))
	if err != nil || len(got) != 2 || string(got[0].Data) != "test loader" {
		t.Fatal(got, err)
	}
	bad := bytes.Clone(b)
	binio.Put32(bad, 512, 0xffff)
	if _, err = Loaders(r(bad)); err == nil {
		t.Fatal("unbounded table accepted")
	}
	bad = bytes.Clone(b)
	bad[655] ^= 0xff
	if _, err = Loaders(r(bad)); err == nil {
		t.Fatal("corrupt gzip accepted")
	}
}
