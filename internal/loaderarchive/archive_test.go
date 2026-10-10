package loaderarchive

import (
	"bytes"
	"encoding/hex"
	"hash/crc32"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func fixture() []byte {
	// Independently encoded with Python lzma.FORMAT_ALONE, preset=1.
	packed, _ := hex.DecodeString("5d00001000ffffffffffffffff00361949297a9a869d56a6596aaf5b57147cb9c87380a98affff87ae0000")
	name := "LDR_01"
	offset := 10 + 4 + len(name) + 28
	b := make([]byte, offset+len(packed))
	copy(b, "BB10MT")
	binio.Put32(b, 6, 1)
	binio.Put32(b, 10, uint32(len(name)))
	copy(b[14:], name)
	at := 14 + len(name)
	binio.Put64(b, at, 19)
	binio.Put64(b, at+8, uint64(len(packed)))
	binio.Put64(b, at+16, uint64(offset))
	binio.Put32(b, at+24, crc32.ChecksumIEEE(packed))
	copy(b[offset:], packed)
	return b
}
func open(b []byte) (*Archive, error) {
	return Read(binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))})
}
func TestPythonLZMARoundtripAndCompressedCRC(t *testing.T) {
	b := fixture()
	a, e := open(b)
	if e != nil {
		t.Fatal(e)
	}
	data, e := a.Extract("ldr_01")
	if e != nil || string(data) != "legacy loader bytes" {
		t.Fatal(string(data), e)
	}
	b[len(b)-1] ^= 1
	a, e = open(b)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Extract("LDR_01"); e == nil {
		t.Fatal("CRC corruption accepted")
	}
}
func TestArchiveTruncationAndBounds(t *testing.T) {
	b := fixture()
	for n := 0; n < len(b); n++ {
		if _, e := open(b[:n]); e == nil {
			t.Fatalf("truncation %d", n)
		}
	}
	for _, mutate := range []func([]byte){func(b []byte) { binio.Put32(b, 6, 4097) }, func(b []byte) { copy(b[14:], "../bad") }, func(b []byte) { binio.Put64(b, 36, 10) }, func(b []byte) { binio.Put64(b, 20, MaxEntrySize+1) }} {
		bad := bytes.Clone(b)
		mutate(bad)
		if _, e := open(bad); e == nil {
			t.Fatal("invalid archive accepted")
		}
	}
}
func TestRejectsExcessiveLZMADictionaryBeforeAllocation(t *testing.T) {
	b := fixture()
	offset := 48
	binio.Put32(b, offset+1, 1<<30)
	binio.Put32(b, 44, crc32.ChecksumIEEE(b[offset:]))
	a, e := open(b)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Extract("LDR_01"); e == nil {
		t.Fatal("huge dictionary accepted")
	}
}
func FuzzArchive(f *testing.F) {
	f.Add(fixture())
	f.Add([]byte("BB10MT"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		a, e := open(b)
		if e == nil && len(a.Entries) > 0 {
			a.Extract(a.Entries[0].Name)
		}
	})
}
