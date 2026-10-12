package qcfm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func TestDeltaKeepsChangedErasedBlocksAndOffsets(t *testing.T) {
	base := bytes.Repeat([]byte{0x12}, 5*BlockSize)
	target := bytes.Clone(base)
	copy(target, bytes.Repeat([]byte{255}, BlockSize))
	target[2*BlockSize+19] = 0x24
	target[4*BlockSize+7] = 0x35
	r := func(b []byte) binio.Reader { return binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))} }
	c := Chunk{Type: 5, BlockSize: BlockSize, Runs: []Run{{0, 5}}, DataSize: int64(len(base))}
	path := filepath.Join(t.TempDir(), "delta")
	report, err := WriteDelta(path, r(base), c, r(target), c)
	if err != nil {
		t.Fatal(err)
	}
	if report.ChangedBlocks != 3 || len(report.Runs) != 3 || report.Runs[1].Offset != 2 || report.Runs[2].Offset != 4 {
		t.Fatal(report)
	}
	h := sha256.Sum256(target)
	if report.TargetSHA256 != hex.EncodeToString(h[:]) || report.OverlaySHA256 != report.TargetSHA256 {
		t.Fatal(report)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := Read(r(b))
	if err != nil {
		t.Fatal(err)
	}
	if !packed.Signed || packed.V2[0].DataSize != 3*BlockSize {
		t.Fatal(packed)
	}
	// Reconstruct independently from its run map. Omitted blocks retain base.
	got := bytes.Clone(base)
	pos := packed.V2[0].DataOffset
	for _, run := range packed.V2[0].Runs {
		n := int64(run.Count) * BlockSize
		off := int64(run.Offset) * BlockSize
		copy(got[off:off+n], b[pos:pos+n])
		pos += n
	}
	if !bytes.Equal(got, target) {
		t.Fatal("overlay differs")
	}
	if _, err = WriteDelta(path, r(base), c, r(target), c); err == nil {
		t.Fatal("overwrote existing output")
	}
}

func TestDeltaRejectsIncompatibleOrUnchangedInputs(t *testing.T) {
	b := bytes.Repeat([]byte{1}, BlockSize)
	r := binio.Reader{ReaderAt: bytes.NewReader(b), Size: int64(len(b))}
	c := Chunk{Type: 5, BlockSize: BlockSize, Runs: []Run{{0, 1}}, DataSize: BlockSize}
	for _, kind := range []string{"unchanged", "resize", "sparse", "boot", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			after := c
			after.Runs = append([]Run(nil), c.Runs...)
			rr := r
			switch kind {
			case "resize":
				after.Runs[0].Count = 2
			case "sparse":
				after.Runs[0].Offset = 1
			case "boot":
				after.Type = 8
			case "truncated":
				rr.Size--
			}
			path := filepath.Join(t.TempDir(), "out")
			if _, err := WriteDelta(path, r, c, rr, after); err == nil {
				t.Fatal("accepted", kind)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("published failed delta")
			}
		})
	}
}

type changingDeltaReader struct {
	data  []byte
	reads int
}

func (r *changingDeltaReader) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	n, err := bytes.NewReader(r.data).ReadAt(p, off)
	if r.reads > 1 && n > 0 {
		p[0] ^= 1
	}
	return n, err
}
func TestDeltaRejectsChangingSource(t *testing.T) {
	b := bytes.Repeat([]byte{1}, BlockSize)
	target := bytes.Repeat([]byte{2}, BlockSize)
	c := Chunk{Type: 5, BlockSize: BlockSize, Runs: []Run{{0, 1}}, DataSize: BlockSize}
	path := filepath.Join(t.TempDir(), "out")
	_, err := WriteDelta(path, binio.Reader{ReaderAt: &changingDeltaReader{data: b}, Size: int64(len(b))}, c, binio.Reader{ReaderAt: bytes.NewReader(target), Size: int64(len(target))}, c)
	if err == nil {
		t.Fatal("changing source accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed output published")
	}
}
