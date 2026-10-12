package qcfm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
)

// DeltaReport describes an exact-base block overlay, not a Red Bend OTA delta.
// Source hashes are evidence only: an unchanged CAP does not enforce them.
type DeltaReport struct {
	Type          uint32   `json:"type"`
	BlockBytes    uint32   `json:"blockBytes"`
	LogicalBytes  int64    `json:"logicalBytes"`
	ChangedBlocks uint32   `json:"changedBlocks"`
	ChangedBytes  int64    `json:"changedBytes"`
	Runs          []Run    `json:"runs"`
	BaseSHA256    string   `json:"baseSHA256"`
	TargetSHA256  string   `json:"targetSHA256"`
	OverlaySHA256 string   `json:"offlineOverlaySHA256"`
	Preimages     []string `json:"changedBlockBaseSHA256"`
}

// WriteDelta deliberately supports only a complete, equally sized, contiguous
// UFS source and target. Sparse *input* images, resizing, boot/radio updates and
// implicit partition selection are outside this experimental format.
func WriteDelta(path string, base binio.Reader, before Chunk, target binio.Reader, after Chunk) (DeltaReport, error) {
	report := DeltaReport{Type: 5, BlockBytes: before.BlockSize}
	full := func(c Chunk) bool {
		return c.Type == 5 && c.BlockSize == BlockSize && len(c.Runs) == 1 && c.Runs[0].Offset == 0 && c.Runs[0].Count != 0
	}
	if !full(before) || !full(after) || before.BlockSize != after.BlockSize || before.Runs[0].Count != after.Runs[0].Count {
		return report, fmt.Errorf("delta requires equal complete UFS geometry with 64 KiB blocks")
	}
	report.LogicalBytes = int64(before.Runs[0].Count) * int64(BlockSize)
	if err := base.Range(before.DataOffset, report.LogicalBytes); err != nil {
		return report, err
	}
	if err := target.Range(after.DataOffset, report.LogicalBytes); err != nil {
		return report, err
	}
	a, b := make([]byte, BlockSize), make([]byte, BlockSize)
	ha, hb := sha256.New(), sha256.New()
	for i := uint32(0); i < before.Runs[0].Count; i++ {
		off := int64(i) * BlockSize
		if _, err := base.ReadAt(a, before.DataOffset+off); err != nil {
			return report, err
		}
		if _, err := target.ReadAt(b, after.DataOffset+off); err != nil {
			return report, err
		}
		ha.Write(a)
		hb.Write(b)
		if bytes.Equal(a, b) {
			continue
		}
		report.ChangedBlocks++
		h := sha256.Sum256(a)
		report.Preimages = append(report.Preimages, hex.EncodeToString(h[:]))
		if n := len(report.Runs); n != 0 && report.Runs[n-1].Offset+report.Runs[n-1].Count == i {
			report.Runs[n-1].Count++
		} else {
			report.Runs = append(report.Runs, Run{i, 1})
		}
	}
	if report.ChangedBlocks == 0 {
		return report, fmt.Errorf("no changed UFS blocks")
	}
	report.ChangedBytes = int64(report.ChangedBlocks) * BlockSize
	report.BaseSHA256 = hex.EncodeToString(ha.Sum(nil))
	report.TargetSHA256 = hex.EncodeToString(hb.Sum(nil))
	if len(report.Runs) > (maxHeader-104)/16 {
		return report, fmt.Errorf("delta run table too large")
	}
	// Native V2 QCFM, one UFS control, preserving absolute block offsets.
	hdr := make([]byte, 104+16*len(report.Runs))
	copy(hdr, "mfcq")
	binio.Put32(hdr, 8, 1)
	binio.Put32(hdr, 16, uint32(len(hdr)))
	binio.Put32(hdr, 24, 32)
	copy(hdr[32:], "mfcq")
	binio.Put32(hdr, 40, 0x20000)
	binio.Put32(hdr, 44, 28)
	binio.Put32(hdr, 48, 1)
	binio.Put32(hdr, 52, uint32(len(hdr)-32))
	copy(hdr[60:], "pfcq")
	binio.Put32(hdr, 64, 0x20000)
	binio.Put32(hdr, 68, uint32(len(hdr)-60))
	binio.Put32(hdr, 72, 5)
	binio.Put32(hdr, 76, 44)
	binio.Put32(hdr, 80, uint32(len(report.Runs)))
	binio.Put32(hdr, 100, BlockSize)
	for i, run := range report.Runs {
		p := 104 + i*16
		copy(hdr[p:], "rrcq")
		binio.Put32(hdr, p+4, 16)
		binio.Put32(hdr, p+8, run.Offset)
		binio.Put32(hdr, p+12, run.Count)
	}
	err := atomicfile.Write(path, func(f *os.File) error {
		crc := crc32.NewIEEE()
		w := io.MultiWriter(f, crc)
		if _, err := w.Write(hdr); err != nil {
			return err
		}
		for _, run := range report.Runs {
			if _, err := io.CopyN(w, io.NewSectionReader(target.ReaderAt, after.DataOffset+int64(run.Offset)*BlockSize, int64(run.Count)*BlockSize), int64(run.Count)*BlockSize); err != nil {
				return err
			}
		}
		// Match the existing patcher's legacy transport trailer, NOT an OEM
		// cryptographic signature. Stock OTA signature validation is separate.
		trailer := bytes.Clone(signature)
		if _, err := w.Write(trailer[:556]); err != nil {
			return err
		}
		binio.Put32(trailer, 556, crc.Sum32())
		if _, err := f.Write(trailer[556:]); err != nil {
			return err
		}
		st, err := f.Stat()
		if err != nil {
			return err
		}
		packed, err := Read(binio.Reader{ReaderAt: f, Size: st.Size()})
		if err != nil {
			return err
		}
		if len(packed.V2) != 1 || packed.V2[0].Type != 5 {
			return fmt.Errorf("delta control verification failed")
		}
		// Replay the *serialized* candidate against the base and compare every
		// byte to the target. Rehash both inputs to reject concurrent changes.
		pa := packed.V2[0]
		src := pa.DataOffset
		runIndex := 0
		ha.Reset()
		hb.Reset()
		overlay := sha256.New()
		for i := uint32(0); i < before.Runs[0].Count; i++ {
			off := int64(i) * BlockSize
			if _, err := base.ReadAt(a, before.DataOffset+off); err != nil {
				return err
			}
			if _, err := target.ReadAt(b, after.DataOffset+off); err != nil {
				return err
			}
			ha.Write(a)
			hb.Write(b)
			for runIndex < len(pa.Runs) && i >= pa.Runs[runIndex].Offset+pa.Runs[runIndex].Count {
				runIndex++
			}
			if runIndex < len(pa.Runs) && i >= pa.Runs[runIndex].Offset {
				if _, err := f.ReadAt(a, src); err != nil {
					return err
				}
				src += BlockSize
			}
			if !bytes.Equal(a, b) {
				return fmt.Errorf("serialized overlay mismatch at block %d", i)
			}
			overlay.Write(a)
		}
		report.OverlaySHA256 = hex.EncodeToString(overlay.Sum(nil))
		if hex.EncodeToString(ha.Sum(nil)) != report.BaseSHA256 || hex.EncodeToString(hb.Sum(nil)) != report.TargetSHA256 || report.OverlaySHA256 != report.TargetSHA256 {
			return fmt.Errorf("input changed during delta creation")
		}
		return nil
	})
	return report, err
}

// LogicalDigest includes erased gaps, consistent with complete image extraction.
func LogicalDigest(r binio.Reader, c Chunk) (string, error) {
	h := sha256.New()
	if err := Extract(r, c, false, h); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
