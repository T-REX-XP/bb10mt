package autoloader

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qcfm"
)

type DeltaBuildReport struct {
	Experimental            bool             `json:"experimental"`
	BaseFileSHA256          string           `json:"baseFileSHA256"`
	TargetFileSHA256        string           `json:"targetFileSHA256"`
	OriginalCAPSHA256       string           `json:"originalCAPSHA256"`
	OutputSHA256            string           `json:"outputSHA256"`
	OutputBytes             int64            `json:"outputBytes"`
	Delta                   qcfm.DeltaReport `json:"delta"`
	UnchangedPartitionTypes []uint32         `json:"unchangedPartitionTypes"`
	Limitations             []string         `json:"limitations"`
}

func readerDigest(r io.Reader) (string, error) {
	h := sha256.New()
	_, err := io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil)), err
}

func osContainer(r binio.Reader, h Header) (binio.Reader, qcfm.Container, error) {
	var result binio.Reader
	var selected qcfm.Container
	found := false
	for _, part := range h.Files {
		rr := binio.Reader{ReaderAt: io.NewSectionReader(r.ReaderAt, part.Offset, part.Size), Size: part.Size}
		c, err := qcfm.Read(rr)
		if err != nil {
			return result, selected, err
		}
		if len(c.V2) == 0 {
			return result, selected, fmt.Errorf("delta requires V2 partition identities")
		}
		for _, ch := range c.V2 {
			if ch.Type == 5 {
				if found {
					return result, selected, fmt.Errorf("ambiguous UFS source")
				}
				found = true
				result = rr
				selected = c
			}
		}
	}
	if !found {
		return result, selected, fmt.Errorf("no UFS container")
	}
	return result, selected, nil
}

// BuildDelta emits an explicitly experimental original-CAP autoloader. It does
// not contact devices. The evidence manifest is NOT enforced by the stock CAP.
func BuildDelta(basePath, targetPath, output, workspace string) (DeltaBuildReport, error) {
	report := DeltaBuildReport{Experimental: true, Limitations: []string{
		"Handset acceptance and preservation of omitted blocks are untested.",
		"Original CAP does not enforce base hashes; installed UFS must match the exact base, including filesystem metadata.",
		"Destination erase, active/inactive region selection, companion controls and activation remain unverified.",
		"Legacy QCFM transport trailer is not an OEM signature and is not a valid stock OTA signature.",
		"Not approved for beta distribution; no claim of user-data preservation or power-loss recovery.",
	}}
	if _, err := os.Lstat(output); err == nil {
		return report, fmt.Errorf("output already exists: %s: %w", output, os.ErrExist)
	} else if !os.IsNotExist(err) {
		return report, err
	}
	open := func(path string) (*os.File, binio.Reader, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, binio.Reader{}, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, binio.Reader{}, err
		}
		if !st.Mode().IsRegular() {
			f.Close()
			return nil, binio.Reader{}, fmt.Errorf("regular CAP input required")
		}
		return f, binio.Reader{ReaderAt: f, Size: st.Size()}, nil
	}
	bf, br, err := open(basePath)
	if err != nil {
		return report, err
	}
	defer bf.Close()
	tf, tr, err := open(targetPath)
	if err != nil {
		return report, err
	}
	defer tf.Close()
	bh, err := Read(br)
	if err != nil {
		return report, err
	}
	th, err := Read(tr)
	if err != nil {
		return report, err
	}
	if len(th.Files) != 1 {
		return report, fmt.Errorf("target must be an OS-only autoloader; radio/extra bundles cannot be silently omitted")
	}
	if bh.SignatureOffset != th.SignatureOffset {
		return report, fmt.Errorf("CAP stubs have different sizes")
	}
	report.OriginalCAPSHA256, err = readerDigest(io.NewSectionReader(bf, 0, bh.SignatureOffset))
	if err != nil {
		return report, err
	}
	targetStub, err := readerDigest(io.NewSectionReader(tf, 0, th.SignatureOffset))
	if err != nil {
		return report, err
	}
	if targetStub != report.OriginalCAPSHA256 {
		return report, fmt.Errorf("CAP stubs differ")
	}
	bs, bc, err := osContainer(br, bh)
	if err != nil {
		return report, err
	}
	ts, tc, err := osContainer(tr, th)
	if err != nil {
		return report, err
	}
	if len(bc.V2) != len(tc.V2) {
		return report, fmt.Errorf("OS partition lists differ")
	}
	var before, after qcfm.Chunk
	for i, a := range bc.V2 {
		b := tc.V2[i]
		if a.Type != b.Type {
			return report, fmt.Errorf("OS partition order/types differ")
		}
		if a.Type == 5 {
			before = a
			after = b
			continue
		}
		x, err := qcfm.LogicalDigest(bs, a)
		if err != nil {
			return report, err
		}
		y, err := qcfm.LogicalDigest(ts, b)
		if err != nil {
			return report, err
		}
		if x != y {
			return report, fmt.Errorf("non-UFS partition %d changed; excluded from delta scope", a.Type)
		}
		report.UnchangedPartitionTypes = append(report.UnchangedPartitionTypes, a.Type)
	}
	stage, err := os.MkdirTemp(workspace, "bb10mt-delta-*")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(stage)
	container := filepath.Join(stage, ".delta.signed")
	report.Delta, err = qcfm.WriteDelta(container, bs, before, ts, after)
	if err != nil {
		return report, err
	}
	stub := filepath.Join(stage, ".original-cap")
	if err = atomicfile.Write(stub, func(f *os.File) error {
		_, e := io.CopyN(f, io.NewSectionReader(bf, 0, bh.SignatureOffset), bh.SignatureOffset)
		return e
	}); err != nil {
		return report, err
	}
	loader := filepath.Join(stage, "patch-only-EXPERIMENTAL.exe")
	if err = Create(loader, stub, []string{container}, bh.Version); err != nil {
		return report, err
	}
	f, lr, err := open(loader)
	if err != nil {
		return report, err
	}
	lh, err := Read(lr)
	if err != nil {
		f.Close()
		return report, err
	}
	stubHash, err := readerDigest(io.NewSectionReader(f, 0, lh.SignatureOffset))
	if err != nil {
		f.Close()
		return report, err
	}
	if stubHash != report.OriginalCAPSHA256 {
		f.Close()
		return report, fmt.Errorf("original CAP changed")
	}
	_, packed, err := osContainer(lr, lh)
	if err != nil {
		f.Close()
		return report, err
	}
	if len(lh.Files) != 1 || len(packed.V2) != 1 || packed.V2[0].DataSize != report.Delta.ChangedBytes {
		f.Close()
		return report, fmt.Errorf("final delta CAP verification failed")
	}
	report.OutputSHA256, err = readerDigest(io.NewSectionReader(f, 0, lr.Size))
	f.Close()
	if err != nil {
		return report, err
	}
	report.OutputBytes = lr.Size
	report.BaseFileSHA256, err = readerDigest(io.NewSectionReader(bf, 0, br.Size))
	if err != nil {
		return report, err
	}
	report.TargetFileSHA256, err = readerDigest(io.NewSectionReader(tf, 0, tr.Size))
	if err != nil {
		return report, err
	}
	if err = os.Remove(container); err != nil {
		return report, err
	}
	if err = os.Remove(stub); err != nil {
		return report, err
	}
	if err = atomicfile.Write(filepath.Join(stage, "validation.json"), func(f *os.File) error { e := json.NewEncoder(f); e.SetIndent("", "  "); return e.Encode(report) }); err != nil {
		return report, err
	}
	if err = atomicfile.PublishDirectory(stage, output); err != nil {
		return report, err
	}
	return report, nil
}
