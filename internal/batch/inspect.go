package batch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/autoloader"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qcfm"
)

// ExtractFilesystem extracts exactly one V2 QNX6 partition for read-only
// planning. It rejects ambiguous and unclassified bundles just like Build.
func ExtractFilesystem(input, output string) error {
	f, err := os.Open(input)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	cap, err := autoloader.Read(binio.Reader{ReaderAt: f, Size: st.Size()})
	if err != nil {
		return err
	}
	var selected qcfm.Chunk
	var reader binio.Reader
	count, radios := 0, 0
	for _, span := range cap.Files {
		r := binio.Reader{ReaderAt: io.NewSectionReader(f, span.Offset, span.Size), Size: span.Size}
		c, err := qcfm.Read(r)
		if err != nil {
			return err
		}
		if len(c.V2) == 0 {
			return fmt.Errorf("package CAP input requires V2 partition types")
		}
		ufs, radio := 0, false
		for _, ch := range c.V2 {
			if ch.Type == 5 {
				count++
				ufs++
				selected = ch
				reader = r
			}
			radio = radio || ch.Type == 12
		}
		if ufs > 1 || (ufs > 0 && radio) || (ufs == 0 && !radio) {
			return fmt.Errorf("ambiguous or unclassified CAP bundle")
		}
		if radio {
			radios++
		}
	}
	if count != 1 || radios > 1 {
		return fmt.Errorf("expected exactly one QNX6 partition and at most one radio bundle")
	}
	return atomicfile.Write(output, func(out *os.File) error { return qcfm.Extract(reader, selected, false, out) })
}

// Verification compares the published container contents with the source and
// the checked filesystem, rather than trusting the packer's success status.
type Verification struct {
	OS         string   `json:"osAutoloader"`
	UFSHash    string   `json:"embeddedUFSSHA256"`
	UFSBytes   int64    `json:"embeddedUFSBytes"`
	UFSMatches bool     `json:"embeddedUFSMatchesImage"`
	Partitions int      `json:"partitions"`
	Trailer    bool     `json:"containerTrailerCRCVerified"`
	Stub       bool     `json:"CAPStubAndOverlayPreserved"`
	Preserved  []uint32 `json:"nonUFSPartitionsPreserved"`
	Radio      string   `json:"radioUnchangedSHA256,omitempty"`
	Verifier   string   `json:"verifier"`
	Device     string   `json:"deviceAcceptance"`
}

func spanHash(r io.ReaderAt, off, size int64) (string, error) {
	h := sha256.New()
	_, err := binio.BulkCopyN(h, io.NewSectionReader(r, off, size), size)
	return hex.EncodeToString(h.Sum(nil)), err
}

func chunkHash(r binio.Reader, ch qcfm.Chunk) (string, int64, error) {
	h := sha256.New()
	if err := qcfm.Extract(r, ch, false, h); err != nil {
		return "", 0, err
	}
	var size int64
	if len(ch.Runs) > 0 {
		last := ch.Runs[len(ch.Runs)-1]
		size = (int64(last.Offset) + int64(last.Count)) * int64(ch.BlockSize)
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// VerifyBuild verifies signed QCFM CRCs, CAP stub/overlay preservation, exact
// partition order/content, embedded filesystem equality and unchanged radio.
func VerifyBuild(input, output string, log io.Writer) (Verification, error) {
	report := Verification{Verifier: "native Go content comparison", Device: "not tested"}
	stem := strings.TrimSuffix(filepath.Base(input), filepath.Ext(input))
	report.OS = stem + "_os.exe"
	source, err := os.Open(input)
	if err != nil {
		return report, err
	}
	defer source.Close()
	st, err := source.Stat()
	if err != nil {
		return report, err
	}
	cap, err := autoloader.Read(binio.Reader{ReaderAt: source, Size: st.Size()})
	if err != nil {
		return report, err
	}
	stubHash, err := spanHash(source, 0, cap.SignatureOffset)
	if err != nil {
		return report, err
	}
	var original qcfm.Container
	var originalReader binio.Reader
	var radio *autoloader.File
	for _, span := range cap.Files {
		r := binio.Reader{ReaderAt: io.NewSectionReader(source, span.Offset, span.Size), Size: span.Size}
		c, err := qcfm.Read(r)
		if err != nil {
			return report, err
		}
		ufs, radios := 0, 0
		for _, ch := range c.V2 {
			if ch.Type == 5 {
				ufs++
			}
			if ch.Type == 12 {
				radios++
			}
		}
		if ufs == 1 && radios == 0 && len(original.V2) == 0 {
			original, originalReader = c, r
		} else if ufs == 0 && radios > 0 && radio == nil {
			s := span
			radio = &s
		} else {
			return report, fmt.Errorf("ambiguous or unclassified source bundle")
		}
	}
	if len(original.V2) == 0 {
		return report, fmt.Errorf("missing source filesystem")
	}
	openOutput := func(name string) (*os.File, autoloader.File, error) {
		f, e := os.Open(filepath.Join(output, name))
		if e != nil {
			return nil, autoloader.File{}, e
		}
		fail := func(e error) (*os.File, autoloader.File, error) { f.Close(); return nil, autoloader.File{}, e }
		st, e := f.Stat()
		if e != nil {
			return fail(e)
		}
		h, e := autoloader.Read(binio.Reader{ReaderAt: f, Size: st.Size()})
		if e != nil {
			return fail(e)
		}
		if len(h.Files) != 1 || h.SignatureOffset != cap.SignatureOffset || h.Version != cap.Version {
			return fail(fmt.Errorf("output CAP layout differs: %s", name))
		}
		digest, e := spanHash(f, 0, h.SignatureOffset)
		if e != nil {
			return fail(e)
		}
		if digest != stubHash {
			return fail(fmt.Errorf("CAP stub/overlay changed: %s", name))
		}
		return f, h.Files[0], nil
	}
	f, span, err := openOutput(report.OS)
	if err != nil {
		return report, err
	}
	defer f.Close()
	r := binio.Reader{ReaderAt: io.NewSectionReader(f, span.Offset, span.Size), Size: span.Size}
	c, err := qcfm.Read(r)
	if err != nil {
		return report, err
	}
	if !c.Signed || c.Version != original.Version || len(c.V2) != len(original.V2) {
		return report, fmt.Errorf("output container version, trailer or partition count differs")
	}
	images, err := filepath.Glob(filepath.Join(output, "*.ufs"))
	if err != nil {
		return report, err
	}
	if len(images) != 1 {
		return report, fmt.Errorf("expected exactly one output filesystem")
	}
	for i, ch := range c.V2 {
		before := original.V2[i]
		if ch.Type != before.Type {
			return report, fmt.Errorf("partition order/type changed at %d", i)
		}
		fmt.Fprintf(log, "Verify partition %d/%d (type %d): content SHA256\n", i+1, len(c.V2), ch.Type)
		digest, size, e := chunkHash(r, ch)
		if e != nil {
			return report, e
		}
		if ch.Type == 5 {
			image, e := os.Open(images[0])
			if e != nil {
				return report, e
			}
			st, e := image.Stat()
			if e != nil {
				image.Close()
				return report, e
			}
			imageHash, e := spanHash(image, 0, st.Size())
			image.Close()
			if e != nil {
				return report, e
			}
			if size != st.Size() || digest != imageHash {
				return report, fmt.Errorf("embedded filesystem differs from checked image")
			}
			report.UFSHash, report.UFSBytes = digest, size
		} else {
			oldHash, oldSize, e := chunkHash(originalReader, before)
			if e != nil {
				return report, e
			}
			if size != oldSize || digest != oldHash {
				return report, fmt.Errorf("non-UFS partition %d changed", ch.Type)
			}
			report.Preserved = append(report.Preserved, ch.Type)
		}
	}
	radioName := stem + "_radio.exe"
	if radio != nil {
		fmt.Fprintln(log, "Verify original radio: exact bundle SHA256 and CAP stub")
		rf, rs, e := openOutput(radioName)
		if e != nil {
			return report, e
		}
		defer rf.Close()
		oldHash, e := spanHash(source, radio.Offset, radio.Size)
		if e != nil {
			return report, e
		}
		newHash, e := spanHash(rf, rs.Offset, rs.Size)
		if e != nil {
			return report, e
		}
		if radio.Size != rs.Size || oldHash != newHash {
			return report, fmt.Errorf("radio bundle changed")
		}
		_, e = qcfm.Read(binio.Reader{ReaderAt: io.NewSectionReader(rf, rs.Offset, rs.Size), Size: rs.Size})
		if e != nil {
			return report, e
		}
		report.Radio = oldHash
	} else if _, e := os.Lstat(filepath.Join(output, radioName)); !os.IsNotExist(e) {
		return report, fmt.Errorf("unexpected radio output")
	}
	report.Partitions, report.Trailer, report.Stub, report.UFSMatches = len(c.V2), true, true, true
	return report, nil
}
