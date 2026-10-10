// Package batch implements the native, offline firmware build transaction.
package batch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/autoloader"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qcfm"
	"github.com/bb10root/bb10mt/internal/qnx6"
)

type Report struct {
	Input      string   `json:"input"`
	OS         string   `json:"osAutoloader"`
	Radio      string   `json:"radioAutoloader,omitempty"`
	Partitions int      `json:"partitions"`
	Checks     []string `json:"checks"`
}
type bundle struct {
	span      autoloader.File
	container qcfm.Container
	index     int
}

func Build(input, script, output string, log io.Writer) error {
	return BuildWithOptions(input, script, output, log, Options{})
}

type Options struct{ Compact bool }

func BuildWithOptions(input, script, output string, log io.Writer, opt Options) error {
	// Validate script syntax before spending disk space on extraction.
	data, err := os.ReadFile(script)
	if err != nil {
		return err
	}
	if _, err = qnx6.ParseScript(data); err != nil {
		return err
	}
	return BuildWithTransform(input, output, log, opt, func(source, target string) error {
		return qnx6.Script(source, script, target, log)
	}, []string{"script fail-fast", "post-script filesystem and pushed SHA256"})
}

// BuildWithTransform reuses the verified CAP transaction for a declarative
// image transform. The callback must publish a new, verified target image.
func BuildWithTransform(input, output string, log io.Writer, opt Options, transform func(string, string) error, checks []string) error {
	started := time.Now()
	progress := func(format string, args ...any) {
		fmt.Fprintf(log, "[bb10mt +%.1fs] %s\n", time.Since(started).Seconds(), fmt.Sprintf(format, args...))
	}
	progress("Stage 1/8: validating input CAP and source container CRCs")
	if transform == nil {
		return fmt.Errorf("image transform required")
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output already exists: %s: %w", output, os.ErrExist)
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.Open(input)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	r := binio.Reader{ReaderAt: f, Size: st.Size()}
	cap, err := autoloader.Read(r)
	if err != nil {
		return err
	}
	var osBundle *bundle
	var radio *bundle
	for i, span := range cap.Files {
		section := io.NewSectionReader(f, span.Offset, span.Size)
		c, err := qcfm.Read(binio.Reader{ReaderAt: section, Size: span.Size})
		if err != nil {
			return fmt.Errorf("bundle %d: %w", i, err)
		}
		if len(c.V2) == 0 {
			return fmt.Errorf("batch requires V2 partition types (V1-only input unsupported)")
		}
		hasUFS, hasRadio := false, false
		for _, ch := range c.V2 {
			hasUFS = hasUFS || ch.Type == 5
			hasRadio = hasRadio || ch.Type == 12
		}
		b := &bundle{span, c, i}
		if hasUFS {
			if osBundle != nil || hasRadio {
				return fmt.Errorf("ambiguous OS bundle")
			}
			osBundle = b
		} else if hasRadio {
			if radio != nil {
				return fmt.Errorf("ambiguous radio bundle")
			}
			radio = b
		} else {
			return fmt.Errorf("unclassified bundle %d; refusing to discard it", i)
		}
	}
	if osBundle == nil {
		return fmt.Errorf("no OS filesystem partition")
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".bb10mt-batch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	stem := strings.TrimSuffix(filepath.Base(input), filepath.Ext(input))
	capPath := filepath.Join(stage, "cap.exe")
	if err = autoloader.ExtractCAP(input, capPath); err != nil {
		return err
	}
	partitions := []qcfm.Input{}
	list := []string{}
	imagePath := ""
	section := io.NewSectionReader(f, osBundle.span.Offset, osBundle.span.Size)
	progress("Stage 2/8: extracting %d OS partitions", len(osBundle.container.V2))
	cr := binio.Reader{ReaderAt: section, Size: osBundle.span.Size}
	for i, ch := range osBundle.container.V2 {
		progress("Extract partition %d/%d (type %d)", i+1, len(osBundle.container.V2), ch.Type)
		ext := qcfm.Extension(ch.Type)
		if ext == ".unk" {
			return fmt.Errorf("unsupported partition type %d", ch.Type)
		}
		name := fmt.Sprintf("%s.%d.%d%s", stem, osBundle.index, i, ext)
		target := filepath.Join(stage, name)
		if err = atomicfile.Write(target, func(out *os.File) error { return qcfm.Extract(cr, ch, false, out) }); err != nil {
			return err
		}
		in := qcfm.Input{Path: target}
		row := name
		if osBundle.container.Version == 3 {
			old := osBundle.container.V1[i]
			if len(old.Runs) > 0 && len(ch.Runs) > 0 {
				in.Delta = old.Runs[0].Offset - ch.Runs[0].Offset
			}
			in.Flags = old.Flags
			row += fmt.Sprintf("=%d,%d", in.Delta, in.Flags)
		}
		partitions = append(partitions, in)
		list = append(list, row)
		if ch.Type == 5 {
			if imagePath != "" {
				return fmt.Errorf("multiple QNX6 partitions")
			}
			imagePath = target
		}
	}
	if imagePath == "" {
		return fmt.Errorf("missing QNX6 partition")
	}
	repaired := filepath.Join(stage, ".source-checked.ufs")
	progress("Stage 3/8: checking source filesystem and repairing names/free counts")
	if _, err = qnx6.Repair(imagePath, repaired); err != nil {
		return fmt.Errorf("source image check: %w", err)
	}
	patched := filepath.Join(stage, ".patched.ufs")
	progress("Stage 4/8: applying patch and verifying filesystem/payloads")
	if err = transform(repaired, patched); err != nil {
		return err
	}
	if err = os.Remove(repaired); err != nil {
		return err
	}
	if err = os.Remove(imagePath); err != nil {
		return err
	}
	if err = os.Rename(patched, imagePath); err != nil {
		return err
	}
	if opt.Compact {
		compacted := filepath.Join(stage, ".compacted.ufs")
		if _, err = qnx6.Compact(imagePath, compacted); err != nil {
			return err
		}
		if err = os.Remove(imagePath); err != nil {
			return err
		}
		if err = os.Rename(compacted, imagePath); err != nil {
			return err
		}
		// QCFM stores full blocks. Keep the delivered loose image identical to
		// its embedded representation, including the erased final block tail.
		image, e := os.OpenFile(imagePath, os.O_WRONLY|os.O_APPEND, 0)
		if e != nil { return e }
		st,e := image.Stat()
		if e == nil {
			padding := (qcfm.BlockSize-st.Size()%qcfm.BlockSize)%qcfm.BlockSize
			_,e = image.Write(bytes.Repeat([]byte{0xff},int(padding)))
		}
		closeErr := image.Close()
		if e != nil { return e }; if closeErr != nil { return closeErr }
	}
	if err = os.WriteFile(filepath.Join(stage, stem+".lst"), []byte(strings.Join(list, "\n")+"\n"), 0644); err != nil {
		return err
	}
	version := osBundle.container.Version
	packed := filepath.Join(stage, stem+".unsigned")
	progress("Stage 5/8: scanning sparse runs and packing QCFM with CRC verification")
	if err = qcfm.Pack(packed, partitions, qcfm.Options{Version: version, Sign: true}); err != nil {
		return err
	}
	osPath := filepath.Join(stage, stem+"_os.exe")
	progress("Stage 6/8: creating and validating the OS autoloader")
	if err = autoloader.Create(osPath, capPath, []string{packed}, cap.Version); err != nil {
		return err
	}
	report := Report{Input: input, OS: filepath.Base(osPath), Partitions: len(partitions), Checks: []string{"source container structure/CRC", "source filesystem and name repair", "packed container structure/CRC", "final CAP offset table"}}
	report.Checks = append(report.Checks, checks...)
	if opt.Compact {
		report.Checks = append(report.Checks, "compaction filesystem and all allocated inode SHA256")
	}
	if radio != nil {
		progress("Stage 7/8: preserving and validating the original radio bundle")
		radioPath := filepath.Join(stage, stem+".radio.signed")
		if err = atomicfile.Write(radioPath, func(out *os.File) error {
			_, err := binio.BulkCopyN(out, io.NewSectionReader(f, radio.span.Offset, radio.span.Size), radio.span.Size)
			return err
		}); err != nil {
			return err
		}
		loader := filepath.Join(stage, stem+"_radio.exe")
		if err = autoloader.Create(loader, capPath, []string{radioPath}, cap.Version); err != nil {
			return err
		}
		report.Radio = filepath.Base(loader)
	}
	if radio == nil {
		progress("Stage 7/8: input has no radio bundle")
	}
	if err = os.Remove(capPath); err != nil {
		return err
	}
	if err = atomicfile.Write(filepath.Join(stage, "build-report.json"), func(f *os.File) error {
		encoder := json.NewEncoder(f)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}); err != nil {
		return err
	}
	progress("Stage 8/8: publishing checked firmware directory")
	err = atomicfile.PublishDirectory(stage, output)
	if err == nil {
		progress("Build complete: %s", output)
	}
	return err
}
