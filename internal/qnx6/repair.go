package qnx6

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
)

// RepairNames repairs a copy only after inspecting every allocated directory.
// Directory inode checksums must be disabled (enforced by Open). All other
// bytes, including superblocks, payloads and permissions, remain unchanged.
func RepairNames(input, output string) (Audit, error) {
	var audit Audit
	f, e := os.Open(input)
	if e != nil {
		return audit, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return audit, e
	}
	r := binio.Reader{ReaderAt: f, Size: st.Size()}
	im, e := Open(r)
	if e != nil {
		return audit, e
	}
	audit, e = im.AuditNames()
	if e != nil {
		return audit, e
	}
	e = atomicfile.Write(output, func(out *os.File) error {
		if _, e := binio.BulkCopyN(out, io.NewSectionReader(f, 0, r.Size), r.Size); e != nil {
			return e
		}
		b := make([]byte, 4)
		for _, v := range audit.Issues {
			binio.Put32(b, 0, v.Expected)
			if _, e := out.WriteAt(b, v.Offset); e != nil {
				return e
			}
		}
		check, e := Open(binio.Reader{ReaderAt: out, Size: r.Size})
		if e != nil {
			return e
		}
		a, e := check.AuditNames()
		if e != nil {
			return e
		}
		if len(a.Issues) != 0 {
			return fmt.Errorf("name checksum repair did not verify")
		}
		return nil
	})
	return audit, e
}

// Repair fixes only name checksums and free counters derived from fully checked
// metadata. It refuses block overlap, link-count and structural errors.
func Repair(input, output string) (CheckReport, error) {
	var report CheckReport
	f, err := os.Open(input)
	if err != nil {
		return report, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return report, err
	}
	r := binio.Reader{ReaderAt: f, Size: st.Size()}
	im, err := Open(r)
	if err != nil {
		return report, err
	}
	report, err = im.Check()
	if err != nil {
		return report, err
	}
	for _, problem := range report.Errors {
		if !strings.HasPrefix(problem, "bad long-name checksum ") && problem != "free block count mismatch" && problem != "free inode count mismatch" {
			return report, fmt.Errorf("automatic repair refused: %s", problem)
		}
	}
	err = atomicfile.Write(output, func(out *os.File) error {
		if _, err := binio.BulkCopyN(out, io.NewSectionReader(f, 0, r.Size), r.Size); err != nil {
			return err
		}
		b := make([]byte, 4)
		for _, v := range report.Audit.Issues {
			binio.Put32(b, 0, v.Expected)
			if _, err := out.WriteAt(b, v.Offset); err != nil {
				return err
			}
		}
		binio.Put32(im.Super, 56, im.Inodes-report.UsedInodes)
		binio.Put32(im.Super, 64, report.ExpectedFreeBlocks)
		binio.Put32(im.Super, 4, CRC(im.Super[8:]))
		if _, err := out.WriteAt(im.Super, im.SuperOffset); err != nil {
			return err
		}
		check, err := Open(binio.Reader{ReaderAt: out, Size: r.Size})
		if err != nil {
			return err
		}
		a, err := check.Check()
		if err != nil {
			return err
		}
		if len(a.Errors) != 0 {
			return fmt.Errorf("repaired image still has errors: %s", a.Errors[0])
		}
		return nil
	})
	return report, err
}
