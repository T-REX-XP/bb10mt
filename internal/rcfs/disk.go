package rcfs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/vmdk"
)

// ModifyDisk locates the RCFS partition by its header, rather than the legacy
// hardcoded parts[1] index. Both partition and disk are disposable working copies.
func ModifyDisk(input, output, script string) (ModifyReport, error) {
	var report ModifyReport
	f, err := os.Open(input)
	if err != nil {
		return report, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return report, err
	}
	err = atomicfile.Write(output, func(work *os.File) error {
		if _, err := io.CopyN(work, io.NewSectionReader(f, 0, st.Size()), st.Size()); err != nil {
			return err
		}
		disk, err := vmdk.Open(binio.Reader{ReaderAt: work, Size: st.Size()})
		if err != nil {
			return err
		}
		parts, err := disk.Partitions()
		if err != nil {
			return err
		}
		var matches []vmdk.Partition
		for _, part := range parts {
			b := make([]byte, 16)
			if _, err = disk.ReadAt(b, part.Offset); err != nil {
				return err
			}
			if string(b[:4]) == "rimh" && string(b[8:16]) == "fs-os   " {
				matches = append(matches, part)
			}
		}
		if len(matches) != 1 {
			return fmt.Errorf("expected one RCFS partition, found %d", len(matches))
		}
		part := matches[0]
		tmp, err := os.MkdirTemp(filepath.Dir(output), ".bb10mt-rcfs-part-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		source := filepath.Join(tmp, "source.rcfs")
		patched := filepath.Join(tmp, "patched.rcfs")
		if err = atomicfile.Write(source, func(out *os.File) error {
			_, err := io.CopyN(out, io.NewSectionReader(disk, part.Offset, part.Size), part.Size)
			return err
		}); err != nil {
			return err
		}
		report, err = Modify(source, patched, script, "")
		if err != nil {
			return err
		}
		changed, err := os.Open(patched)
		if err != nil {
			return err
		}
		defer changed.Close()
		h := sha256.New()
		buf := make([]byte, 1<<20)
		position := part.Offset
		for {
			n, err := changed.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				if _, err = disk.WriteAt(work, buf[:n], position); err != nil {
					return err
				}
				position += int64(n)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		if position != part.Offset+part.Size {
			return fmt.Errorf("partition length changed")
		}
		actual := sha256.New()
		if _, err = io.CopyN(actual, io.NewSectionReader(disk, part.Offset, part.Size), part.Size); err != nil {
			return err
		}
		if !bytes.Equal(actual.Sum(nil), h.Sum(nil)) {
			return fmt.Errorf("VMDK partition read-back hash mismatch")
		}
		return nil
	})
	return report, err
}
