package batch

import (
	"fmt"
	"io"
	"os"

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
