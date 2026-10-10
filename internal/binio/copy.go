package binio

import (
	"io"
	"sync"
)

// BulkCopyN copies an exact bounded span with a reusable 4 MiB buffer. Hiding
// optional fast-path interfaces is intentional: os.File.ReadFrom otherwise
// falls back to 32 KiB reads for SectionReader on Windows, causing tens of
// thousands of expensive ReadFile calls per firmware image.
var copyBuffers = sync.Pool{New: func() any { return make([]byte, 4<<20) }}

type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

func BulkCopyN(dst io.Writer, src io.Reader, n int64) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	buffer := copyBuffers.Get().([]byte)
	defer copyBuffers.Put(buffer)
	copied, err := io.CopyBuffer(writerOnly{dst}, readerOnly{io.LimitReader(src, n)}, buffer)
	if copied == n {
		return copied, nil
	}
	if err == nil {
		err = io.EOF
	}
	return copied, err
}
