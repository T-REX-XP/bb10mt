package binio

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type measuredReader struct {
	remaining      int64
	calls, largest int
}

func (r *measuredReader) Read(p []byte) (int, error) {
	r.calls++
	if len(p) > r.largest {
		r.largest = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.remaining)
	clear(p[:n])
	r.remaining -= n
	return int(n), nil
}

type badWriter struct{}

func (badWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestBulkCopyNBounded(t *testing.T) {
	for _, n := range []int64{-1, 0, 1, 32 << 10, 4 << 20, 5 << 20} {
		r := &measuredReader{remaining: 8 << 20}
		got, err := BulkCopyN(io.Discard, r, n)
		if got != max(n, 0) || err != nil || r.remaining != (8<<20)-max(n, 0) {
			t.Fatalf("n=%d got=%d remaining=%d err=%v", n, got, r.remaining, err)
		}
		if n >= 4<<20 && (r.largest < 4<<20 || r.calls > 2) {
			t.Fatalf("small I/O: %+v", r)
		}
	}
}
func TestBulkCopyNShortSource(t *testing.T) {
	var dst bytes.Buffer
	n, err := BulkCopyN(&dst, bytes.NewBufferString("abc"), 5)
	if n != 3 || !errors.Is(err, io.EOF) || dst.String() != "abc" {
		t.Fatal(n, err, dst.String())
	}
}
func TestBulkCopyNShortWrite(t *testing.T) {
	n, err := BulkCopyN(badWriter{}, bytes.NewBufferString("abc"), 3)
	if n != 2 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(n, err)
	}
}

func TestBulkCopyReducesReadCalls(t *testing.T) {
	baseline := &measuredReader{remaining: 8 << 20}
	if _, err := io.CopyN(writerOnly{io.Discard}, readerOnly{baseline}, 8<<20); err != nil {
		t.Fatal(err)
	}
	bulk := &measuredReader{remaining: 8 << 20}
	if _, err := BulkCopyN(io.Discard, bulk, 8<<20); err != nil {
		t.Fatal(err)
	}
	if baseline.calls != 256 || bulk.calls != 2 {
		t.Fatalf("read calls: baseline %d, bulk %d", baseline.calls, bulk.calls)
	}
}
