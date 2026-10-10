package apperror

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestStableCodesAndWrappedCauses(t *testing.T) {
	for _, tt := range []struct {
		err  error
		code int
	}{
		{fmt.Errorf("input: %w", os.ErrNotExist), Input},
		{fmt.Errorf("publish: %w", os.ErrExist), OutputExists},
		{fmt.Errorf("write: %w", syscall.ENOSPC), Space},
		{New(Usage, "missing flag", "Use --help."), Usage},
		{fmt.Errorf("bad CRC"), Validation},
	} {
		var out bytes.Buffer
		if got := Print(&out, tt.err); got != tt.code || out.Len() == 0 {
			t.Fatalf("%v: %d %s", tt.err, got, out.String())
		}
	}
}

func TestWindowsDiskFullCodes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows error numbers")
	}
	for _, errno := range []syscall.Errno{112, 39} {
		if got := Classify(&os.PathError{Op: "write", Path: "firmware", Err: errno}).Code; got != Space {
			t.Fatal(errno, got)
		}
	}
}
