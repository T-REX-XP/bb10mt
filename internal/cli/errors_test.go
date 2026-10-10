package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/apperror"
)

func TestStableCommandErrorCodes(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "invalid.signed")
	os.WriteFile(bad, []byte("invalid"), 0600)
	for _, tt := range []struct {
		args []string
		code int
	}{
		{[]string{"unknown"}, 2},
		{[]string{"batch"}, 2},
		{[]string{"batch", "--bad-option"}, 2},
		{[]string{"verify", "-c", filepath.Join(dir, "missing")}, 3},
		{[]string{"verify", "-c", bad}, 8},
		{[]string{"batch", "-o", dir}, 4},
	} {
		var out, stderr bytes.Buffer
		err := Run(tt.args, &out, &stderr, "test")
		if err == nil || apperror.Classify(err).Code != tt.code {
			t.Fatalf("%v: %v", tt.args, err)
		}
	}
}
