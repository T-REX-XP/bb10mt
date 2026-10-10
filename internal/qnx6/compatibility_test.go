package qnx6

import (
	"strings"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

func TestCheckRejectsBB10InodeMetadataRegression(t *testing.T) {
	for _, kind := range []string{"zero status", "unaligned directory"} {
		t.Run(kind, func(t *testing.T) {
			e, _ := editor(t)
			n, _, err := e.Resolve("/")
			if err != nil {
				t.Fatal(err)
			}
			want := "has zero status"
			if kind == "zero status" {
				n.Raw[101] = 0
			} else {
				// The previous writer stored used entry bytes rather than the
				// complete directory block. Keep the entries intact so this
				// cannot fail merely because of a missing dot or child entry.
				binio.Put64(n.Raw, 0, 96)
				want = "is not block aligned"
			}
			if err = e.setNode(n); err != nil {
				t.Fatal(err)
			}
			report, err := e.Check()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(report.Errors, "\n"), want) {
				t.Fatalf("corrupt %s accepted: %v", kind, report.Errors)
			}
			if err = e.Commit(); err == nil {
				t.Fatalf("commit accepted corrupt %s", kind)
			}
		})
	}
}
