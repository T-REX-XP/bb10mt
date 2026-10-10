package batch

import (
	"fmt"
	"os"
	"testing"
	"time"
)

type timedLog struct {
	file  *os.File
	start time.Time
}

func (l timedLog) Write(p []byte) (int, error) {
	if _, err := fmt.Fprintf(l.file, "[%.3fs] %s", time.Since(l.start).Seconds(), p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Opt-in real-image profiler: never runs as part of normal tests/CI.
func TestProfileRealBuild(t *testing.T) {
	input, script, output := os.Getenv("BB10MT_PROFILE_INPUT"), os.Getenv("BB10MT_PROFILE_SCRIPT"), os.Getenv("BB10MT_PROFILE_OUTPUT")
	if input == "" || script == "" || output == "" {
		t.Skip("set the three BB10MT_PROFILE_* paths for an offline profile")
	}
	log, err := os.OpenFile(output+".log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	start := time.Now()
	if err = Build(input, script, output, timedLog{log, start}); err != nil {
		t.Fatal(err)
	}
	t.Logf("native verified batch: %.3fs", time.Since(start).Seconds())
}
