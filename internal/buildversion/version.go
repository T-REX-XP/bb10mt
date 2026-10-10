// Package buildversion reserves increasing versions before compiler invocation.
package buildversion

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var pattern = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)-go\.(\d+)$`)
var idPattern = regexp.MustCompile(`^[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*$`)

type Record struct {
	Version  string `json:"version"`
	Base     string `json:"base"`
	Previous string `json:"previous"`
	BuildID  string `json:"buildID,omitempty"`
}

func parse(s string) ([4]uint64, error) {
	var parts [4]uint64
	m := pattern.FindStringSubmatch(s)
	if m == nil {
		return parts, fmt.Errorf("expected vMAJOR.MINOR.PATCH-go.NUMBER, got %q", s)
	}
	for i := range parts {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return parts, err
		}
		parts[i] = n
	}
	return parts, nil
}
func compare(a, b [4]uint64) int {
	for i := range a {
		if a[i] > b[i] {
			return 1
		}
		if a[i] < b[i] {
			return -1
		}
	}
	return 0
}

// Reserve consumes a version even if the later build fails. Never reset the
// ignored state file to reuse an old version. A directory lock serializes builds.
func Reserve(seedPath, statePath, requested, buildID string) (Record, error) {
	var record Record
	if buildID != "" && !idPattern.MatchString(buildID) {
		return record, fmt.Errorf("invalid build ID")
	}
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		return record, err
	}
	previous := strings.TrimSpace(string(seed))
	last, err := parse(previous)
	if err != nil {
		return record, err
	}
	if err = os.Mkdir(statePath+".lock", 0700); err != nil {
		return record, fmt.Errorf("version allocator busy or inaccessible (%s.lock); check for another build before removing a stale lock: %w", statePath, err)
	}
	defer os.Remove(statePath + ".lock")
	if info, statErr := os.Lstat(statePath); statErr == nil {
		if !info.Mode().IsRegular() {
			return record, fmt.Errorf("version state must be a regular file")
		}
		data, readErr := os.ReadFile(statePath)
		if readErr != nil {
			return record, readErr
		}
		var prior Record
		if err = json.Unmarshal(data, &prior); err != nil {
			return record, fmt.Errorf("corrupt version state: %w", err)
		}
		stored, parseErr := parse(prior.Base)
		if parseErr != nil {
			return record, parseErr
		}
		if compare(stored, last) > 0 {
			last, previous = stored, prior.Base
		}
	} else if !os.IsNotExist(statErr) {
		return record, statErr
	}
	if requested == "" {
		if last[3] == ^uint64(0) {
			return record, fmt.Errorf("build counter exhausted")
		}
		requested = fmt.Sprintf("v%d.%d.%d-go.%d", last[0], last[1], last[2], last[3]+1)
	} else {
		next, parseErr := parse(requested)
		if parseErr != nil {
			return record, parseErr
		}
		if compare(next, last) <= 0 {
			return record, fmt.Errorf("version %s must be greater than last allocated %s; omit --version to allocate the next number", requested, previous)
		}
	}
	record = Record{Version: requested, Base: requested, Previous: previous, BuildID: buildID}
	if buildID != "" {
		record.Version += "+build." + buildID
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return record, err
	}
	f, err := os.CreateTemp(filepath.Dir(statePath), ".bb10mt-version-*")
	if err != nil {
		return record, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return record, err
	}
	if closeErr != nil {
		return record, closeErr
	}
	if err = os.Rename(f.Name(), statePath); err != nil {
		return record, err
	}
	return record, nil
}
