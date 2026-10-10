package qnx6

import (
	"fmt"
	"sort"
	"strings"
)

const DefaultBlacklist = "com.twitter com.evernote com.linkedin com.tcs.maps com.rim.bb.app.facebook com.rim.bb.app.retaildemoshim sys.socialconnect.linkedin sys.socialconnect.twitter sys.socialconnect.youtube sys.socialconnect.facebook sys.cfs.box sys.cfs.dropbox sys.uri.youtube sys.weather sys.appworld sys.bbm"

// DebloatList generates the legacy deferred-uninstall package list. The Android
// runtime and shell remain protected. It does not remove applications itself.
func DebloatList(names []string) ([]byte, error) {
	if names == nil {
		names = strings.Fields(DefaultBlacklist)
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || len(name) > 255 {
			return nil, fmt.Errorf("invalid debloat package")
		}
		for _, r := range name {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
				return nil, fmt.Errorf("invalid debloat package %q", name)
			}
		}
		if name == "." || name == ".." {
			return nil, fmt.Errorf("invalid debloat package")
		}
		if name != "sys.android" && name != "sys.android.shell" {
			seen[name] = true
		}
	}
	var rows []string
	for name := range seen {
		rows = append(rows, name)
	}
	sort.Strings(rows)
	if len(rows) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(rows, "\n") + "\n"), nil
}
