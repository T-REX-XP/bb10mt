package atomicfile

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Windows directory renames fail when the destination already exists.
// Brief directory-reader locks can also deny a rename after all our handles
// are closed. Retry those errors for at most 1.575 seconds, without replacing
// an existing destination or masking permanent failures.
func PublishDirectory(stage, output string) error {
	err := os.Rename(stage, output)
	for attempt := 0; attempt < 6 && err != nil; attempt++ {
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return err
		}
		if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
			return err
		}
		time.Sleep((25 * time.Millisecond) << attempt)
		err = os.Rename(stage, output)
	}
	return err
}

func AvailableSpace(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var available uint64
	err = windows.GetDiskFreeSpaceEx(p, &available, nil, nil)
	return available, err
}
