package atomicfile

import (
	"golang.org/x/sys/windows"
	"os"
)

// Windows directory renames fail when the destination already exists.
func PublishDirectory(stage, output string) error { return os.Rename(stage, output) }

func AvailableSpace(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var available uint64
	err = windows.GetDiskFreeSpaceEx(p, &available, nil, nil)
	return available, err
}
