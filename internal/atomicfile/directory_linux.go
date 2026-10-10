package atomicfile

import "golang.org/x/sys/unix"

// PublishDirectory atomically renames a staged directory without replacing a
// concurrently created destination, including an empty directory.
func PublishDirectory(stage, output string) error {
	return unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE)
}

func AvailableSpace(path string) (uint64, error) {
	var st unix.Statfs_t
	err := unix.Statfs(path, &st)
	return st.Bavail * uint64(st.Bsize), err
}
