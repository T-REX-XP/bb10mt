package atomicfile

import "golang.org/x/sys/unix"

func PublishDirectory(stage, output string) error {
	return unix.RenamexNp(stage, output, unix.RENAME_EXCL)
}

func AvailableSpace(path string) (uint64, error) {
	var st unix.Statfs_t
	err := unix.Statfs(path, &st)
	return st.Bavail * uint64(st.Bsize), err
}
