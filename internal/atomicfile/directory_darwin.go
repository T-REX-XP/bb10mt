package atomicfile

import "golang.org/x/sys/unix"

func PublishDirectory(stage, output string) error {
	return unix.RenamexNp(stage, output, unix.RENAME_EXCL)
}
