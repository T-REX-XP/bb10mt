package atomicfile

import "os"

// Windows directory renames fail when the destination already exists.
func PublishDirectory(stage, output string) error { return os.Rename(stage, output) }
