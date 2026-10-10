//go:build !linux

package qnx6

import (
	"context"
	"fmt"
	"io"
)

func Mount(ctx context.Context, input, output, mountpoint string, opt MountOptions, log io.Writer) error {
	return fmt.Errorf("QNX6 FUSE mounting is supported on Linux only")
}
