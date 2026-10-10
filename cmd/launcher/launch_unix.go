//go:build linux || darwin

package main

import "syscall"

func launch(app string, args, env []string) error { return syscall.Exec(app, args, env) }
