//go:build !linux

package main

func helperEnvironment(_ string, env []string) []string { return env }
