package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
)

func launch(app string, args, env []string) error {
	cmd := exec.Command(app, args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Console control events reach both processes. Let the application clean up.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	return err
}
