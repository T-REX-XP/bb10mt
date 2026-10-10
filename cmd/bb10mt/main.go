package main

import (
	"github.com/bb10root/bb10mt/internal/apperror"
	"github.com/bb10root/bb10mt/internal/cli"
	"os"
)

var version = "dev-go"

func main() {
	if e := cli.Run(os.Args[1:], os.Stdout, os.Stderr, version); e != nil {
		os.Exit(apperror.Print(os.Stderr, e))
	}
}
