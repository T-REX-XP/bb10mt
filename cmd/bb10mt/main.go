package main

import (
	"fmt"
	"github.com/bb10root/bb10mt/internal/cli"
	"os"
)

var version = "dev-go"

func main() {
	if e := cli.Run(os.Args[1:], os.Stdout, os.Stderr, version); e != nil {
		fmt.Fprintln(os.Stderr, "error:", e)
		os.Exit(1)
	}
}
