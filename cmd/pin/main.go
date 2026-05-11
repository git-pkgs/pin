package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/git-pkgs/pin/internal/cli"
)

type exitCoder interface {
	error
	ExitCode() int
}

func main() {
	if err := cli.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if ec, ok := errors.AsType[exitCoder](err); ok {
			os.Exit(ec.ExitCode())
		}
		os.Exit(1)
	}
}
