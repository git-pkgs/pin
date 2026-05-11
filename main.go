package main

import (
	"fmt"
	"os"

	"github.com/git-pkgs/pin/internal/cli"
)

func main() {
	if err := cli.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
