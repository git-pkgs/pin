// Regenerates the troff man pages for every pin subcommand under
// ./man/. Invoked by goreleaser as a before: hook so each release
// archive ships up-to-date man pages, and runnable by hand during
// development:
//
//	go run ./scripts/generate-man
package main

import (
	"log"
	"os"
	"time"

	"github.com/spf13/cobra/doc"

	"github.com/git-pkgs/pin/internal/cli"
)

const dirPerm = 0o755

func main() {
	if err := os.MkdirAll("man", dirPerm); err != nil {
		log.Fatal(err)
	}

	now := time.Now()
	header := &doc.GenManHeader{
		Title:   "PIN",
		Section: "1",
		Date:    &now,
		Source:  "pin",
		Manual:  "Pin Manual",
	}

	if err := doc.GenManTree(cli.Root(), header, "man"); err != nil {
		log.Fatal(err)
	}
}
