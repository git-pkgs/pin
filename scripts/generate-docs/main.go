// Regenerates a flat tree of Markdown reference pages — one per pin
// subcommand — under ./docs/reference/. The output is suitable for
// publishing directly (each file has a YAML front matter block that
// Hugo and similar static-site generators consume). Invoked by
// goreleaser as a before: hook; also runnable by hand:
//
//	go run ./scripts/generate-docs
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/git-pkgs/pin/internal/cli"
)

const (
	dirPerm  = 0o755
	filePerm = 0o644
)

func main() {
	dir := "docs/reference"
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		log.Fatal(err)
	}
	if err := genTree(cli.Root(), dir); err != nil {
		log.Fatal(err)
	}
}

func genTree(cmd *cobra.Command, dir string) error {
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := genTree(c, dir); err != nil {
			return err
		}
	}

	basename := strings.ReplaceAll(cmd.CommandPath(), " ", "_") + ".md"
	filename := filepath.Join(dir, basename)

	name := strings.TrimSuffix(basename, ".md")
	title := strings.ReplaceAll(name, "_", " ")
	weight := 10
	if name == "pin" {
		weight = 1
	}

	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "---\ntitle: %q\ndescription: %q\nweight: %d\n---\n", title, cmd.Short, weight)
	if err := genMarkdown(cmd, buf); err != nil {
		return err
	}
	return os.WriteFile(filename, buf.Bytes(), filePerm)
}

func genMarkdown(cmd *cobra.Command, buf *bytes.Buffer) error {
	cmd.InitDefaultHelpCmd()
	cmd.InitDefaultHelpFlag()

	buf.WriteString("\n" + cmd.Short + "\n")
	if len(cmd.Long) > 0 {
		buf.WriteString("\n" + cmd.Long + "\n")
	}
	if cmd.Runnable() {
		fmt.Fprintf(buf, "\n```\n%s\n```\n", cmd.UseLine())
	}
	if len(cmd.Example) > 0 {
		buf.WriteString("\n### Examples\n\n")
		fmt.Fprintf(buf, "```\n%s\n```\n", cmd.Example)
	}

	flags := cmd.NonInheritedFlags()
	flags.SetOutput(buf)
	if flags.HasAvailableFlags() {
		buf.WriteString("\n### Options\n\n```\n")
		flags.PrintDefaults()
		buf.WriteString("```\n")
	}

	parentFlags := cmd.InheritedFlags()
	parentFlags.SetOutput(buf)
	if parentFlags.HasAvailableFlags() {
		buf.WriteString("\n### Options inherited from parent commands\n\n```\n")
		parentFlags.PrintDefaults()
		buf.WriteString("```\n")
	}
	return nil
}
