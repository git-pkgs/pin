package cli

import (
	"encoding/json"
	"fmt"

	pin "github.com/git-pkgs/pin"
	"github.com/spf13/cobra"
)

const exitVerifyFailed = 4

func newVerifyCmd() *cobra.Command {
	var opts pin.VerifyOptions
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Re-hash files on disk against the lockfile",
		Long: `Walk the manifest's out: directory, re-hash each vendored file, and
compare against the integrity recorded in pin.lock. Exits 4 on drift or
missing files.

With --strict, each npm package's tarball is also re-fetched and the
per-file SHA-384 is re-derived from scratch. Anchors the lockfile back
to what the registry actually published. Forge and url sources are
skipped under --strict because their per-file hash is the anchor.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := pin.Verify(opts)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				_ = enc.Encode(res)
			} else {
				fmt.Fprintln(out, res.Summary())
				for _, m := range res.Missing {
					fmt.Fprintf(out, "  missing: %s\n", m)
				}
				for _, d := range res.Drifted {
					fmt.Fprintf(out, "  drifted: %s\n    expected %s\n    actual   %s\n", d.Out, d.Expected, d.Actual)
				}
				for _, e := range res.Extra {
					fmt.Fprintf(out, "  extra:   %s\n", e)
				}
			}
			if res.Failed() || (opts.Strict && len(res.Extra) > 0) {
				return &exitError{code: exitVerifyFailed, msg: "verify failed"}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.Dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&opts.Lock, "lock", pin.DefaultLock, "lockfile path")
	cmd.Flags().BoolVar(&opts.Strict, "strict", false, "treat extra files as failures and re-derive each npm asset's hash from the registry tarball (slow; anchors the lockfile back to what npm published)")
	cmd.Flags().StringVar(&opts.RegistryURL, "registry", "", "npm registry base URL (for --strict re-derive)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	return cmd
}

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }
func (e *exitError) ExitCode() int { return e.code }
