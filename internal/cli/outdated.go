package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	pin "github.com/git-pkgs/pin"
	"github.com/spf13/cobra"
)

func newOutdatedCmd() *cobra.Command {
	var opts pin.OutdatedOptions
	var jsonOut, exitZero bool
	cmd := &cobra.Command{
		Use:   "outdated",
		Short: "Compare locked versions against the registry's latest",
		RunE: func(cmd *cobra.Command, args []string) error {
			reports, err := pin.Outdated(cmd.Context(), opts)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				_ = enc.Encode(reports)
			} else {
				const pad = 2
				tw := tabwriter.NewWriter(out, 0, 0, pad, ' ', 0)
				fmt.Fprintln(tw, "NAME\tLOCKED\tLATEST\tAGE\tSTATUS")
				for _, r := range reports {
					age := "-"
					if r.AgeDays >= 0 {
						age = fmt.Sprintf("%dd", r.AgeDays)
					}
					status := r.Severity()
					if r.Deprecated != "" {
						status = "deprecated: " + r.Deprecated
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.Locked, r.Latest, age, status)
				}
				_ = tw.Flush()
			}
			if exitZero {
				return nil
			}
			if code := pin.OutdatedExitCode(reports); code != 0 {
				return &exitError{code: code, msg: fmt.Sprintf("outdated: %d package(s) need attention", countAttention(reports))}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.Dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&opts.Lock, "lock", pin.DefaultLock, "lockfile path")
	cmd.Flags().StringVar(&opts.RegistryURL, "registry", "", "npm registry base URL")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	cmd.Flags().BoolVar(&exitZero, "exit-zero", false, "exit 0 even if packages are behind")
	return cmd
}

func countAttention(reports []pin.OutdatedReport) int {
	n := 0
	for _, r := range reports {
		if r.Severity() != pin.SeverityOK {
			n++
		}
	}
	return n
}
