package cli

import (
	"encoding/json"
	"fmt"
	"strings"
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
		Long: `Report each locked package against the registry's current state.
Severity tiers: yanked (exit 9) > provenance-downgrade > deprecated >
behind > ok. Behind / deprecated / yanked exit non-zero unless
--exit-zero is set.

The NOTES column surfaces informational signals that don't affect
exit code: license drift between locked and latest, packages whose
last publish is older than a year (unmaintained), and packages whose
latest version gained a SLSA attestation since the lockfile was
written (provenance available).`,
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
				fmt.Fprintln(tw, "NAME\tLOCKED\tLATEST\tAGE\tSTATUS\tNOTES")
				for _, r := range reports {
					age := "-"
					if r.AgeDays >= 0 {
						age = fmt.Sprintf("%dd", r.AgeDays)
					}
					status := r.Severity()
					if r.Deprecated != "" {
						status = "deprecated: " + r.Deprecated
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
						r.Name, r.Locked, r.Latest, age, status, notes(r))
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

// notes formats the informational signals on an OutdatedReport that
// don't fit into Severity: license drift, unmaintained packages, and
// provenance gains/losses. Empty when there's nothing to say.
func notes(r pin.OutdatedReport) string {
	var ns []string
	if r.LicenseChange {
		ns = append(ns, fmt.Sprintf("license: %s → %s", r.LicenseLocked, r.LicenseLatest))
	}
	if r.Unmaintained {
		ns = append(ns, "unmaintained")
	}
	if r.ProvenanceUpgrade {
		ns = append(ns, "provenance available")
	}
	return strings.Join(ns, "; ")
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
