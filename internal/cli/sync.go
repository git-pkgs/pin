package cli

import (
	"fmt"
	"os"

	pin "github.com/git-pkgs/pin"
	"github.com/spf13/cobra"
)

// ciEnvVars is the set of environment variable names that indicate the
// process is running under a CI system. When one of these is set and
// --frozen isn't passed, pin sync prints a one-line nudge.
var ciEnvVars = []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL"}

func detectCI() string {
	for _, k := range ciEnvVars {
		if os.Getenv(k) != "" {
			return k
		}
	}
	return ""
}

func newSyncCmd() *cobra.Command {
	var opts pin.SyncOptions
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Resolve manifest, fetch assets, write lockfile",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.Frozen {
				if ci := detectCI(); ci != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "note: %s is set; consider --frozen so a stale lockfile fails the build instead of being silently re-resolved\n", ci)
				}
			}
			res, err := pin.Sync(cmd.Context(), opts)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				encoded, err := pin.EncodeLock(res.Lock)
				if err != nil {
					return err
				}
				_, _ = out.Write(encoded)
				return nil
			}
			fmt.Fprintf(out, "synced %d assets (%d added, %d updated, %d removed, %d unchanged)\n",
				len(res.Lock.Assets),
				len(res.Changes.Added), len(res.Changes.Updated),
				len(res.Changes.Removed), len(res.Changes.Unchanged))
			for _, a := range res.Changes.Added {
				fmt.Fprintf(out, "  + %s\n", a.Out)
			}
			for _, a := range res.Changes.Updated {
				fmt.Fprintf(out, "  ~ %s\n", a.Out)
			}
			for _, p := range res.Removed {
				fmt.Fprintf(out, "  - %s\n", p)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.Dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&opts.Manifest, "manifest", pin.DefaultManifest, "manifest path")
	cmd.Flags().StringVar(&opts.Lock, "lock", pin.DefaultLock, "lockfile path")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "resolve and report, but write nothing")
	cmd.Flags().BoolVar(&opts.Frozen, "frozen", false, "fail if the lockfile would change (CI mode)")
	cmd.Flags().StringVar(&opts.RegistryURL, "registry", "", "npm registry base URL (default: registry.npmjs.org)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the resolved lockfile as JSON instead of a summary (use with --dry-run for managers' resolve)")
	cmd.Flags().BoolVar(&opts.StrictProvenance, "strict-provenance", false, "fail if any npm entry resolves to a version with no attestation")
	cmd.Flags().BoolVar(&opts.RequirePublisherMatchesRepository, "require-publisher-matches-repository", false, "fail if an attestation's build workflow lives on a different repository than the package's declared repository.url (catches leaked-token attacks)")
	return cmd
}
