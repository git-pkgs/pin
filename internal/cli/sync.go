package cli

import (
	"fmt"

	pin "github.com/git-pkgs/pin"
	"github.com/spf13/cobra"
)

func newSyncCmd() *cobra.Command {
	var opts pin.SyncOptions
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Resolve manifest, fetch assets, write lockfile",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := pin.Sync(cmd.Context(), opts)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
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
	return cmd
}
