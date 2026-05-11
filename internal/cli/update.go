package cli

import (
	"fmt"

	pin "github.com/git-pkgs/pin"
	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	var opts pin.SyncOptions
	cmd := &cobra.Command{
		Use:   "update [NAME...]",
		Short: "Re-resolve manifest entries to the highest satisfying version",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				opts.UpdateAll = true
			} else {
				opts.Update = args
			}
			res, err := pin.Sync(cmd.Context(), opts)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "updated %d assets (%d changed, %d unchanged)\n",
				len(res.Lock.Assets), len(res.Changes.Updated)+len(res.Changes.Added), len(res.Changes.Unchanged))
			for _, a := range res.Changes.Updated {
				fmt.Fprintf(out, "  ~ %s -> %s\n", a.Out, a.Version)
			}
			for _, a := range res.Changes.Added {
				fmt.Fprintf(out, "  + %s\n", a.Out)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.Dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&opts.Manifest, "manifest", pin.DefaultManifest, "manifest path")
	cmd.Flags().StringVar(&opts.Lock, "lock", pin.DefaultLock, "lockfile path")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "resolve and report, but write nothing")
	cmd.Flags().StringVar(&opts.RegistryURL, "registry", "", "npm registry base URL")
	return cmd
}
