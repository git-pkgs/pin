package cli

import (
	"fmt"

	pin "github.com/git-pkgs/pin"
	"github.com/spf13/cobra"
)

func newAddCmd() *cobra.Command {
	var opts pin.AddOptions
	cmd := &cobra.Command{
		Use:   "add NAME[@SPEC] [FILE...]",
		Short: "Add a package to the manifest and sync it",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := args[0]
			var files []string
			if len(args) > 1 {
				files = args[1:]
			}
			res, err := pin.Add(cmd.Context(), spec, files, opts)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "added %s %s (resolved %s)\n", res.Entry.Name, res.Entry.Version, res.Resolved)
			if res.SyncResult != nil {
				for _, a := range res.SyncResult.Changes.Added {
					fmt.Fprintf(out, "  + %s\n", a.Out)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.Dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&opts.Manifest, "manifest", pin.DefaultManifest, "manifest path")
	cmd.Flags().StringVar(&opts.Lock, "lock", pin.DefaultLock, "lockfile path")
	cmd.Flags().StringVar(&opts.RegistryURL, "registry", "", "npm registry base URL")
	cmd.Flags().BoolVar(&opts.Exact, "exact", false, "write the resolved exact version instead of a caret range")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "show what would be added without writing")
	return cmd
}
