package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	pin "github.com/git-pkgs/pin"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var dir, manifestPath string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter pin.yaml in the current directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := pin.Init(dir, manifestPath); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", manifestPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&manifestPath, "manifest", pin.DefaultManifest, "manifest path")
	return cmd
}

func newRmCmd() *cobra.Command {
	var opts pin.SyncOptions
	cmd := &cobra.Command{
		Use:   "rm NAME...",
		Short: "Remove packages from the manifest and sync",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := pin.Remove(cmd.Context(), args, opts)
			if err != nil {
				return err
			}
			for _, p := range res.Removed {
				fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", p)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.Dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&opts.Manifest, "manifest", pin.DefaultManifest, "manifest path")
	cmd.Flags().StringVar(&opts.Lock, "lock", pin.DefaultLock, "lockfile path")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "show what would be removed without writing")
	cmd.Flags().StringVar(&opts.RegistryURL, "registry", "", "npm registry base URL")
	return cmd
}

func newListCmd() *cobra.Command {
	var opts pin.VerifyOptions
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Print the lockfile contents",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := pin.List(opts)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(entries)
			}
			const pad = 2
			tw := tabwriter.NewWriter(out, 0, 0, pad, ' ', 0)
			fmt.Fprintln(tw, "NAME\tVERSION\tTYPE\tOUT\tSIZE")
			for _, e := range entries {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", e.Name, e.Version, e.Type, e.Out, e.Size)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&opts.Dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&opts.Lock, "lock", pin.DefaultLock, "lockfile path")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	return cmd
}

func newPathCmd() *cobra.Command {
	var opts pin.VerifyOptions
	cmd := &cobra.Command{
		Use:   "path NAME",
		Short: "Print the on-disk paths for a locked package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := pin.Path(args[0], opts)
			if err != nil {
				return err
			}
			for _, p := range paths {
				fmt.Fprintln(cmd.OutOrStdout(), p)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.Dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&opts.Lock, "lock", pin.DefaultLock, "lockfile path")
	return cmd
}
