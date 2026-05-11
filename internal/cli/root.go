package cli

import (
	"github.com/spf13/cobra"
)

var version = "dev"

func Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "pin",
		Short:         "Browser asset vendoring without npm",
		Long:          "pin fetches files from published packages, anchors integrity to the registry tarball, and writes a lockfile other tools can read.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newSyncCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newOutdatedCmd())
	root.AddCommand(newAddCmd())

	return root
}
