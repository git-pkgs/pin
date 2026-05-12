package cli

import (
	"os"

	pin "github.com/git-pkgs/pin"
	"github.com/spf13/cobra"
)

func newSBOMCmd() *cobra.Command {
	var opts pin.SBOMOptions
	var format, output string
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Emit the lockfile as an SBOM (CycloneDX or SPDX)",
		Long:  "pin.lock is already a valid CycloneDX 1.6 BOM. The default format is a byte-for-byte passthrough; spdx and cyclonedx-xml convert via git-pkgs/sbom.",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Format = pin.SBOMFormat(format)
			w := cmd.OutOrStdout()
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				w = f
			}
			return pin.SBOM(w, opts)
		},
	}
	cmd.Flags().StringVarP(&opts.Dir, "dir", "C", ".", "project directory")
	cmd.Flags().StringVar(&opts.Lock, "lock", pin.DefaultLock, "lockfile path")
	cmd.Flags().StringVarP(&format, "format", "f", string(pin.SBOMCycloneDXJSON), "output format: cyclonedx, cyclonedx-xml, spdx")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to file instead of stdout")
	cmd.Flags().BoolVar(&opts.StripPinProperties, "strip-pin", false, "drop pin: namespace properties from the emitted SBOM (for downstream consumers that don't recognise them)")
	return cmd
}
