package pin

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/git-pkgs/sbom"
)

// SBOMFormat selects the on-wire SBOM encoding pin.SBOM emits.
type SBOMFormat string

const (
	SBOMCycloneDXJSON SBOMFormat = "cyclonedx"
	SBOMCycloneDXXML  SBOMFormat = "cyclonedx-xml"
	SBOMSPDXJSON      SBOMFormat = "spdx"
)

// SBOMOptions configures pin.SBOM. Format defaults to CycloneDX
// (the lockfile's native shape, emitted byte-for-byte); SPDX and
// CycloneDX-XML reshapes happen via git-pkgs/sbom.
type SBOMOptions struct {
	Dir    string
	Lock   string
	Format SBOMFormat
}

// SBOM writes the lockfile in the requested SBOM format. The lockfile
// is already a valid CycloneDX 1.6 BOM, so the default format is a
// byte-for-byte passthrough; other formats round-trip through
// git-pkgs/sbom's unified model.
func SBOM(w io.Writer, opts SBOMOptions) error {
	if opts.Lock == "" {
		opts.Lock = DefaultLock
	}
	if opts.Format == "" {
		opts.Format = SBOMCycloneDXJSON
	}

	lockPath := filepath.Join(opts.Dir, opts.Lock)
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return err
	}

	if opts.Format == SBOMCycloneDXJSON {
		_, err = w.Write(raw)
		return err
	}

	doc, err := sbom.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse %s as SBOM: %w", lockPath, err)
	}

	var format sbom.Format
	switch opts.Format {
	case SBOMSPDXJSON:
		format = sbom.FormatSPDXJSON
	case SBOMCycloneDXXML:
		format = sbom.FormatCycloneDXXML
	default:
		return fmt.Errorf("unknown sbom format %q (supported: cyclonedx, cyclonedx-xml, spdx)", opts.Format)
	}
	return sbom.Encode(w, doc, format)
}
