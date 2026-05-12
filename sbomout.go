package pin

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/sbom"
)

type SBOMFormat string

const (
	SBOMCycloneDXJSON SBOMFormat = "cyclonedx"
	SBOMCycloneDXXML  SBOMFormat = "cyclonedx-xml"
	SBOMSPDXJSON      SBOMFormat = "spdx"
)

// SBOMOptions. Format defaults to CycloneDX (the lockfile's native
// shape, byte-for-byte passthrough when StripPinProperties is false).
// StripPinProperties drops every property whose name starts with "pin:"
// before encoding; the lockfile on disk is untouched.
type SBOMOptions struct {
	Dir                string
	Lock               string
	Format             SBOMFormat
	StripPinProperties bool
}

// SBOM writes the lockfile in the requested SBOM format. CycloneDX
// JSON is byte-for-byte when no filtering is requested; other formats
// (and any strip) round-trip through git-pkgs/sbom.
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

	if opts.Format == SBOMCycloneDXJSON && !opts.StripPinProperties {
		_, err = w.Write(raw)
		return err
	}

	doc, err := sbom.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse %s as SBOM: %w", lockPath, err)
	}

	if opts.StripPinProperties {
		doc.FilterProperties(func(name string) bool {
			return !strings.HasPrefix(name, "pin:")
		})
	}

	var format sbom.Format
	switch opts.Format {
	case SBOMCycloneDXJSON:
		format = sbom.FormatCycloneDXJSON
	case SBOMSPDXJSON:
		format = sbom.FormatSPDXJSON
	case SBOMCycloneDXXML:
		format = sbom.FormatCycloneDXXML
	default:
		return fmt.Errorf("unknown sbom format %q (supported: cyclonedx, cyclonedx-xml, spdx)", opts.Format)
	}
	return sbom.Encode(w, doc, format)
}
