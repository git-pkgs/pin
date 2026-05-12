package pin

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
//
// StripPinProperties drops every property whose name starts with the
// pin: prefix before encoding. Downstream SBOM consumers that don't
// recognise the namespace see a smaller, taxonomy-clean document. The
// underlying lockfile on disk is untouched.
type SBOMOptions struct {
	Dir                string
	Lock               string
	Format             SBOMFormat
	StripPinProperties bool
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

	if opts.StripPinProperties {
		raw, err = stripPinProperties(raw)
		if err != nil {
			return fmt.Errorf("strip pin: properties: %w", err)
		}
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

// stripPinProperties walks the CycloneDX JSON and removes every
// properties[] entry whose name starts with "pin:". Used by --strip-
// pin when handing the SBOM to a downstream consumer (Dependency-
// Track, GUAC, OSV-scanner) that wouldn't recognise the namespace.
// The lockfile on disk is untouched; only the emitted bytes are
// rewritten.
func stripPinProperties(raw []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	stripFromNode(doc)
	return json.MarshalIndent(doc, "", "  ")
}

// stripFromNode descends a parsed CycloneDX tree filtering pin:
// properties out of every properties[] array it encounters.
func stripFromNode(node any) {
	switch v := node.(type) {
	case map[string]any:
		if props, ok := v["properties"].([]any); ok {
			kept := props[:0]
			for _, p := range props {
				if pm, ok := p.(map[string]any); ok {
					if name, ok := pm["name"].(string); ok && strings.HasPrefix(name, "pin:") {
						continue
					}
				}
				kept = append(kept, p)
			}
			if len(kept) == 0 {
				delete(v, "properties")
			} else {
				v["properties"] = kept
			}
		}
		for _, child := range v {
			stripFromNode(child)
		}
	case []any:
		for _, child := range v {
			stripFromNode(child)
		}
	}
}
