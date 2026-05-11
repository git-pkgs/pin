// Package lock reads and writes pin.lock as a CycloneDX 1.6 BOM.
//
// The on-disk format is valid CycloneDX so any SBOM consumer can read it
// directly. The in-memory model (Lock, Asset) is flat — one Asset per
// vendored file — and the CycloneDX nesting (one library component per
// package, nested file components per asset) is a serialisation detail
// handled by Read and Write.
package lock

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"
)

const Version = 1

type Lock struct {
	LockfileVersion int
	GeneratedBy     string
	OutDir          string
	Assets          []Asset
}

type Asset struct {
	Name             string
	Version          string
	PURL             string
	Type             string
	Format           string
	Path             string
	Out              string
	URL              string
	Integrity        string
	Size             int64
	PackageIntegrity string
	License          string
	SourceRepository string
}

func Read(r io.Reader) (*Lock, error) {
	var bom cdxBOM
	if err := json.NewDecoder(r).Decode(&bom); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}
	if bom.BOMFormat != cdxBOMFormat {
		return nil, fmt.Errorf("lockfile bomFormat %q is not %s", bom.BOMFormat, cdxBOMFormat)
	}
	if v := findProp(bom.Metadata.Properties, propLockfileVersion); v != "" {
		got, _ := strconv.Atoi(v)
		if got != Version {
			return nil, fmt.Errorf("pin:lockfile_version %d not supported (this binary supports %d)", got, Version)
		}
	}
	return fromCDX(&bom)
}

func Write(w io.Writer, l *Lock, toolName, toolVersion string) error {
	bom := toCDX(l, toolName, toolVersion)
	raw, err := json.Marshal(bom)
	if err != nil {
		return err
	}
	stable, err := canonicalize(raw)
	if err != nil {
		return err
	}
	_, err = w.Write(stable)
	return err
}

// canonicalize re-encodes JSON with alphabetically sorted keys at every level,
// two-space indent, LF endings, and a trailing newline.
func canonicalize(raw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type Changes struct {
	Added     []Asset
	Updated   []Asset
	Removed   []Asset
	Unchanged []Asset
}

func Diff(prev, next *Lock) Changes {
	var c Changes
	prevByOut := index(prev)
	nextByOut := index(next)

	for out, a := range nextByOut {
		p, ok := prevByOut[out]
		switch {
		case !ok:
			c.Added = append(c.Added, a)
		case p.Integrity != a.Integrity || p.Version != a.Version:
			c.Updated = append(c.Updated, a)
		default:
			c.Unchanged = append(c.Unchanged, a)
		}
	}
	for out, a := range prevByOut {
		if _, ok := nextByOut[out]; !ok {
			c.Removed = append(c.Removed, a)
		}
	}
	sortAssets(c.Added)
	sortAssets(c.Updated)
	sortAssets(c.Removed)
	sortAssets(c.Unchanged)
	return c
}

func index(l *Lock) map[string]Asset {
	if l == nil {
		return map[string]Asset{}
	}
	m := make(map[string]Asset, len(l.Assets))
	for _, a := range l.Assets {
		m[a.Out] = a
	}
	return m
}

func sortAssets(as []Asset) {
	slices.SortFunc(as, func(a, b Asset) int { return cmp.Compare(a.Out, b.Out) })
}

type AssetType string

const (
	TypeScript AssetType = "script"
	TypeStyle  AssetType = "style"
	TypeFont   AssetType = "font"
	TypeImage  AssetType = "image"
	TypeWASM   AssetType = "wasm"
	TypeMap    AssetType = "map"
	TypeOther  AssetType = "other"
)

var typeByExt = map[string]AssetType{
	".js": TypeScript, ".mjs": TypeScript, ".cjs": TypeScript,
	".css":   TypeStyle,
	".woff2": TypeFont, ".woff": TypeFont, ".ttf": TypeFont, ".otf": TypeFont, ".eot": TypeFont,
	".png": TypeImage, ".jpg": TypeImage, ".jpeg": TypeImage, ".gif": TypeImage,
	".svg": TypeImage, ".webp": TypeImage, ".avif": TypeImage,
	".wasm": TypeWASM,
	".map":  TypeMap,
}

func ClassifyType(p string) AssetType {
	if t, ok := typeByExt[strings.ToLower(path.Ext(p))]; ok {
		return t
	}
	return TypeOther
}
