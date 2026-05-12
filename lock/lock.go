// Package lock reads and writes pin.lock as a CycloneDX 1.6 BOM.
//
// The in-memory model (Lock, Asset) is flat — one Asset per vendored
// file. CycloneDX nesting (one library component per package, file
// components nested under each) is a serialisation detail handled by
// Read and Write.
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

// MaxLockfileBytes is a DoS-prevention cap. A 1000-file monorepo
// lockfile stays under 1 MiB; 16 MiB is the comfortable upper bound.
const MaxLockfileBytes = 16 << 20

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
	// Repository is the package's *declared* repository URL. NOT to
	// be conflated with Attestation.SourceRepository (the repo the
	// attestation says the build came from); the
	// publisher-matches-repository check compares the two.
	Repository  string
	Attestation *Attestation
}

// Attestation holds SLSA Provenance v1 identity fields. Cryptographic
// verification of the underlying bundle is gated separately on
// --verify-provenance.
type Attestation struct {
	PredicateType    string
	BuilderID        string
	SourceRepository string
	SourceRevision   string
	SignerIdentity   string
	BundleURL        string
}

func Read(r io.Reader) (*Lock, error) {
	limited := io.LimitReader(r, MaxLockfileBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	if int64(len(raw)) > MaxLockfileBytes {
		return nil, fmt.Errorf("lockfile exceeds %d bytes", MaxLockfileBytes)
	}
	var bom cdxBOM
	if err := json.Unmarshal(raw, &bom); err != nil {
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
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bom); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
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
