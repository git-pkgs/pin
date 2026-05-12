package pin

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"path"

	"github.com/git-pkgs/pin/cdn"
	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
	"github.com/git-pkgs/pin/sniff"
	"github.com/git-pkgs/pin/source"
	"github.com/git-pkgs/pin/source/npm"
)

// maybeStripSourcemap removes sourceMappingURL directives from a
// script or style and recomputes integrity. Integrity must reflect
// what lands on disk so verify-on-checkout doesn't fail.
func maybeStripSourcemap(f source.ResolvedFile, e *manifest.Entry) source.ResolvedFile {
	if !e.StripSourcemap {
		return f
	}
	switch lock.ClassifyType(f.Path) {
	case lock.TypeScript, lock.TypeStyle:
	default:
		return f
	}
	stripped := sniff.StripSourcemapURL(f.Content)
	if len(stripped) == len(f.Content) {
		return f
	}
	h := sha512.Sum384(stripped)
	f.Content = stripped
	f.Size = int64(len(stripped))
	f.Integrity = "sha384-" + base64.StdEncoding.EncodeToString(h[:])
	return f
}

type fileContent struct {
	out     string
	content []byte
}

func (c *Client) resolveEntry(ctx context.Context, m *manifest.Manifest, e *manifest.Entry, lockedVersion string) ([]lock.Asset, []fileContent, error) {
	src := e.Source()
	switch src.Kind {
	case manifest.SourceNPM:
		return c.resolveNPMEntry(ctx, m, e, lockedVersion)
	case manifest.SourceForge:
		return c.resolveForgeEntry(ctx, m, e, src)
	case manifest.SourceURL:
		return c.resolveURLEntry(ctx, m, e)
	default:
		return nil, nil, fmt.Errorf("%s: source kind %q not supported in this build", e.Name, src.Kind)
	}
}

func (c *Client) resolveURLEntry(ctx context.Context, m *manifest.Manifest, e *manifest.Entry) ([]lock.Asset, []fileContent, error) {
	resolver := c.resolvers["generic"]
	if resolver == nil {
		return nil, nil, fmt.Errorf("%s: no resolver registered for purl type %q", e.Name, "generic")
	}
	resolved, err := resolver.Resolve(ctx, e.PURL(e.Version), nil)
	if err != nil {
		return nil, nil, err
	}

	slug := e.Slug()
	assets := make([]lock.Asset, 0, len(resolved.Files))
	files := make([]fileContent, 0, len(resolved.Files))

	for _, f := range resolved.Files {
		f = maybeStripSourcemap(f, e)
		out := outputPath(m.Layout, slug, resolved.Version, f.Path)
		assetType := lock.ClassifyType(f.Path)
		format := e.Format
		if format == "" && assetType == lock.TypeScript {
			format = sniff.Format(f.Content)
		}
		assets = append(assets, lock.Asset{
			Name:             e.Name,
			Version:          resolved.Version,
			PURL:             resolved.PURL,
			Type:             string(assetType),
			Format:           format,
			Path:             f.Path,
			Out:              out,
			URL:              f.URL,
			Integrity:        f.Integrity,
			Size:             f.Size,
			PackageIntegrity: f.Integrity,
		})
		files = append(files, fileContent{out: out, content: f.Content})
	}
	return assets, files, nil
}

func (c *Client) resolveNPMEntry(ctx context.Context, m *manifest.Manifest, e *manifest.Entry, lockedVersion string) ([]lock.Asset, []fileContent, error) {
	version := lockedVersion
	if !npm.IsSticky(lockedVersion, e.Version) {
		v, err := c.NPM.ResolveVersion(ctx, e.PURL(""), e.Version, m.Cooldown())
		if err != nil {
			return nil, nil, err
		}
		version = v
	}

	resolver := c.resolvers["npm"]
	if resolver == nil {
		return nil, nil, fmt.Errorf("%s: no resolver registered for purl type %q", e.Name, "npm")
	}
	resolved, err := resolver.Resolve(ctx, e.PURL(version), e.Files)
	if err != nil {
		return nil, nil, err
	}

	slug := e.Slug()
	assets := make([]lock.Asset, 0, len(resolved.Files))
	files := make([]fileContent, 0, len(resolved.Files))

	att := toLockAttestation(resolved.Attestation)

	for _, f := range resolved.Files {
		f = maybeStripSourcemap(f, e)
		out := outputPath(m.Layout, slug, resolved.Version, f.Path)
		assetType := lock.ClassifyType(f.Path)
		format := e.Format
		if format == "" && assetType == lock.TypeScript {
			format = sniff.Format(f.Content)
		}
		assets = append(assets, lock.Asset{
			Name:             resolved.Name,
			Version:          resolved.Version,
			PURL:             resolved.PURL,
			Type:             string(assetType),
			Format:           format,
			Path:             f.Path,
			Out:              out,
			URL:              cdn.NPMFileURL(cdn.JSDelivr, resolved.Name, resolved.Version, f.Path),
			Integrity:        f.Integrity,
			Size:             f.Size,
			PackageIntegrity: resolved.PackageIntegrity,
			License:          resolved.License,
			Repository:       resolved.SourceRepository,
			Attestation:      att,
		})
		files = append(files, fileContent{out: out, content: f.Content})
	}
	return assets, files, nil
}

func toLockAttestation(a *source.Attestation) *lock.Attestation {
	if a == nil {
		return nil
	}
	return &lock.Attestation{
		PredicateType:    a.PredicateType,
		BuilderID:        a.BuilderID,
		SourceRepository: a.SourceRepository,
		SourceRevision:   a.SourceRevision,
		SignerIdentity:   a.SignerIdentity,
		BundleURL:        a.BundleURL,
	}
}

func (c *Client) resolveForgeEntry(ctx context.Context, m *manifest.Manifest, e *manifest.Entry, _ manifest.Source) ([]lock.Asset, []fileContent, error) {
	p := e.PURL(e.Version)
	resolver := c.resolvers[p.Type]
	if resolver == nil {
		return nil, nil, fmt.Errorf("%s: no resolver registered for purl type %q", e.Name, p.Type)
	}
	resolved, err := resolver.Resolve(ctx, p, e.Files)
	if err != nil {
		return nil, nil, err
	}

	slug := e.Slug()
	assets := make([]lock.Asset, 0, len(resolved.Files))
	files := make([]fileContent, 0, len(resolved.Files))

	att := toLockAttestation(resolved.Attestation)

	for _, f := range resolved.Files {
		f = maybeStripSourcemap(f, e)
		out := outputPath(m.Layout, slug, resolved.Version, f.Path)
		assetType := lock.ClassifyType(f.Path)
		format := e.Format
		if format == "" && assetType == lock.TypeScript {
			format = sniff.Format(f.Content)
		}
		assets = append(assets, lock.Asset{
			Name:             e.Name,
			Version:          resolved.Version,
			PURL:             resolved.PURL,
			Type:             string(assetType),
			Format:           format,
			Path:             f.Path,
			Out:              out,
			URL:              f.URL,
			Integrity:        f.Integrity,
			Size:             f.Size,
			PackageIntegrity: resolved.PackageIntegrity,
			Repository:       resolved.SourceRepository,
			Attestation:      att,
		})
		files = append(files, fileContent{out: out, content: f.Content})
	}
	return assets, files, nil
}

func outputPath(layout manifest.Layout, slug, version, packagePath string) string {
	base := path.Base(packagePath)
	if layout == manifest.LayoutFlat {
		return slug + "-" + version + "-" + base
	}
	return slug + "/" + base
}
