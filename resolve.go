package pin

import (
	"context"
	"fmt"
	"path"

	"github.com/git-pkgs/pin/cdn"
	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
	"github.com/git-pkgs/pin/sniff"
	"github.com/git-pkgs/pin/source"
	"github.com/git-pkgs/pin/source/forge"
	"github.com/git-pkgs/pin/source/npm"
	"github.com/git-pkgs/pin/source/rawurl"
)

// fileContent is the resolver-to-writer handoff: where the bytes should
// land on disk relative to the manifest's out: directory, and the bytes
// themselves. Writes happen serially after all resolves complete (see
// Sync); fileContent is the small in-memory carrier.
type fileContent struct {
	out     string
	content []byte
}

func resolveEntry(ctx context.Context, srcs sources, m *manifest.Manifest, e *manifest.Entry, lockedVersion string) ([]lock.Asset, []fileContent, error) {
	src := e.Source()
	switch src.Kind {
	case manifest.SourceNPM:
		return resolveNPMEntry(ctx, srcs.npm, m, e, lockedVersion)
	case manifest.SourceForge:
		return resolveForgeEntry(ctx, srcs.forge, m, e, src)
	case manifest.SourceURL:
		return resolveURLEntry(ctx, srcs.rawurl, m, e)
	default:
		return nil, nil, fmt.Errorf("%s: source kind %q not supported in this build", e.Name, src.Kind)
	}
}

func resolveURLEntry(ctx context.Context, src *rawurl.Source, m *manifest.Manifest, e *manifest.Entry) ([]lock.Asset, []fileContent, error) {
	resolved, err := src.Resolve(ctx, e.PURL(e.Version), nil)
	if err != nil {
		return nil, nil, err
	}

	slug := e.Slug()
	assets := make([]lock.Asset, 0, len(resolved.Files))
	files := make([]fileContent, 0, len(resolved.Files))

	for _, f := range resolved.Files {
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

func resolveNPMEntry(ctx context.Context, src *npm.Source, m *manifest.Manifest, e *manifest.Entry, lockedVersion string) ([]lock.Asset, []fileContent, error) {
	version := lockedVersion
	if !npm.IsSticky(lockedVersion, e.Version) {
		v, err := src.ResolveVersion(ctx, e.Name, e.Version, m.EffectiveMinReleaseAge(e))
		if err != nil {
			return nil, nil, err
		}
		version = v
	}

	resolved, err := src.Resolve(ctx, e.PURL(version), e.Files)
	if err != nil {
		return nil, nil, err
	}

	slug := e.Slug()
	assets := make([]lock.Asset, 0, len(resolved.Files))
	files := make([]fileContent, 0, len(resolved.Files))

	att := toLockAttestation(resolved.Attestation)

	for _, f := range resolved.Files {
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
			SourceRepository: resolved.SourceRepository,
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

func resolveForgeEntry(ctx context.Context, src *forge.Source, m *manifest.Manifest, e *manifest.Entry, _ manifest.Source) ([]lock.Asset, []fileContent, error) {
	resolved, err := src.Resolve(ctx, e.PURL(e.Version), e.Files)
	if err != nil {
		return nil, nil, err
	}

	slug := e.Slug()
	assets := make([]lock.Asset, 0, len(resolved.Files))
	files := make([]fileContent, 0, len(resolved.Files))

	att := toLockAttestation(resolved.Attestation)

	for _, f := range resolved.Files {
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
			SourceRepository: resolved.SourceRepository,
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
