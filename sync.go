// Package pin is the public Go API for the pin tool: read a manifest,
// resolve assets, write them to disk, and emit a CycloneDX lockfile.
package pin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/git-pkgs/pin/cdn"
	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
	"github.com/git-pkgs/pin/sniff"
	"github.com/git-pkgs/pin/source"
	"github.com/git-pkgs/pin/source/forge"
	"github.com/git-pkgs/pin/source/npm"
	"github.com/git-pkgs/pin/source/rawurl"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const (
	DefaultManifest = "pin.yaml"
	DefaultLock     = "pin.lock"

	ToolName = "pin"

	dirPerm  = 0o755
	filePerm = 0o644
)

var ToolVersion = "dev"

type SyncOptions struct {
	Dir         string
	Manifest    string
	Lock        string
	DryRun      bool
	Frozen      bool
	RegistryURL string
	Forge       forge.Options

	// Update names whose lock-is-sticky check is bypassed: those entries
	// re-resolve against the registry even if the locked version still
	// satisfies the manifest constraint.
	Update []string
	// UpdateAll bypasses lock-is-sticky for every entry.
	UpdateAll bool

	// StrictProvenance fails sync when an npm entry resolves to a version
	// that has no SLSA Provenance attestation recorded by the registry.
	StrictProvenance bool

	// RequirePublisherMatchesRepository fails sync when an attestation's
	// build workflow lives on a different repository than the package's
	// declared repository.url. This is the key consumer-side check
	// against leaked-token attacks: an attacker with a stolen publish
	// token can produce a technically valid attestation from their own
	// CI, but the source_repository field will not match the legitimate
	// package's repo.
	RequirePublisherMatchesRepository bool

	// VerifyProvenance cryptographically verifies each attestation
	// bundle against Sigstore's TUF trust root (Fulcio cert chain,
	// Rekor inclusion proof, DSSE signature, subject digest matches
	// the fetched tarball). Implies fetching the trust root from TUF.
	VerifyProvenance bool
}

func (o *SyncOptions) forceResolve(name string) bool {
	return o.UpdateAll || slices.Contains(o.Update, name)
}

type SyncResult struct {
	Lock    *lock.Lock
	Changes lock.Changes
	Written []string
	Removed []string
}

func Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	if opts.Manifest == "" {
		opts.Manifest = DefaultManifest
	}
	if opts.Lock == "" {
		opts.Lock = DefaultLock
	}

	m, err := readManifest(filepath.Join(opts.Dir, opts.Manifest))
	if err != nil {
		return nil, err
	}

	prev, err := readLock(filepath.Join(opts.Dir, opts.Lock))
	if err != nil {
		return nil, err
	}

	srcs, err := buildSources(opts)
	if err != nil {
		return nil, err
	}
	prevVersions := lockedVersionsByName(prev)

	if opts.Frozen {
		if err := checkFrozen(m, prev, prevVersions); err != nil {
			return nil, err
		}
	}

	next := &lock.Lock{OutDir: m.Out}
	var written []string

	for _, entry := range m.Assets {
		locked := prevVersions[entry.Name]
		if opts.forceResolve(entry.Name) {
			locked = ""
		}
		assets, files, rerr := resolveEntry(ctx, srcs, m, &entry, locked)
		if rerr != nil {
			return nil, rerr
		}
		next.Assets = append(next.Assets, assets...)
		if !opts.DryRun {
			w, werr := writeFiles(opts.Dir, m.Out, files)
			if werr != nil {
				return nil, werr
			}
			written = append(written, w...)
		}
	}

	changes := lock.Diff(prev, next)

	if opts.StrictProvenance {
		if err := assertProvenance(next); err != nil {
			return nil, err
		}
	}
	if opts.RequirePublisherMatchesRepository {
		if err := assertPublisherMatchesRepository(next); err != nil {
			return nil, err
		}
	}

	var removed []string
	if !opts.DryRun {
		removed, err = removeOrphans(opts.Dir, m.Out, changes.Removed)
		if err != nil {
			return nil, err
		}
		if err := writeLock(filepath.Join(opts.Dir, opts.Lock), next); err != nil {
			return nil, err
		}
	}

	return &SyncResult{Lock: next, Changes: changes, Written: written, Removed: removed}, nil
}

type fileContent struct {
	out     string
	content []byte
}

// safeOut returns an error if any joined path component would let a
// vendored file escape the project's out directory. Defence in depth:
// the manifest validates files: paths and slugs are built from sanitised
// names, but the joined output path is checked one more time before any
// bytes hit the disk.
func safeOut(dir, outDir, out string) (string, error) {
	root := filepath.Clean(filepath.Join(dir, outDir))
	dst := filepath.Clean(filepath.Join(root, filepath.FromSlash(out)))
	rel, err := filepath.Rel(root, dst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing to write outside out dir: out=%q resolves to %q", out, dst)
	}
	return dst, nil
}

type sources struct {
	npm    *npm.Source
	forge  *forge.Source
	rawurl *rawurl.Source
}

func buildSources(opts SyncOptions) (sources, error) {
	npmOpts := npm.Options{RegistryURL: opts.RegistryURL, VerifyProvenance: opts.VerifyProvenance}
	if opts.VerifyProvenance {
		tr, err := root.FetchTrustedRoot()
		if err != nil {
			return sources{}, fmt.Errorf("--verify-provenance: fetch Sigstore trust root: %w", err)
		}
		npmOpts.TrustedRoot = tr
	}
	return sources{
		npm:    npm.New(npmOpts),
		forge:  forge.New(opts.Forge),
		rawurl: rawurl.New(rawurl.Options{}),
	}, nil
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

func writeFiles(dir, outDir string, files []fileContent) ([]string, error) {
	var written []string
	for _, f := range files {
		dst, err := safeOut(dir, outDir, f.out)
		if err != nil {
			return written, err
		}
		if err := os.MkdirAll(filepath.Dir(dst), dirPerm); err != nil {
			return written, err
		}
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, f.content, filePerm); err != nil {
			return written, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return written, err
		}
		written = append(written, f.out)
	}
	return written, nil
}

func removeOrphans(dir, outDir string, orphans []lock.Asset) ([]string, error) {
	root := filepath.Join(dir, outDir)
	var removed []string
	parents := map[string]bool{}
	for _, a := range orphans {
		p := filepath.Join(root, filepath.FromSlash(a.Out))
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, fmt.Errorf("remove orphan %s: %w", a.Out, err)
		}
		removed = append(removed, a.Out)
		parents[filepath.Dir(p)] = true
	}
	for parent := range parents {
		pruneEmpty(parent, root)
	}
	return removed, nil
}

func pruneEmpty(dir, stop string) {
	for dir != stop && dir != "." && dir != string(filepath.Separator) {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			return
		}
		if err := os.Remove(dir); err != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}

// checkFrozen fails fast, before any network call, if the manifest and
// lockfile are inconsistent. Under --frozen the lockfile is the contract:
// every manifest entry must already be locked at a satisfying version, and
// every locked asset must still be claimed by a manifest entry.
func checkFrozen(m *manifest.Manifest, prev *lock.Lock, prevVersions map[string]string) error {
	if prev == nil {
		return fmt.Errorf("--frozen: no lockfile present; run sync without --frozen first")
	}
	manifestNames := map[string]bool{}
	for _, e := range m.Assets {
		manifestNames[e.Name] = true
		locked := prevVersions[e.Name]
		if locked == "" {
			return fmt.Errorf("--frozen: %s is in the manifest but not the lockfile", e.Name)
		}
		if !npm.IsSticky(locked, e.Version) {
			return fmt.Errorf("--frozen: %s is locked at %s which no longer satisfies manifest constraint %q", e.Name, locked, e.Version)
		}
	}
	for _, a := range prev.Assets {
		if !manifestNames[a.Name] {
			return fmt.Errorf("--frozen: %s is in the lockfile but not the manifest", a.Name)
		}
	}
	return nil
}

// assertPublisherMatchesRepository requires that, for every asset with
// a recorded attestation, the attestation's source repository matches
// the package's declared repository.url. This is the consumer-side check
// against a leaked publish token: an attacker can produce a syntactically
// valid attestation from their own CI, but the source_repository field
// will not match the legitimate package's repo.
func assertPublisherMatchesRepository(l *lock.Lock) error {
	seen := map[string]bool{}
	var mismatches []string
	for _, a := range l.Assets {
		if seen[a.Name] {
			continue
		}
		seen[a.Name] = true
		if a.Attestation == nil {
			continue
		}
		want := normaliseRepoURL(a.SourceRepository)
		got := normaliseRepoURL(a.Attestation.SourceRepository)
		if want == "" || got == "" {
			continue
		}
		if want != got {
			mismatches = append(mismatches, fmt.Sprintf("%s@%s: attestation built from %s but package.json says %s", a.Name, a.Version, got, want))
		}
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("--require-publisher-matches-repository: %s", strings.Join(mismatches, "; "))
	}
	return nil
}

// normaliseRepoURL strips a leading https:// (or http://), trailing .git,
// and any trailing slash, so two URLs that differ only in scheme or
// suffix compare equal.
func normaliseRepoURL(u string) string {
	u = strings.TrimSuffix(u, "/")
	u = strings.TrimSuffix(u, ".git")
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return strings.ToLower(u)
}

func assertProvenance(l *lock.Lock) error {
	seen := map[string]bool{}
	var missing []string
	for _, a := range l.Assets {
		if seen[a.Name] {
			continue
		}
		seen[a.Name] = true
		if !strings.HasPrefix(a.PURL, "pkg:npm/") {
			continue // only npm carries SLSA attestations today
		}
		if a.Attestation == nil {
			missing = append(missing, a.Name+"@"+a.Version)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("--strict-provenance: no attestation recorded for: %s", strings.Join(missing, ", "))
	}
	return nil
}

func lockedVersionsByName(l *lock.Lock) map[string]string {
	out := map[string]string{}
	if l == nil {
		return out
	}
	for _, a := range l.Assets {
		out[a.Name] = a.Version
	}
	return out
}

func readManifest(path string) (*manifest.Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return manifest.Read(f)
}

func readLock(path string) (*lock.Lock, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return lock.Read(f)
}

func writeLock(path string, l *lock.Lock) error {
	encoded, err := EncodeLock(l)
	if err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, encoded) {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, filePerm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// EncodeLock returns the lockfile bytes for l using the current tool
// name and version. Useful for --dry-run --json and for byte-comparison
// against an existing lockfile.
func EncodeLock(l *lock.Lock) ([]byte, error) {
	var buf bytes.Buffer
	if err := lock.Write(&buf, l, ToolName, ToolVersion); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
