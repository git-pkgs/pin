// Package pin is the public Go API for the pin tool: read a manifest,
// resolve assets, write them out, and emit a CycloneDX lockfile.
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

	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
	"github.com/git-pkgs/pin/pinfs"
	"github.com/git-pkgs/pin/source/forge"
	"github.com/git-pkgs/pin/source/npm"
	"golang.org/x/sync/errgroup"
)

const defaultConcurrency = 8

const (
	DefaultManifest = "pin.yaml"
	DefaultLock     = "pin.lock"

	ToolName = "pin"

	dirPerm  = 0o755
	filePerm = 0o644
)

// ToolVersion is overridden at build time via the
// `-X github.com/git-pkgs/pin.ToolVersion=X.Y.Z` ldflag.
var ToolVersion = "dev"

// SyncOptions configures pin.Sync / Client.Sync. RegistryURL, Forge,
// SignatureMode, and VerifyProvenance are honoured by the top-level
// pin.Sync shim only; pass them via ClientOptions when constructing a
// Client directly.
type SyncOptions struct {
	Dir         string
	Manifest    string
	Lock        string
	DryRun      bool
	Frozen      bool
	RegistryURL string
	Forge       forge.Options

	// Update lists entry names whose lock-is-sticky check is
	// bypassed; UpdateAll bypasses it for every entry.
	Update    []string
	UpdateAll bool

	// StrictProvenance fails sync when an npm entry resolves to a
	// version with no SLSA Provenance attestation recorded.
	StrictProvenance bool

	// RequirePublisherMatchesRepository fails sync when an
	// attestation's build workflow lives on a different repository
	// than the package's declared repository.url. The consumer-side
	// check against leaked-token attacks: a stolen publish token
	// produces an attestation whose source_repository won't match.
	RequirePublisherMatchesRepository bool

	// VerifyProvenance cryptographically verifies each attestation
	// bundle against Sigstore's TUF trust root.
	VerifyProvenance bool

	SignatureMode npm.SignatureMode

	// Concurrency caps parallel resolves; zero = defaultConcurrency.
	// Lockfile order is independent of completion order: assets are
	// sorted by (name, asset.out) before writing.
	Concurrency int

	// NoFetch implies Frozen and re-hashes every vendored file on
	// disk against the lockfile's recorded integrity. For CI jobs
	// that vendored at image-build time. No network, no writes.
	NoFetch bool

	// FS redirects Sync's outputs (vendored files + pin.lock). nil
	// means pinfs.OS(opts.Dir). pinfs.NewMemory() keeps everything in
	// process. The manifest and prior lockfile are still read from
	// opts.Dir on local disk.
	FS pinfs.Writer
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

// Sync constructs a Client from opts and runs one Sync. Consumers
// that reuse a Client across calls should use New + Client.Sync.
func Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	c, err := clientFromSyncOptions(opts)
	if err != nil {
		return nil, err
	}
	return c.Sync(ctx, opts)
}

// Sync resolves the manifest, fetches assets, and writes the
// lockfile. Per-operation behaviour comes from opts; infrastructure
// config (RegistryURL, SignatureMode, ...) comes from the Client.
func (c *Client) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
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

	prevVersions := lockedVersionsByName(prev)

	if opts.NoFetch {
		return c.syncNoFetch(opts, m, prev, prevVersions)
	}

	if opts.Frozen {
		if err := checkFrozen(m, prev, prevVersions); err != nil {
			return nil, err
		}
	}

	fw := opts.FS
	if fw == nil {
		fw = pinfs.OS(opts.Dir)
	}

	next := &lock.Lock{OutDir: m.Out}
	var written []string

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	results := make([]entryResult, len(m.Assets))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i := range m.Assets {
		g.Go(func() error {
			entry := m.Assets[i]
			locked := prevVersions[entry.Name]
			if opts.forceResolve(entry.Name) {
				locked = ""
			}
			assets, files, rerr := c.resolveEntry(gctx, m, &entry, locked)
			if rerr != nil {
				return rerr
			}
			results[i] = entryResult{assets: assets, files: files}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	for _, r := range results {
		next.Assets = append(next.Assets, r.assets...)
	}
	if err := checkOutCollisions(next.Assets); err != nil {
		return nil, err
	}
	if !opts.DryRun {
		w, werr := writeAllFiles(fw, m.Out, results)
		if werr != nil {
			return nil, werr
		}
		written = w
	}

	changes := lock.Diff(prev, next)

	if err := enforceTrust(m, next, opts); err != nil {
		return nil, err
	}

	var removed []string
	if !opts.DryRun {
		removed, err = removeOrphans(fw, m.Out, changes.Removed)
		if err != nil {
			return nil, err
		}
		if err := writeLock(fw, opts.Lock, next); err != nil {
			return nil, err
		}
	}

	return &SyncResult{Lock: next, Changes: changes, Written: written, Removed: removed}, nil
}

func (c *Client) syncNoFetch(opts SyncOptions, m *manifest.Manifest, prev *lock.Lock, prevVersions map[string]string) (*SyncResult, error) {
	if prev == nil {
		return nil, fmt.Errorf("--no-fetch: %w at %s", ErrNoLockfile, filepath.Join(opts.Dir, opts.Lock))
	}
	if err := checkFrozen(m, prev, prevVersions); err != nil {
		return nil, fmt.Errorf("--no-fetch: %w", err)
	}
	vr, err := c.Verify(VerifyOptions{Dir: opts.Dir, Lock: opts.Lock})
	if err != nil {
		return nil, fmt.Errorf("--no-fetch: %w", err)
	}
	if vr.Failed() {
		return nil, fmt.Errorf("--no-fetch: %w: %s", ErrVerifyFailed, vr.Summary())
	}
	return &SyncResult{Lock: prev, Changes: lock.Diff(prev, prev)}, nil
}

type entryResult struct {
	assets []lock.Asset
	files  []fileContent
}

func writeAllFiles(fw pinfs.Writer, outDir string, results []entryResult) ([]string, error) {
	var written []string
	for _, r := range results {
		w, err := writeFiles(fw, outDir, r.files)
		if err != nil {
			return nil, err
		}
		written = append(written, w...)
	}
	return written, nil
}

// safeOut returns a slash-separated path under outDir, or
// ErrPathEscape. Defence in depth on top of manifest validation: the
// joined output path is checked one more time before any bytes leave
// pin's process.
func safeOut(outDir, out string) (string, error) {
	cleanDir := path.Clean(outDir)
	if cleanDir != "" && cleanDir != "." && !fs.ValidPath(cleanDir) {
		return "", fmt.Errorf("%w: outDir %q is not a valid relative slash path", ErrPathEscape, outDir)
	}
	joined := path.Clean(path.Join(outDir, out))
	if !fs.ValidPath(joined) {
		return "", fmt.Errorf("%w: out=%q resolves outside outDir", ErrPathEscape, out)
	}
	if cleanDir == "" || cleanDir == "." {
		return joined, nil
	}
	if joined == cleanDir || strings.HasPrefix(joined, cleanDir+"/") {
		return joined, nil
	}
	return "", fmt.Errorf("%w: out=%q resolves outside outDir %q", ErrPathEscape, out, outDir)
}

func writeFiles(fw pinfs.Writer, outDir string, files []fileContent) ([]string, error) {
	var written []string
	for _, f := range files {
		rel, err := safeOut(outDir, f.out)
		if err != nil {
			return written, err
		}
		if err := fw.WriteFile(rel, f.content); err != nil {
			return written, err
		}
		written = append(written, f.out)
	}
	return written, nil
}

func removeOrphans(fw pinfs.Writer, outDir string, orphans []lock.Asset) ([]string, error) {
	var removed []string
	for _, a := range orphans {
		rel, err := safeOut(outDir, a.Out)
		if err != nil {
			return removed, err
		}
		if err := fw.Remove(rel); err != nil {
			return removed, fmt.Errorf("remove orphan %s: %w", a.Out, err)
		}
		removed = append(removed, a.Out)
	}
	return removed, nil
}

// checkOutCollisions fails closed when two resolved assets share an
// Out path. Hits most often under layout: flat when packages or
// per-entry file lists collide on basename. Reports the first pair so
// the user can fix the manifest before any bytes are written.
func checkOutCollisions(assets []lock.Asset) error {
	seen := make(map[string]string, len(assets))
	for _, a := range assets {
		if prev, ok := seen[a.Out]; ok {
			return fmt.Errorf("%w: %q claimed by both %s and %s", ErrPathCollision, a.Out, prev, a.Name)
		}
		seen[a.Out] = a.Name
	}
	return nil
}

// checkFrozen fails fast, before any network call, if manifest and
// lockfile disagree.
func checkFrozen(m *manifest.Manifest, prev *lock.Lock, prevVersions map[string]string) error {
	if prev == nil {
		return fmt.Errorf("%w: no lockfile present; run sync without --frozen first", ErrFrozenDrift)
	}
	manifestNames := map[string]bool{}
	for _, e := range m.Assets {
		manifestNames[e.Name] = true
		locked := prevVersions[e.Name]
		if locked == "" {
			return fmt.Errorf("%w: %s is in the manifest but not the lockfile", ErrFrozenDrift, e.Name)
		}
		if !npm.IsSticky(locked, e.Version) {
			return fmt.Errorf("%w: %s is locked at %s which no longer satisfies manifest constraint %q", ErrFrozenDrift, e.Name, locked, e.Version)
		}
	}
	for _, a := range prev.Assets {
		if !manifestNames[a.Name] {
			return fmt.Errorf("%w: %s is in the lockfile but not the manifest", ErrFrozenDrift, a.Name)
		}
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

func writeLock(fw pinfs.Writer, lockPath string, l *lock.Lock) error {
	if !fs.ValidPath(lockPath) {
		return fmt.Errorf("%w: lockfile path %q is not a valid relative slash path", ErrPathEscape, lockPath)
	}
	encoded, err := EncodeLock(l)
	if err != nil {
		return err
	}
	return fw.WriteFile(lockPath, encoded)
}

// EncodeLock returns the lockfile bytes for l using the current tool
// name and version.
func EncodeLock(l *lock.Lock) ([]byte, error) {
	var buf bytes.Buffer
	if err := lock.Write(&buf, l, ToolName, ToolVersion); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
