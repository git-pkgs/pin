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
	"path/filepath"
	"slices"
	"strings"

	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
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

// ToolVersion is the tool-version string written to pin.lock's
// metadata.tools[]. Overridden at build time via the
// `-X github.com/git-pkgs/pin.ToolVersion=X.Y.Z` ldflag.
var ToolVersion = "dev"

// SyncOptions configures pin.Sync / Client.Sync. Per-call fields
// (DryRun, Frozen, Update, ...) belong here; client-config fields
// (RegistryURL, Forge, ...) are honoured by the top-level pin.Sync
// shim only — pass them via ClientOptions when constructing a Client
// directly.
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

	// SignatureMode controls npm dist.signatures (ECDSA over
	// {name}@{version}:{integrity}) verification. Warn (default) verifies
	// when a signature is present and fails on a bad one; enforce
	// additionally fails on missing signatures; off skips verification.
	SignatureMode npm.SignatureMode

	// Concurrency caps the number of entries Sync resolves in parallel.
	// Zero means defaultConcurrency. The lockfile order is independent of
	// completion order: assets are sorted by (name, asset.out) before the
	// file is written, so determinism is preserved regardless of how
	// resolves interleave.
	Concurrency int

	// NoFetch is the CI cheap-assertion mode: implies Frozen (bail before
	// any network if manifest and lockfile disagree) and additionally
	// verifies that every vendored file on disk hashes to the integrity
	// recorded in the lockfile. Designed for CI jobs that vendored at
	// image-build time and just want to assert nothing was tampered with
	// after checkout. No network, no writes.
	NoFetch bool
}

func (o *SyncOptions) forceResolve(name string) bool {
	return o.UpdateAll || slices.Contains(o.Update, name)
}

// SyncResult is the outcome of pin.Sync: the resolved lockfile, the
// diff against the previous lockfile, and the paths written and
// removed under the manifest's out: directory.
type SyncResult struct {
	Lock    *lock.Lock
	Changes lock.Changes
	Written []string
	Removed []string
}

// Sync is a one-shot shim around Client.Sync that constructs a Client
// from the client-config fields embedded in SyncOptions (RegistryURL,
// Forge, SignatureMode, VerifyProvenance). Library consumers that
// reuse a Client across calls should use New + Client.Sync directly.
func Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	c, err := clientFromSyncOptions(opts)
	if err != nil {
		return nil, err
	}
	return c.Sync(ctx, opts)
}

// Sync resolves the manifest, fetches assets, and writes the lockfile.
// Per-operation behaviour (DryRun, Frozen, Update, NoFetch, ...) lives
// in opts; infrastructure config (RegistryURL, SignatureMode, ...)
// comes from the Client created via New. The client-config fields on
// SyncOptions are ignored — they exist for the package-level Sync
// shim only.
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

	next := &lock.Lock{OutDir: m.Out}
	var written []string

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	type entryResult struct {
		assets []lock.Asset
		files  []fileContent
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
		if !opts.DryRun {
			w, werr := writeFiles(opts.Dir, m.Out, r.files)
			if werr != nil {
				return nil, werr
			}
			written = append(written, w...)
		}
	}

	changes := lock.Diff(prev, next)

	if err := enforceTrust(m, next, opts); err != nil {
		return nil, err
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

// syncNoFetch implements --no-fetch: verify manifest and lockfile agree
// (frozen-style), and re-hash every file under m.Out against the
// lockfile's recorded integrity. No network, no writes.
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
		return "", fmt.Errorf("%w: out=%q resolves to %q", ErrPathEscape, out, dst)
	}
	return dst, nil
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
