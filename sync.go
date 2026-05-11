// Package pin is the public Go API for the pin tool: read a manifest,
// resolve assets, write them to disk, and emit a CycloneDX lockfile.
package pin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"

	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
	"github.com/git-pkgs/pin/source/npm"
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

	// Update names whose lock-is-sticky check is bypassed: those entries
	// re-resolve against the registry even if the locked version still
	// satisfies the manifest constraint.
	Update []string
	// UpdateAll bypasses lock-is-sticky for every entry.
	UpdateAll bool
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

	npmSrc := npm.New(npm.Options{RegistryURL: opts.RegistryURL})
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
		assets, files, rerr := resolveEntry(ctx, npmSrc, m, &entry, locked)
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

func resolveEntry(ctx context.Context, src *npm.Source, m *manifest.Manifest, e *manifest.Entry, lockedVersion string) ([]lock.Asset, []fileContent, error) {
	if e.Source().Kind != manifest.SourceNPM {
		return nil, nil, fmt.Errorf("%s: only npm sources are supported in this build", e.Name)
	}

	version := lockedVersion
	if !npm.IsSticky(lockedVersion, e.Version) {
		v, err := src.ResolveVersion(ctx, e.Name, e.Version)
		if err != nil {
			return nil, nil, err
		}
		version = v
	}

	resolved, err := src.Resolve(ctx, e.Name, version, e.Files)
	if err != nil {
		return nil, nil, err
	}

	slug := e.Slug()
	assets := make([]lock.Asset, 0, len(resolved.Files))
	files := make([]fileContent, 0, len(resolved.Files))

	for _, f := range resolved.Files {
		out := outputPath(m.Layout, slug, resolved.Version, f.Path)
		assets = append(assets, lock.Asset{
			Name:             resolved.Name,
			Version:          resolved.Version,
			PURL:             resolved.PURL,
			Type:             string(lock.ClassifyType(f.Path)),
			Format:           e.Format,
			Path:             f.Path,
			Out:              out,
			Integrity:        f.Integrity,
			Size:             f.Size,
			PackageIntegrity: resolved.PackageIntegrity,
			License:          resolved.License,
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
		dst := filepath.Join(dir, outDir, filepath.FromSlash(f.out))
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
	var removed []string
	for _, a := range orphans {
		p := filepath.Join(dir, outDir, filepath.FromSlash(a.Out))
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, fmt.Errorf("remove orphan %s: %w", a.Out, err)
		}
		removed = append(removed, a.Out)
	}
	return removed, nil
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
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := lock.Write(f, l, ToolName, ToolVersion); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
