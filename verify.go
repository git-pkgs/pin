package pin

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/source/npm"
	"github.com/git-pkgs/purl"
)

type VerifyOptions struct {
	Dir         string
	Lock        string
	Strict      bool
	RegistryURL string
}

type VerifyResult struct {
	OK      []string
	Missing []string
	Drifted []Drift
	Extra   []string
}

type Drift struct {
	Out      string
	Expected string
	Actual   string
}

func (r *VerifyResult) Failed() bool {
	return len(r.Missing) > 0 || len(r.Drifted) > 0
}

func Verify(opts VerifyOptions) (*VerifyResult, error) {
	if opts.Lock == "" {
		opts.Lock = DefaultLock
	}

	l, err := readLock(filepath.Join(opts.Dir, opts.Lock))
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, fmt.Errorf("no lockfile at %s; run sync first", filepath.Join(opts.Dir, opts.Lock))
	}

	res := &VerifyResult{}
	known := map[string]bool{}

	for _, a := range l.Assets {
		known[a.Out] = true
		p := filepath.Join(opts.Dir, l.OutDir, filepath.FromSlash(a.Out))
		got, err := hashFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			res.Missing = append(res.Missing, a.Out)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", a.Out, err)
		}
		if got != a.Integrity {
			res.Drifted = append(res.Drifted, Drift{Out: a.Out, Expected: a.Integrity, Actual: got})
			continue
		}
		res.OK = append(res.OK, a.Out)
	}

	extra, err := findExtras(filepath.Join(opts.Dir, l.OutDir), known)
	if err != nil {
		return nil, err
	}
	res.Extra = extra

	if opts.Strict {
		drifts, err := verifyStrictNPM(l, opts.RegistryURL)
		if err != nil {
			return nil, err
		}
		res.Drifted = append(res.Drifted, drifts...)
	}

	sort.Strings(res.OK)
	sort.Strings(res.Missing)
	sort.Strings(res.Extra)
	return res, nil
}

// verifyStrictNPM re-fetches each npm package's tarball from the registry,
// re-extracts the files the lockfile claims, and compares the derived
// per-file SHA-384 to the recorded integrity. Mismatches indicate either
// a tampered lockfile or an upstream that re-published the same version
// with different bytes (npm does not permit this, so it's a hard failure).
//
// forge and url sources are skipped: their per-file SHA-384 IS the
// anchor (no separate tarball to re-derive from), so the standard
// on-disk verify already provides equivalent assurance.
func verifyStrictNPM(l *lock.Lock, registryURL string) ([]Drift, error) {
	src := npm.New(npm.Options{RegistryURL: registryURL, SignatureMode: npm.SignatureModeOff})

	byPkg := map[string][]lock.Asset{}
	var keys []string
	for _, a := range l.Assets {
		if !strings.HasPrefix(a.PURL, "pkg:npm/") {
			continue
		}
		if _, seen := byPkg[a.PURL]; !seen {
			keys = append(keys, a.PURL)
		}
		byPkg[a.PURL] = append(byPkg[a.PURL], a)
	}
	sort.Strings(keys)

	var drifts []Drift
	ctx := context.Background()
	for _, key := range keys {
		assets := byPkg[key]
		p, err := purl.Parse(key)
		if err != nil {
			return nil, fmt.Errorf("parse purl %q: %w", key, err)
		}
		paths := make([]string, len(assets))
		for i, a := range assets {
			paths[i] = a.Path
		}
		resolved, err := src.Resolve(ctx, p, paths)
		if err != nil {
			return nil, fmt.Errorf("re-derive %s: %w", key, err)
		}
		derived := map[string]string{}
		for _, f := range resolved.Files {
			derived[f.Path] = f.Integrity
		}
		for _, a := range assets {
			got, ok := derived[a.Path]
			if !ok {
				drifts = append(drifts, Drift{Out: a.Out, Expected: a.Integrity, Actual: "<not in tarball>"})
				continue
			}
			if got != a.Integrity {
				drifts = append(drifts, Drift{Out: a.Out, Expected: a.Integrity, Actual: got})
			}
		}
	}
	return drifts, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha512.New384()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha384-" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func findExtras(root string, known map[string]bool) ([]string, error) {
	var extras []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, ".tmp") {
			return nil
		}
		if !known[rel] {
			extras = append(extras, rel)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return extras, err
}

func (r *VerifyResult) Summary() string {
	parts := []string{fmt.Sprintf("%d ok", len(r.OK))}
	if len(r.Missing) > 0 {
		parts = append(parts, fmt.Sprintf("%d missing", len(r.Missing)))
	}
	if len(r.Drifted) > 0 {
		parts = append(parts, fmt.Sprintf("%d drifted", len(r.Drifted)))
	}
	if len(r.Extra) > 0 {
		parts = append(parts, fmt.Sprintf("%d extra", len(r.Extra)))
	}
	return strings.Join(parts, ", ")
}
