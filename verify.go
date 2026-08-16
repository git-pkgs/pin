package pin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/git-pkgs/integrity"
	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/source/npm"
	"github.com/git-pkgs/purl"
)

// VerifyOptions: Strict turns the cheap on-disk re-hash into a
// tarball re-derive for npm assets.
type VerifyOptions struct {
	Dir         string
	Lock        string
	Strict      bool
	RegistryURL string
}

// VerifyResult. Failed reports whether any drift or missing-file was
// seen; Extra is informational unless opts.Strict.
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
	c := New(ClientOptions{RegistryURL: opts.RegistryURL, SignatureMode: npm.SignatureModeOff})
	return c.Verify(opts)
}

// Verify re-hashes every file under the lockfile's OutDir and
// compares against the recorded integrity. With opts.Strict, npm
// assets additionally re-derive their per-file integrity by
// re-fetching the registry tarball.
func (c *Client) Verify(opts VerifyOptions) (*VerifyResult, error) {
	if opts.Lock == "" {
		opts.Lock = DefaultLock
	}

	l, err := readLock(filepath.Join(opts.Dir, opts.Lock))
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, fmt.Errorf("%w at %s", ErrNoLockfile, filepath.Join(opts.Dir, opts.Lock))
	}

	res := &VerifyResult{}
	known := map[string]bool{}

	for _, a := range l.Assets {
		known[a.Out] = true
		p := filepath.Join(opts.Dir, l.OutDir, filepath.FromSlash(a.Out))
		got, matches, err := verifyFile(p, a.Integrity)
		if errors.Is(err, fs.ErrNotExist) {
			res.Missing = append(res.Missing, a.Out)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", a.Out, err)
		}
		if !matches {
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
		drifts, err := c.verifyStrictNPM(l)
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

// verifyStrictNPM re-fetches each npm tarball, re-extracts the
// lockfile's claimed files, and verifies their bytes against the
// recorded integrity. forge and url sources are skipped because
// their per-file hashes already are the anchor.
func (c *Client) verifyStrictNPM(l *lock.Lock) ([]Drift, error) {
	src := c.NPM

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
		derived := map[string][]byte{}
		for _, f := range resolved.Files {
			derived[f.Path] = f.Content
		}
		for _, a := range assets {
			content, ok := derived[a.Path]
			if !ok {
				drifts = append(drifts, Drift{Out: a.Out, Expected: a.Integrity, Actual: "<not in tarball>"})
				continue
			}
			got, matches, err := verifyIntegrity(bytes.NewReader(content), a.Integrity)
			if err != nil {
				return nil, fmt.Errorf("verify %s integrity: %w", a.Path, err)
			}
			if !matches {
				drifts = append(drifts, Drift{Out: a.Out, Expected: a.Integrity, Actual: got})
			}
		}
	}
	return drifts, nil
}

func verifyFile(path, expected string) (string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = f.Close() }()
	return verifyIntegrity(f, expected)
}

func verifyIntegrity(source io.Reader, expectedValue string) (string, bool, error) {
	var expected integrity.SRI
	algorithms := []integrity.Algorithm{integrity.SHA384}
	if expectedValue != "" {
		var err error
		expected, err = integrity.ParseSRI(expectedValue)
		if err != nil {
			return "", false, fmt.Errorf("parse expected integrity: %w", err)
		}
		algorithms = algorithms[:0]
		for _, digest := range expected {
			algorithms = append(algorithms, digest.Algorithm())
		}
	}

	reader, err := integrity.NewReader(source, algorithms...)
	if err != nil {
		return "", false, err
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return "", false, err
	}
	result := reader.Result()
	actual := integrity.FormatSRI(result.Digests)
	matches := len(expected) > 0 && result.Verify(expected) == nil
	return actual, matches, nil
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
