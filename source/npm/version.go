package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/git-pkgs/vers"
)

type ConstraintKind int

const (
	KindExact ConstraintKind = iota
	KindRange
	KindDistTag
)

const minSemverParts = 3

// Classify decides whether a manifest version string is an exact pin
// ("2.0.6"), a semver range ("^2.0", "~1.2.3", ">=1.0 <2.0", "1.x"), or
// an npm dist-tag ("latest", "next").
func Classify(constraint string) ConstraintKind {
	if isExactVersion(constraint) {
		return KindExact
	}
	if isDistTagName(constraint) {
		return KindDistTag
	}
	if _, err := vers.ParseNative(constraint, "npm"); err == nil {
		return KindRange
	}
	return KindDistTag
}

func isDistTagName(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
		return false
	}
	return !strings.ContainsAny(s, " *|^~<>=")
}

func isExactVersion(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	if strings.ContainsAny(s, " *|^~<>=") {
		return false
	}
	base, _, _ := strings.Cut(s, "-")
	base, _, _ = strings.Cut(base, "+")
	parts := strings.Split(base, ".")
	if len(parts) < minSemverParts {
		return false
	}
	for _, p := range parts {
		if p == "x" || p == "X" {
			return false
		}
	}
	return true
}

type packageDoc struct {
	DistTags map[string]string          `json:"dist-tags"`
	Versions map[string]json.RawMessage `json:"versions"`
}

// ResolveVersion turns a manifest constraint into an exact published version.
func (s *Source) ResolveVersion(ctx context.Context, name, constraint string) (string, error) {
	switch Classify(constraint) {
	case KindExact:
		return constraint, nil
	case KindDistTag:
		doc, err := s.fetchPackageDoc(ctx, name)
		if err != nil {
			return "", err
		}
		if v, ok := doc.DistTags[constraint]; ok {
			return v, nil
		}
		return "", fmt.Errorf("%s: dist-tag %q not found", name, constraint)
	case KindRange:
		return s.resolveRange(ctx, name, constraint)
	}
	return "", fmt.Errorf("%s: unable to classify constraint %q", name, constraint)
}

func (s *Source) resolveRange(ctx context.Context, name, constraint string) (string, error) {
	doc, err := s.fetchPackageDoc(ctx, name)
	if err != nil {
		return "", err
	}
	r, err := vers.ParseNative(constraint, "npm")
	if err != nil {
		return "", err
	}
	includePrerelease := strings.Contains(constraint, "-")
	var candidates []string
	for v := range doc.Versions {
		if !includePrerelease && isPrerelease(v) {
			continue
		}
		if r.Contains(v) {
			candidates = append(candidates, v)
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("%s: no published version satisfies %q", name, constraint)
	}
	slices.SortFunc(candidates, vers.Compare)
	return candidates[len(candidates)-1], nil
}

// IsSticky reports whether a locked version still satisfies a manifest
// constraint, so the locked version can be reused without re-resolving.
// Dist-tags are never sticky (the tag can move under a stable manifest).
func IsSticky(lockedVersion, constraint string) bool {
	if lockedVersion == "" {
		return false
	}
	switch Classify(constraint) {
	case KindExact:
		return lockedVersion == constraint
	case KindRange:
		ok, err := vers.Satisfies(lockedVersion, constraint, "npm")
		return err == nil && ok
	case KindDistTag:
		return false
	}
	return false
}

func isPrerelease(version string) bool {
	base, _, _ := strings.Cut(version, "+")
	return strings.Contains(base, "-")
}

func (s *Source) fetchPackageDoc(ctx context.Context, name string) (*packageDoc, error) {
	u := strings.TrimRight(s.opts.RegistryURL, "/") + "/" + name
	var doc packageDoc
	if err := s.http.GetJSON(ctx, u, &doc); err != nil {
		return nil, fmt.Errorf("fetch %s package metadata: %w", name, err)
	}
	return &doc, nil
}
