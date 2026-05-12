package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

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
	Time     map[string]string          `json:"time"`
}

type PackageStatus struct {
	Latest              string
	LatestTime          string
	LastPublish         string
	Deprecated          string
	Yanked              bool
	License             string
	LatestLicense       string
	LockedHasProvenance bool
	LatestHasProvenance bool
}

// Status reports registry-side health signals for a locked package version.
func (s *Source) Status(ctx context.Context, name, lockedVersion string) (*PackageStatus, error) {
	doc, err := s.fetchPackageDoc(ctx, name)
	if err != nil {
		return nil, err
	}
	st := &PackageStatus{
		Latest:      doc.DistTags["latest"],
		LastPublish: doc.Time["modified"],
	}
	if st.Latest != "" {
		st.LatestTime = doc.Time[st.Latest]
		st.LatestHasProvenance = versionHasProvenance(doc.Versions[st.Latest])
		st.LatestLicense = parseLicenseFromVersionDoc(doc.Versions[st.Latest])
	}

	raw, ok := doc.Versions[lockedVersion]
	if !ok {
		st.Yanked = true
		return st, nil
	}
	var v struct {
		Deprecated string          `json:"deprecated"`
		License    json.RawMessage `json:"license"`
	}
	_ = json.Unmarshal(raw, &v)
	st.Deprecated = v.Deprecated
	st.License = parseLicense(v.License)
	st.LockedHasProvenance = versionHasProvenance(raw)
	return st, nil
}

// parseLicenseFromVersionDoc extracts the license field from a raw npm
// version document. Used by Status to surface the latest version's
// license alongside the locked version's for license_change detection.
func parseLicenseFromVersionDoc(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v struct {
		License json.RawMessage `json:"license"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return parseLicense(v.License)
}

func versionHasProvenance(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var v struct {
		Dist struct {
			Attestations []json.RawMessage `json:"attestations"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return len(v.Dist.Attestations) > 0
}

// ResolveVersion turns a manifest constraint into an exact published version.
// Exact pins bypass the cooldown (the user named the version explicitly).
// Ranges fall back to the next-highest satisfying version outside the
// cooldown window. Dist-tags fail with a clear error when the tag resolves
// to a version that's still inside the window.
func (s *Source) ResolveVersion(ctx context.Context, name, constraint string, cooldown time.Duration) (string, error) {
	switch Classify(constraint) {
	case KindExact:
		return constraint, nil
	case KindDistTag:
		return s.resolveDistTag(ctx, name, constraint, cooldown)
	case KindRange:
		return s.resolveRange(ctx, name, constraint, cooldown)
	}
	return "", fmt.Errorf("%s: unable to classify constraint %q", name, constraint)
}

func (s *Source) resolveDistTag(ctx context.Context, name, tag string, cooldown time.Duration) (string, error) {
	doc, err := s.fetchPackageDoc(ctx, name)
	if err != nil {
		return "", err
	}
	v, ok := doc.DistTags[tag]
	if !ok {
		return "", fmt.Errorf("%s: dist-tag %q not found", name, tag)
	}
	if cooldown > 0 {
		if age, ok := versionAge(doc, v); ok && age < cooldown {
			return "", fmt.Errorf("%s: dist-tag %q resolves to %s published %s ago, inside the %s cooldown; pin an exact version or shorten min_release_age", name, tag, v, age.Truncate(time.Minute), cooldown)
		}
	}
	return v, nil
}

func (s *Source) resolveRange(ctx context.Context, name, constraint string, cooldown time.Duration) (string, error) {
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
		if !r.Contains(v) {
			continue
		}
		if cooldown > 0 {
			if age, ok := versionAge(doc, v); ok && age < cooldown {
				continue
			}
		}
		candidates = append(candidates, v)
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("%s: no published version satisfies %q (after %s cooldown)", name, constraint, cooldown)
	}
	slices.SortFunc(candidates, vers.Compare)
	return candidates[len(candidates)-1], nil
}

func versionAge(doc *packageDoc, version string) (time.Duration, bool) {
	t, ok := doc.Time[version]
	if !ok {
		return 0, false
	}
	parsed, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return 0, false
	}
	return time.Since(parsed), true
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
