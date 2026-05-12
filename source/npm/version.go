package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/git-pkgs/cooldown"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vers"
)

const ecosystem = "npm"

type ConstraintKind int

const (
	KindExact ConstraintKind = iota
	KindRange
	KindDistTag
)

const minSemverParts = 3

// Classify maps a manifest version string to exact / range / dist-tag.
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

// Status reports registry-side signals for a locked version.
// p.Version is the locked version to look up. p's repository_url
// qualifier, if present, overrides the Source's default registry.
func (s *Source) Status(ctx context.Context, p *purl.PURL) (*PackageStatus, error) {
	doc, err := s.fetchPackageDoc(ctx, p)
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

	raw, ok := doc.Versions[p.Version]
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

// ResolveVersion turns a manifest constraint into an exact version.
// Exact pins bypass cooldown. Ranges fall back to the next-highest
// satisfying version outside the window. Dist-tags inside the window
// error rather than silently picking an older version. cool may be
// nil to disable cooldown. p's repository_url qualifier, if present,
// overrides the Source's default registry for this call.
func (s *Source) ResolveVersion(ctx context.Context, p *purl.PURL, constraint string, cool *cooldown.Config) (string, error) {
	switch Classify(constraint) {
	case KindExact:
		return constraint, nil
	case KindDistTag:
		return s.resolveDistTag(ctx, p, constraint, cool)
	case KindRange:
		return s.resolveRange(ctx, p, constraint, cool)
	}
	return "", fmt.Errorf("%s: unable to classify constraint %q", p.FullName(), constraint)
}

func (s *Source) resolveDistTag(ctx context.Context, p *purl.PURL, tag string, cool *cooldown.Config) (string, error) {
	doc, err := s.fetchPackageDoc(ctx, p)
	if err != nil {
		return "", err
	}
	v, ok := doc.DistTags[tag]
	if !ok {
		return "", fmt.Errorf("%s: dist-tag %q not found", p.FullName(), tag)
	}
	if cool == nil {
		return v, nil
	}
	purlKey := p.WithoutVersion().String()
	publishedAt := versionPublishedAt(doc, v)
	if !cool.IsAllowed(ecosystem, purlKey, publishedAt) {
		cd := cool.For(ecosystem, purlKey)
		age := time.Since(publishedAt).Truncate(time.Minute)
		return "", fmt.Errorf("%s: dist-tag %q resolves to %s published %s ago, inside the %s cooldown; pin an exact version or shorten min_release_age", p.FullName(), tag, v, age, cd)
	}
	return v, nil
}

func (s *Source) resolveRange(ctx context.Context, p *purl.PURL, constraint string, cool *cooldown.Config) (string, error) {
	doc, err := s.fetchPackageDoc(ctx, p)
	if err != nil {
		return "", err
	}
	includePrerelease := strings.Contains(constraint, "-")
	purlKey := p.WithoutVersion().String()
	candidates := make([]string, 0, len(doc.Versions))
	for v := range doc.Versions {
		if !includePrerelease && isPrerelease(v) {
			continue
		}
		if cool != nil && !cool.IsAllowed(ecosystem, purlKey, versionPublishedAt(doc, v)) {
			continue
		}
		candidates = append(candidates, v)
	}
	picked, err := vers.HighestSatisfying(candidates, constraint, "npm")
	if err != nil {
		return "", err
	}
	if picked == "" {
		cd := time.Duration(0)
		if cool != nil {
			cd = cool.For(ecosystem, purlKey)
		}
		return "", fmt.Errorf("%s: no published version satisfies %q (after %s cooldown)", p.FullName(), constraint, cd)
	}
	return picked, nil
}

// versionPublishedAt returns the zero time when the registry omits
// or malforms the publish timestamp. cooldown.IsAllowed treats zero
// as "allow", which matches the old "no age = let it through" rule.
func versionPublishedAt(doc *packageDoc, version string) time.Time {
	t, ok := doc.Time[version]
	if !ok {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// IsSticky reports whether the locked version still satisfies the
// constraint and can be reused without re-resolving. Dist-tags are
// never sticky — the tag can move under a stable manifest.
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

func (s *Source) fetchPackageDoc(ctx context.Context, p *purl.PURL) (*packageDoc, error) {
	u := strings.TrimRight(s.registryURLFor(p), "/") + "/" + p.FullName()
	var doc packageDoc
	if err := s.http.GetJSON(ctx, u, &doc); err != nil {
		return nil, fmt.Errorf("fetch %s package metadata: %w", p.FullName(), err)
	}
	return &doc, nil
}

// registryURLFor returns p's repository_url qualifier when present,
// otherwise the Source's configured default registry.
func (s *Source) registryURLFor(p *purl.PURL) string {
	if p != nil {
		if u := p.RepositoryURL(); u != "" {
			return u
		}
	}
	return s.opts.RegistryURL
}
