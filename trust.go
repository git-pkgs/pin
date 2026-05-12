package pin

import (
	"fmt"
	"strings"

	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
)

// enforceTrust applies the manifest trust block plus CLI overrides
// (--strict-provenance, --require-publisher-matches-repository) to each
// entry. Per-entry trust overrides the manifest top level; CLI flags
// override both (you can't opt an entry out of a flag-forced policy).
// trusted_workflows is additive: any workflow URI listed there satisfies
// the publisher-matches-repository check even when the package's
// repository.url disagrees.
func enforceTrust(m *manifest.Manifest, l *lock.Lock, opts SyncOptions) error {
	entryByName := map[string]*manifest.Entry{}
	for i := range m.Assets {
		entryByName[m.Assets[i].Name] = &m.Assets[i]
	}

	var missing, mismatches []string
	seen := map[string]bool{}
	for _, a := range l.Assets {
		if seen[a.Name] {
			continue
		}
		seen[a.Name] = true

		t := manifest.Trust{}
		if e := entryByName[a.Name]; e != nil {
			t = m.EffectiveTrust(e)
		}
		if opts.StrictProvenance {
			yes := true
			t.RequireProvenance = &yes
		}
		if opts.RequirePublisherMatchesRepository {
			yes := true
			t.RequirePublisherMatchesRepository = &yes
		}

		if manifest.BoolValue(t.RequireProvenance) && strings.HasPrefix(a.PURL, "pkg:npm/") && a.Attestation == nil {
			missing = append(missing, a.Name+"@"+a.Version)
		}

		if manifest.BoolValue(t.RequirePublisherMatchesRepository) && a.Attestation != nil {
			if msg := publisherMismatch(&a, t.TrustedWorkflows); msg != "" {
				mismatches = append(mismatches, msg)
			}
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("%w for: %s", ErrProvenanceMissing, strings.Join(missing, ", "))
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("%w: %s", ErrPublisherMismatch, strings.Join(mismatches, "; "))
	}
	return nil
}

// publisherMismatch returns the error message when the attestation's
// source repository doesn't match the package's declared repository,
// or empty when it does or the trusted_workflows allowlist permits it.
func publisherMismatch(a *lock.Asset, trustedWorkflows []string) string {
	want := normaliseRepoURL(a.SourceRepository)
	got := normaliseRepoURL(a.Attestation.SourceRepository)
	if want == "" || got == "" || want == got {
		return ""
	}
	for _, wf := range trustedWorkflows {
		if a.Attestation.BuilderID == wf || strings.HasPrefix(a.Attestation.BuilderID, wf+"@") {
			return ""
		}
	}
	return fmt.Sprintf("%s@%s: attestation built from %s but package.json says %s", a.Name, a.Version, got, want)
}

// normaliseRepoURL strips scheme, trailing .git, trailing slash, and
// github-style subpaths (`/tree/<branch>/<path>`, `/blob/...`) so two
// URLs pointing at the same repo compare equal even when one references
// a subdirectory within a monorepo. Used by the publisher-matches
// comparison; the npm package has its own canonicalRepoURL that handles
// the git+/ssh:// shapes registries return.
func normaliseRepoURL(u string) string {
	u = strings.TrimSuffix(u, "/")
	u = strings.TrimSuffix(u, ".git")
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.ToLower(u)
	for _, sep := range []string{"/tree/", "/blob/"} {
		if i := strings.Index(u, sep); i >= 0 {
			u = u[:i]
		}
	}
	return u
}
