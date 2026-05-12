package pin

import (
	"fmt"
	"strings"

	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
)

// enforceTrust applies trust policy. Precedence: CLI flags override
// manifest, which overrides per-entry. trusted_workflows is additive
// — a matching workflow URI satisfies publisher-matches-repository
// even when repository.url disagrees.
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

func publisherMismatch(a *lock.Asset, trustedWorkflows []string) string {
	want := normaliseRepoURL(a.Repository)
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

// normaliseRepoURL strips scheme, trailing .git, slash, and
// /tree/<branch>/ or /blob/ subpaths so monorepo subdirectory
// references compare equal to the bare repo URL.
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
