package pin

import (
	"strings"
	"testing"

	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
)

func boolPtr(b bool) *bool { return &b }

func TestEnforceTrust_PublisherMismatch(t *testing.T) {
	m := &manifest.Manifest{Assets: []manifest.Entry{{Name: "evil", Version: "1.0.0"}}}
	l := &lock.Lock{Assets: []lock.Asset{{
		Name:             "evil",
		Version:          "1.0.0",
		PURL:             "pkg:npm/evil@1.0.0",
		SourceRepository: "https://github.com/legitimate/repo",
		Attestation: &lock.Attestation{
			SourceRepository: "https://github.com/attacker/repo",
			BuilderID:        "https://github.com/attacker/repo/.github/workflows/release.yml@refs/tags/v1",
		},
	}}}
	err := enforceTrust(m, l, SyncOptions{RequirePublisherMatchesRepository: true})
	if err == nil || !strings.Contains(err.Error(), "evil@1.0.0") {
		t.Errorf("expected mismatch error, got %v", err)
	}
}

func TestEnforceTrust_TrustedWorkflowAllows(t *testing.T) {
	m := &manifest.Manifest{
		Trust: &manifest.Trust{
			RequirePublisherMatchesRepository: boolPtr(true),
			TrustedWorkflows:                  []string{"https://github.com/builder-org/builder/.github/workflows/release.yml"},
		},
		Assets: []manifest.Entry{{Name: "monorepo-pkg", Version: "1.0.0"}},
	}
	l := &lock.Lock{Assets: []lock.Asset{{
		Name:             "monorepo-pkg",
		Version:          "1.0.0",
		PURL:             "pkg:npm/monorepo-pkg@1.0.0",
		SourceRepository: "https://github.com/owner/declared-repo",
		Attestation: &lock.Attestation{
			SourceRepository: "https://github.com/builder-org/builder",
			BuilderID:        "https://github.com/builder-org/builder/.github/workflows/release.yml@refs/tags/v1",
		},
	}}}
	if err := enforceTrust(m, l, SyncOptions{}); err != nil {
		t.Errorf("trusted_workflows should permit the mismatch: %v", err)
	}
}

func TestEnforceTrust_RequireProvenanceMissing(t *testing.T) {
	m := &manifest.Manifest{
		Trust:  &manifest.Trust{RequireProvenance: boolPtr(true)},
		Assets: []manifest.Entry{{Name: "no-att", Version: "1.0.0"}},
	}
	l := &lock.Lock{Assets: []lock.Asset{{
		Name: "no-att", Version: "1.0.0", PURL: "pkg:npm/no-att@1.0.0",
	}}}
	err := enforceTrust(m, l, SyncOptions{})
	if err == nil || !strings.Contains(err.Error(), "no-att@1.0.0") {
		t.Errorf("expected provenance error, got %v", err)
	}
}

func TestEnforceTrust_PerEntryOptOut(t *testing.T) {
	m := &manifest.Manifest{
		Trust: &manifest.Trust{RequireProvenance: boolPtr(true)},
		Assets: []manifest.Entry{
			{Name: "no-att", Version: "1.0.0", Trust: &manifest.Trust{RequireProvenance: boolPtr(false)}},
		},
	}
	l := &lock.Lock{Assets: []lock.Asset{{
		Name: "no-att", Version: "1.0.0", PURL: "pkg:npm/no-att@1.0.0",
	}}}
	if err := enforceTrust(m, l, SyncOptions{}); err != nil {
		t.Errorf("per-entry opt-out should let it pass: %v", err)
	}
}

func TestEnforceTrust_CLIFlagForces(t *testing.T) {
	m := &manifest.Manifest{
		Assets: []manifest.Entry{
			{Name: "no-att", Version: "1.0.0", Trust: &manifest.Trust{RequireProvenance: boolPtr(false)}},
		},
	}
	l := &lock.Lock{Assets: []lock.Asset{{
		Name: "no-att", Version: "1.0.0", PURL: "pkg:npm/no-att@1.0.0",
	}}}
	err := enforceTrust(m, l, SyncOptions{StrictProvenance: true})
	if err == nil {
		t.Error("--strict-provenance should override per-entry opt-out")
	}
}

func TestNormaliseRepoURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/owner/repo":     "github.com/owner/repo",
		"https://github.com/owner/repo.git": "github.com/owner/repo",
		"https://github.com/owner/repo/":    "github.com/owner/repo",
		"http://github.com/Owner/Repo":      "github.com/owner/repo",
		"git@github.com:owner/repo.git":     "git@github.com:owner/repo",
		"":                                  "",
	}
	for in, want := range cases {
		if got := normaliseRepoURL(in); got != want {
			t.Errorf("normaliseRepoURL(%q) = %q, want %q", in, got, want)
		}
	}
}
