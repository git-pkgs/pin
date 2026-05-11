package pin

import (
	"strings"
	"testing"

	"github.com/git-pkgs/pin/lock"
)

func TestAssertPublisherMatchesRepository(t *testing.T) {
	cases := []struct {
		name    string
		assets  []lock.Asset
		wantErr string
	}{
		{
			"matching",
			[]lock.Asset{{
				Name:             "sigstore",
				Version:          "3.0.0",
				PURL:             "pkg:npm/sigstore@3.0.0",
				SourceRepository: "https://github.com/sigstore/sigstore-js",
				Attestation: &lock.Attestation{
					SourceRepository: "https://github.com/sigstore/sigstore-js",
				},
			}},
			"",
		},
		{
			"trailing-git-suffix",
			[]lock.Asset{{
				Name:             "x",
				Version:          "1.0.0",
				PURL:             "pkg:npm/x@1.0.0",
				SourceRepository: "https://github.com/owner/repo",
				Attestation: &lock.Attestation{
					SourceRepository: "https://github.com/owner/repo.git",
				},
			}},
			"",
		},
		{
			"mismatch",
			[]lock.Asset{{
				Name:             "evil",
				Version:          "1.0.0",
				PURL:             "pkg:npm/evil@1.0.0",
				SourceRepository: "https://github.com/legitimate/repo",
				Attestation: &lock.Attestation{
					SourceRepository: "https://github.com/attacker/repo",
				},
			}},
			"evil@1.0.0",
		},
		{
			"no attestation skips",
			[]lock.Asset{{
				Name:             "x",
				Version:          "1.0.0",
				SourceRepository: "https://github.com/o/r",
			}},
			"",
		},
		{
			"missing repository skips (can't compare)",
			[]lock.Asset{{
				Name:    "x",
				Version: "1.0.0",
				Attestation: &lock.Attestation{
					SourceRepository: "https://github.com/o/r",
				},
			}},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := assertPublisherMatchesRepository(&lock.Lock{Assets: tc.assets})
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
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
