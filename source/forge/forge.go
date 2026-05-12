// Package forge resolves manifest entries against git forges. Dispatch
// is purl-driven: pkg:github/owner/repo@ref routes to the GitHub
// implementation, and adding pkg:gitlab, pkg:bitbucket etc. later is
// a matter of adding cases to the type switch without changing the
// public surface or the lockfile schema.
package forge

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries/client"

	"github.com/git-pkgs/pin/source"
)

type Options struct {
	HTTPClient *client.Client

	// API and CDN base URLs, overridable for tests and self-hosted forges.
	GitHubAPI   string
	JSDelivrCDN string
}

type Source struct {
	opts Options
	http *client.Client
}

func New(opts Options) *Source {
	if opts.GitHubAPI == "" {
		opts.GitHubAPI = "https://api.github.com"
	}
	if opts.JSDelivrCDN == "" {
		opts.JSDelivrCDN = "https://cdn.jsdelivr.net"
	}
	c := opts.HTTPClient
	if c == nil {
		c = client.NewClient()
	}
	return &Source{opts: opts, http: c}
}

type Resolved = source.Resolved
type ResolvedFile = source.ResolvedFile
type Attestation = source.Attestation

// Resolve fetches the named files for a forge-hosted package. The purl's
// Type selects the forge (only "github" in this build); Namespace is the
// owner, Name is the repo, Version is the ref (tag, branch, or commit
// SHA). The ref is resolved to a commit SHA which becomes the integrity
// anchor in PackageIntegrity and is recorded on the purl as a
// vcs_revision qualifier.
func (s *Source) Resolve(ctx context.Context, p *purl.PURL, files []string) (*Resolved, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("%s/%s: forge sources require an explicit files: list", p.Namespace, p.Name)
	}

	switch p.Type {
	case "github":
		return s.resolveGitHub(ctx, p, files)
	default:
		return nil, fmt.Errorf("forge type %q not supported in this build (only github)", p.Type)
	}
}

func hashSRI384(b []byte) string {
	h := sha512.Sum384(b)
	return "sha384-" + base64.StdEncoding.EncodeToString(h[:])
}

// withRevision returns p augmented with a vcs_revision qualifier so the
// commit SHA is recorded alongside the human-readable ref.
func withRevision(p *purl.PURL, commitSHA string) string {
	q := map[string]string{"vcs_revision": commitSHA}
	return purl.New(p.Type, p.Namespace, p.Name, p.Version, q).String()
}
