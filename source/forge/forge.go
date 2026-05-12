// Package forge resolves manifest entries against git forges.
// Dispatch is purl-driven: pkg:github/owner/repo@ref routes to the
// GitHub implementation; pkg:gitlab, pkg:bitbucket etc. plug in via
// the type switch without touching the public surface or lockfile
// schema.
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

	// API and CDN base URLs; overridable for tests and self-hosted.
	GitHubAPI   string
	JSDelivrCDN string

	// Verifier validates each attestation bundle the forge path
	// records. Nil = record-only.
	Verifier source.ProvenanceVerifier
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
		c = client.NewClient(client.WithSafeHTTP())
	}
	return &Source{opts: opts, http: c}
}

type Resolved = source.Resolved
type ResolvedFile = source.ResolvedFile
type Attestation = source.Attestation

// Resolve fetches files for a forge-hosted package. The ref
// (p.Version) is resolved to a commit SHA which becomes
// PackageIntegrity and a vcs_revision purl qualifier.
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

func withRevision(p *purl.PURL, commitSHA string) string {
	q := map[string]string{"vcs_revision": commitSHA}
	return purl.New(p.Type, p.Namespace, p.Name, p.Version, q).String()
}
