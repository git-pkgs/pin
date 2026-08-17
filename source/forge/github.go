package forge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/git-pkgs/attestation"
	githubforge "github.com/git-pkgs/forge/github"
	"github.com/git-pkgs/purl"
	"golang.org/x/sync/errgroup"
)

// forgeFileConcurrency caps per-entry parallelism so an outer Sync
// with 8-way entry concurrency doesn't fan out into hundreds of CDN
// connections.
const forgeFileConcurrency = 4

type fileFetch struct {
	rf     ResolvedFile
	att    *Attestation
	attRaw []byte
}

type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(clone)
}

func (s *Source) resolveGitHub(ctx context.Context, p *purl.PURL, files []string) (*Resolved, error) {
	owner, repo, ref := p.Namespace, p.Name, p.Version
	sha, err := s.githubResolveSHA(ctx, owner, repo, ref)
	if err != nil {
		return nil, err
	}

	fetches := make([]fileFetch, len(files))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(forgeFileConcurrency)
	for i, path := range files {
		g.Go(func() error {
			url := fmt.Sprintf("%s/gh/%s/%s@%s/%s",
				strings.TrimRight(s.opts.JSDelivrCDN, "/"), owner, repo, sha, path)
			body, err := s.http.GetBody(gctx, url)
			if err != nil {
				return fmt.Errorf("%s/%s@%s: fetch %s: %w", owner, repo, ref, path, err)
			}
			att, raw := s.fetchGitHubAttestation(gctx, owner, repo, body)
			fetches[i] = fileFetch{
				rf: ResolvedFile{
					Path:      path,
					Integrity: hashSRI384(body),
					Size:      int64(len(body)),
					URL:       url,
					Content:   body,
				},
				att:    att,
				attRaw: raw,
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// g.Wait is the happens-before for these reads.
	resolved := make([]ResolvedFile, len(files))
	for i, f := range fetches {
		resolved[i] = f.rf
	}

	// First attestation by file index — deterministic regardless of
	// completion order.
	var att *Attestation
	for i, f := range fetches {
		if f.att == nil {
			continue
		}
		if s.opts.Verifier != nil {
			digest := sha256.Sum256(f.rf.Content)
			if err := s.opts.Verifier.VerifyBundle(ctx, f.attRaw, "sha256", digest[:]); err != nil {
				return nil, fmt.Errorf("%s/%s@%s: provenance verification failed for %s: %w",
					owner, repo, ref, files[i], err)
			}
		}
		att = f.att
		break
	}

	return &Resolved{
		PURL:             withRevision(p, sha),
		Name:             owner + "/" + repo,
		Version:          ref,
		PackageIntegrity: sha,
		SourceRepository: fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		Attestation:      att,
		Files:            resolved,
	}, nil
}

// fetchGitHubAttestation queries GitHub's attestations API for the
// file's SHA-256. Network errors degrade to (nil, nil): attestations
// are supplementary metadata, not a fetch dependency.
func (s *Source) fetchGitHubAttestation(ctx context.Context, owner, repo string, body []byte) (*Attestation, []byte) {
	digest := sha256.Sum256(body)
	url := fmt.Sprintf("%s/repos/%s/%s/attestations/sha256:%s",
		strings.TrimRight(s.opts.GitHubAPI, "/"), owner, repo, hex.EncodeToString(digest[:]))
	var list struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := s.http.GetJSON(ctx, url, &list); err != nil {
		return nil, nil
	}
	for _, a := range list.Attestations {
		parsed, err := attestation.Parse(a.Bundle)
		if err != nil || parsed == nil {
			continue
		}
		if !strings.HasPrefix(parsed.PredicateType, "https://slsa.dev/provenance/") {
			continue
		}
		return &Attestation{
			PredicateType:    parsed.PredicateType,
			BuilderID:        parsed.BuilderID,
			SourceRepository: parsed.SourceRepository,
			SourceRevision:   parsed.SourceRevision,
			SignerIdentity:   parsed.SignerIdentity,
		}, a.Bundle
	}
	return nil, nil
}

func (s *Source) githubResolveSHA(ctx context.Context, owner, repo, ref string) (string, error) {
	httpClient := *s.http.HTTPClient
	transport := httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	httpClient.Transport = userAgentTransport{base: transport, userAgent: s.http.UserAgent}

	resolver, err := githubforge.NewCommitResolverWithBase(s.opts.GitHubAPI, "", &httpClient)
	if err != nil {
		return "", fmt.Errorf("create GitHub commit resolver: %w", err)
	}
	return resolver.ResolveCommit(ctx, owner, repo, ref)
}
