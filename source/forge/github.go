package forge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/purl"
	"golang.org/x/sync/errgroup"

	"github.com/git-pkgs/pin/source/attestation"
)

// forgeFileConcurrency caps the per-entry parallelism for jsdelivr file
// fetches inside a single forge resolve. Small enough that an outer
// Sync with the default 8 entry concurrency doesn't fan out into
// hundreds of CDN connections when several forge entries each list many
// files.
const forgeFileConcurrency = 4

const fullSHALen = 40

// fileFetch carries the result of one jsdelivr file fetch plus any
// attestation lookup that fired off the same content. Each Goroutine
// in resolveGitHub writes its own indexed slot, so there is no shared
// state and the post-processing can pick the first non-nil attestation
// by index for an order-deterministic result.
type fileFetch struct {
	rf     ResolvedFile
	att    *Attestation
	attRaw []byte
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

	// Materialise the resolved-files slice in input order (slot writes
	// are race-free; the goroutine fan-in via g.Wait establishes the
	// happens-before for the reads here).
	resolved := make([]ResolvedFile, len(files))
	for i, f := range fetches {
		resolved[i] = f.rf
	}

	// Pick the first attestation by file index. Same selection rule as
	// the previous serial loop; with parallel fetches we walk the
	// indexed slots rather than the natural iteration order so the
	// result is independent of completion order.
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

// fetchGitHubAttestation queries GitHub's attestations API for a file's
// SHA-256 digest. Returns the parsed Attestation and the raw bundle bytes
// (for cryptographic verification by the caller), or (nil, nil) when no
// matching SLSA Provenance v1 bundle exists. A network error is treated
// as "no attestation" rather than a sync failure — the attestation is
// supplementary metadata, not a fetch dependency.
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
	if len(ref) == fullSHALen && isHex(ref) {
		return ref, nil
	}
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", strings.TrimRight(s.opts.GitHubAPI, "/"), owner, repo, ref)
	var resp struct {
		SHA string `json:"sha"`
	}
	if err := s.http.GetJSON(ctx, url, &resp); err != nil {
		return "", fmt.Errorf("resolve %s/%s ref %q to commit: %w", owner, repo, ref, err)
	}
	if resp.SHA == "" {
		return "", fmt.Errorf("resolve %s/%s ref %q: empty SHA in response", owner, repo, ref)
	}
	return resp.SHA, nil
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
