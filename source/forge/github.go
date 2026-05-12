package forge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/purl"

	"github.com/git-pkgs/pin/source/attestation"
)

const fullSHALen = 40

func (s *Source) resolveGitHub(ctx context.Context, p *purl.PURL, files []string) (*Resolved, error) {
	owner, repo, ref := p.Namespace, p.Name, p.Version
	sha, err := s.githubResolveSHA(ctx, owner, repo, ref)
	if err != nil {
		return nil, err
	}

	resolved := make([]ResolvedFile, 0, len(files))
	var attestation *Attestation
	for _, path := range files {
		url := fmt.Sprintf("%s/gh/%s/%s@%s/%s", strings.TrimRight(s.opts.JSDelivrCDN, "/"), owner, repo, sha, path)
		body, err := s.http.GetBody(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("%s/%s@%s: fetch %s: %w", owner, repo, ref, path, err)
		}
		resolved = append(resolved, ResolvedFile{
			Path:      path,
			Integrity: hashSRI384(body),
			Size:      int64(len(body)),
			URL:       url,
			Content:   body,
		})
		if attestation == nil {
			att, raw := s.fetchGitHubAttestation(ctx, owner, repo, body)
			if att != nil {
				if s.opts.Verifier != nil {
					digest := sha256.Sum256(body)
					if err := s.opts.Verifier.VerifyBundle(ctx, raw, "sha256", digest[:]); err != nil {
						return nil, fmt.Errorf("%s/%s@%s: provenance verification failed for %s: %w", owner, repo, ref, path, err)
					}
				}
				attestation = att
			}
		}
	}

	return &Resolved{
		PURL:             withRevision(p, sha),
		Name:             owner + "/" + repo,
		Version:          ref,
		PackageIntegrity: sha,
		SourceRepository: fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		Attestation:      attestation,
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
