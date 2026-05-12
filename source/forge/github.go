package forge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/purl"
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
			if att := s.fetchGitHubAttestation(ctx, owner, repo, body); att != nil {
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
// SHA-256 digest. Returns nil when no attestation is recorded for these
// bytes (the common case for individual repo files; attestations
// typically attach to release-asset archives). A network error here is
// treated as "no attestation" rather than a sync failure — the
// attestation is supplementary metadata, not a fetch dependency.
func (s *Source) fetchGitHubAttestation(ctx context.Context, owner, repo string, body []byte) *Attestation {
	digest := sha256.Sum256(body)
	url := fmt.Sprintf("%s/repos/%s/%s/attestations/sha256:%s",
		strings.TrimRight(s.opts.GitHubAPI, "/"), owner, repo, hex.EncodeToString(digest[:]))
	var list struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := s.http.GetJSON(ctx, url, &list); err != nil {
		return nil
	}
	for _, a := range list.Attestations {
		att, err := parseGitHubBundle(a.Bundle)
		if err != nil || att == nil {
			continue
		}
		if !strings.HasPrefix(att.PredicateType, "https://slsa.dev/provenance/") {
			continue
		}
		return att
	}
	return nil
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
