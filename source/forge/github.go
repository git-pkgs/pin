package forge

import (
	"context"
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
	}

	return &Resolved{
		PURL:             withRevision(p, sha),
		Name:             owner + "/" + repo,
		Version:          ref,
		PackageIntegrity: sha,
		SourceRepository: fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		Files:            resolved,
	}, nil
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
