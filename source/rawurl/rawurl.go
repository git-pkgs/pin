// Package rawurl implements source.Resolver for url: manifest sources.
// Integrity is TOFU: the first fetch records a SHA-384 SRI; later
// fetches verify against it. No upstream anchor exists — the publisher
// controls the bytes without registry intermediation.
package rawurl

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"path"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries/client"

	"github.com/git-pkgs/pin/source"
)

type Options struct {
	HTTPClient *client.Client
}

type Source struct {
	http *client.Client
}

func New(opts Options) *Source {
	c := opts.HTTPClient
	if c == nil {
		c = client.NewClient(client.WithSafeHTTP())
	}
	return &Source{http: c}
}

type Resolved = source.Resolved
type ResolvedFile = source.ResolvedFile

// Resolve fetches the purl's download_url qualifier. files is
// ignored — a url source is exactly one file by construction.
func (s *Source) Resolve(ctx context.Context, p *purl.PURL, _ []string) (*Resolved, error) {
	url := p.Qualifier("download_url")
	if url == "" {
		return nil, fmt.Errorf("%s@%s: url source missing download_url qualifier", p.Name, p.Version)
	}

	body, err := s.http.GetBody(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	h := sha512.Sum384(body)
	sri := "sha384-" + base64.StdEncoding.EncodeToString(h[:])

	return &Resolved{
		PURL:    p.String(),
		Name:    p.Name,
		Version: p.Version,
		Files: []ResolvedFile{{
			Path:      path.Base(url),
			Integrity: sri,
			Size:      int64(len(body)),
			URL:       url,
			Content:   body,
		}},
	}, nil
}
