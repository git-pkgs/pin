// Package rawurl implements source.Resolver for url: manifest sources.
// The integrity model is TOFU: the first fetch records a SHA-384 SRI of
// the bytes; subsequent fetches verify against the recorded hash. No
// upstream anchor is possible because the URL points at arbitrary bytes
// that the publisher controls without any registry intermediation.
package rawurl

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"path"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries/client"

	"github.com/git-pkgs/pin/internal/safehttp"
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
		c = client.NewClient()
		c.HTTPClient = safehttp.New(c.HTTPClient, safehttp.Options{})
	}
	return &Source{http: c}
}

type Resolved = source.Resolved
type ResolvedFile = source.ResolvedFile

// Resolve fetches the URL recorded in the purl's download_url qualifier.
// The purl carries name + version as user-supplied identifiers; the URL
// is what gets fetched. `files` is ignored — a url source is exactly one
// file by construction.
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
