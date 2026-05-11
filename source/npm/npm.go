// Package npm resolves manifest entries against the npm registry, anchoring
// per-file integrity to the registry-published tarball hash.
package npm

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/git-pkgs/archives"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries/client"

	"github.com/git-pkgs/pin/source"
)

const (
	DefaultRegistryURL     = "https://registry.npmjs.org"
	DefaultMaxTarballBytes = 100 << 20 // 100 MiB
)

var entryPointFields = []string{"jsdelivr", "unpkg", "browser", "module", "main"} //nolint:goconst

type Options struct {
	RegistryURL     string
	MaxTarballBytes int64
	HTTPClient      *client.Client

	// test hook: forces a different package integrity to provoke a mismatch.
	overrideIntegrity func(name string) string
}

type Source struct {
	opts Options
	http *client.Client
}

func New(opts Options) *Source {
	if opts.RegistryURL == "" {
		opts.RegistryURL = DefaultRegistryURL
	}
	if opts.MaxTarballBytes == 0 {
		opts.MaxTarballBytes = DefaultMaxTarballBytes
	}
	c := opts.HTTPClient
	if c == nil {
		c = client.NewClient()
	}
	return &Source{opts: opts, http: c}
}

// Resolved and ResolvedFile are re-exported from source for compatibility.
type Resolved = source.Resolved
type ResolvedFile = source.ResolvedFile

type npmVersion struct {
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	License    json.RawMessage `json:"license"`
	Repository json.RawMessage `json:"repository"`
	Dist       struct {
		Tarball   string `json:"tarball"`
		Integrity string `json:"integrity"`
	} `json:"dist"`
}

// Resolve fetches the named files for the package identified by p (whose
// Type must be "npm"). When files is nil, the package's declared entry
// point is used.
func (s *Source) Resolve(ctx context.Context, p *purl.PURL, files []string) (*Resolved, error) {
	name := p.FullName()
	version := p.Version

	meta, err := s.fetchMetadata(ctx, name, version)
	if err != nil {
		return nil, err
	}

	tarball, err := s.fetchTarball(ctx, meta.Dist.Tarball)
	if err != nil {
		return nil, err
	}

	wantIntegrity := meta.Dist.Integrity
	if s.opts.overrideIntegrity != nil {
		wantIntegrity = s.opts.overrideIntegrity(name)
	}
	if err := verifyTarball(tarball, wantIntegrity); err != nil {
		return nil, fmt.Errorf("%s@%s: %w", name, version, err)
	}

	reader, err := archives.OpenBytesWithPrefix(name+".tgz", tarball, "package/")
	if err != nil {
		return nil, fmt.Errorf("open tarball: %w", err)
	}
	defer func() { _ = reader.Close() }()

	if files == nil {
		entry, eerr := defaultEntryPoint(reader)
		if eerr != nil {
			return nil, fmt.Errorf("%s@%s: %w", name, version, eerr)
		}
		files = []string{entry}
	}

	resolvedFiles, err := extractFiles(reader, files)
	if err != nil {
		return nil, fmt.Errorf("%s@%s: %w", name, version, err)
	}

	return &Resolved{
		Name:             meta.Name,
		Version:          meta.Version,
		PURL:             p.String(),
		PackageIntegrity: meta.Dist.Integrity,
		License:          parseLicense(meta.License),
		SourceRepository: parseRepository(meta.Repository),
		Files:            resolvedFiles,
	}, nil
}

func (s *Source) fetchMetadata(ctx context.Context, name, version string) (*npmVersion, error) {
	u := strings.TrimRight(s.opts.RegistryURL, "/") + "/" + name + "/" + url.PathEscape(version)
	var meta npmVersion
	if err := s.http.GetJSON(ctx, u, &meta); err != nil {
		return nil, fmt.Errorf("fetch %s@%s metadata: %w", name, version, err)
	}
	if meta.Dist.Tarball == "" {
		return nil, fmt.Errorf("%s@%s: registry response has no dist.tarball", name, version)
	}
	return &meta, nil
}

func (s *Source) fetchTarball(ctx context.Context, tarballURL string) ([]byte, error) {
	body, err := s.http.GetBody(ctx, tarballURL)
	if err != nil {
		return nil, fmt.Errorf("fetch tarball %s: %w", tarballURL, err)
	}
	if int64(len(body)) > s.opts.MaxTarballBytes {
		return nil, fmt.Errorf("tarball %s is %d bytes, exceeds cap of %d", tarballURL, len(body), s.opts.MaxTarballBytes)
	}
	return body, nil
}

func verifyTarball(tarball []byte, wantSRI string) error {
	if wantSRI == "" {
		return nil
	}
	alg, b64, ok := strings.Cut(wantSRI, "-")
	if !ok || strings.ToLower(alg) != "sha512" {
		return fmt.Errorf("registry integrity %q: only sha512 is supported", wantSRI)
	}
	got := sha512.Sum512(tarball)
	gotB64 := base64.StdEncoding.EncodeToString(got[:])
	if gotB64 != b64 {
		return fmt.Errorf("tarball integrity mismatch: registry says sha512-%s, got sha512-%s", b64, gotB64)
	}
	return nil
}

func defaultEntryPoint(r archives.Reader) (string, error) {
	rc, err := r.Extract("package.json")
	if err != nil {
		return "", fmt.Errorf("read package.json: %w", err)
	}
	defer func() { _ = rc.Close() }()
	var pj map[string]any
	if err := json.NewDecoder(rc).Decode(&pj); err != nil {
		return "", fmt.Errorf("parse package.json: %w", err)
	}
	for _, field := range entryPointFields {
		if v, ok := pj[field].(string); ok && v != "" {
			return strings.TrimPrefix(v, "./"), nil
		}
	}
	return "", fmt.Errorf("package.json has no %s field; specify files: explicitly", strings.Join(entryPointFields, "/"))
}

func extractFiles(r archives.Reader, paths []string) ([]ResolvedFile, error) {
	out := make([]ResolvedFile, 0, len(paths))
	for _, p := range paths {
		rc, err := r.Extract(p)
		if err != nil {
			return nil, fmt.Errorf("file %q not found in package", p)
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", p, err)
		}
		h := sha512.Sum384(content)
		out = append(out, ResolvedFile{
			Path:      p,
			Integrity: "sha384-" + base64.StdEncoding.EncodeToString(h[:]),
			Size:      int64(len(content)),
			Content:   content,
		})
	}
	return out, nil
}

func parseLicense(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Type
	}
	return ""
}

func parseRepository(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return normalizeRepoURL(s)
	}
	var obj struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return normalizeRepoURL(obj.URL)
	}
	return ""
}

func normalizeRepoURL(u string) string {
	u = strings.TrimPrefix(u, "git+")
	u = strings.TrimSuffix(u, ".git")
	if rest, ok := strings.CutPrefix(u, "git://"); ok {
		u = "https://" + rest
	}
	if rest, ok := strings.CutPrefix(u, "ssh://git@"); ok {
		u = "https://" + rest
	}
	if !strings.Contains(u, "://") {
		rest := strings.TrimPrefix(u, "git@")
		rest = strings.Replace(rest, ":", "/", 1)
		u = "https://" + rest
	}
	return u
}
