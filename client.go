package pin

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	rclient "github.com/git-pkgs/registries/client"
	"github.com/git-pkgs/sigstore"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"

	"github.com/git-pkgs/pin/source"
	"github.com/git-pkgs/pin/source/forge"
	"github.com/git-pkgs/pin/source/npm"
	"github.com/git-pkgs/pin/source/rawurl"
)

// ClientOptions configures a Client. Zero values give the CLI defaults.
type ClientOptions struct {
	// HTTPClient overrides the default, which is the safehttp transport
	// (SSRF-safe dial gate, redirect cap, scheme allowlist).
	HTTPClient *http.Client

	// RegistryURL overrides the default npm registry. Honoured by the
	// built-in npm resolver only.
	RegistryURL string

	Forge forge.Options

	// SignatureMode controls npm dist.signatures verification. Zero is
	// SignatureModeWarn.
	SignatureMode npm.SignatureMode

	// Verifier validates each attestation bundle the built-in npm and
	// forge resolvers record. Nil means record-only — attestations
	// land in the lockfile but the certificate chain and inclusion
	// proof are not checked. The pin CLI sets this to sigstore.New(<TUF
	// root>) when --verify-provenance is passed.
	Verifier source.ProvenanceVerifier
}

// Client holds shared state across pin operations: HTTP client,
// source resolvers keyed by purl type, and typed accessors for the
// built-in sources. Safe for concurrent use across operations.
type Client struct {
	httpClient *http.Client

	// NPM, Forge, URL stay pointing at the resolvers registered by
	// New even when a consumer overrides the same purl type via
	// RegisterResolver. Operations that need source-specific APIs
	// (npm.IsSticky, npm.Status, npm tarball re-derive for
	// verify --strict) use these.
	NPM   *npm.Source
	Forge *forge.Source
	URL   *rawurl.Source

	resolvers map[string]source.Resolver
}

// New returns a Client with the built-in npm, github, and generic
// resolvers registered. Consumers can add or replace resolvers via
// RegisterResolver before calling any operation method.
func New(opts ClientOptions) *Client {
	var clientOpts []rclient.Option
	if opts.HTTPClient != nil {
		clientOpts = append(clientOpts, rclient.WithHTTPClient(opts.HTTPClient))
	} else {
		clientOpts = append(clientOpts, rclient.WithSafeHTTP())
	}
	rc := rclient.NewClient(clientOpts...).WithUserAgent(userAgent())

	npmS := npm.New(npm.Options{
		HTTPClient:    rc,
		RegistryURL:   opts.RegistryURL,
		SignatureMode: opts.SignatureMode,
		Verifier:      opts.Verifier,
	})

	fopts := opts.Forge
	fopts.HTTPClient = rc
	if fopts.Verifier == nil {
		fopts.Verifier = opts.Verifier
	}
	forgeS := forge.New(fopts)

	rawurlS := rawurl.New(rawurl.Options{HTTPClient: rc})

	return &Client{
		httpClient: rc.HTTPClient,
		NPM:        npmS,
		Forge:      forgeS,
		URL:        rawurlS,
		resolvers: map[string]source.Resolver{
			"npm":     npmS,
			"github":  forgeS,
			"generic": rawurlS,
		},
	}
}

// RegisterResolver attaches a resolver for the given purl type.
// Overwrites any previously-registered resolver. Resolvers are
// read-only after registration; operations dispatch on resolved purl
// type at sync time.
func (c *Client) RegisterResolver(purlType string, r source.Resolver) {
	c.resolvers[purlType] = r
}

// Resolver returns the resolver registered for the given purl type,
// or nil. Useful for custom resolvers that delegate to a built-in for
// non-matching purls.
//
//nolint:ireturn // the plug-in surface is interface-typed by design
func (c *Client) Resolver(purlType string) source.Resolver {
	return c.resolvers[purlType]
}

func userAgent() string {
	return "pin/" + ToolVersion + " (+https://github.com/git-pkgs/pin)"
}

// loadTrustedRoot caches the Sigstore TUF trust root locally so a
// second sync within the metadata's validity window skips the network
// round-trip.
func loadTrustedRoot() (*root.TrustedRoot, error) {
	cachePath, err := pinTUFCachePath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cachePath, dirPerm); err != nil {
		return nil, fmt.Errorf("create TUF cache dir %s: %w", cachePath, err)
	}
	tufOpts := tuf.DefaultOptions()
	tufOpts.CachePath = cachePath
	tufOpts.ForceCache = true
	return root.FetchTrustedRootWithOptions(tufOpts)
}

func pinTUFCachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pin", "sigstore-tuf"), nil
}

func clientFromSyncOptions(opts SyncOptions) (*Client, error) {
	co := ClientOptions{
		RegistryURL:   opts.RegistryURL,
		Forge:         opts.Forge,
		SignatureMode: opts.SignatureMode,
	}
	if opts.VerifyProvenance {
		tr, err := loadTrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("--verify-provenance: load Sigstore trust root: %w", err)
		}
		co.Verifier = sigstore.New(tr)
	}
	return New(co), nil
}
