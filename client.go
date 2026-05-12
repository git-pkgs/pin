package pin

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	rclient "github.com/git-pkgs/registries/client"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"

	"github.com/git-pkgs/pin/internal/safehttp"
	"github.com/git-pkgs/pin/source"
	"github.com/git-pkgs/pin/source/forge"
	"github.com/git-pkgs/pin/source/npm"
	"github.com/git-pkgs/pin/source/rawurl"
	"github.com/git-pkgs/pin/source/sigstoreverifier"
)

// ClientOptions configures a Client. All fields are optional; zero
// values give the same defaults the pin CLI uses.
type ClientOptions struct {
	// HTTPClient is shared across every resolver in the Client.
	// Default: safehttp.New(nil, safehttp.Options{}) — SSRF-safe dial
	// gate, redirect cap, scheme allowlist.
	HTTPClient *http.Client

	// RegistryURL overrides the default npm registry
	// (https://registry.npmjs.org). Honoured by the built-in npm
	// resolver only.
	RegistryURL string

	// Forge configures the forge resolver (GitHub today; the package
	// is structured so GitLab/Gitea/Codeberg slot in by adding cases
	// to its purl-type switch).
	Forge forge.Options

	// SignatureMode controls npm dist.signatures verification. Zero is
	// SignatureModeWarn (verify when present, warn on absent, fail on
	// bad).
	SignatureMode npm.SignatureMode

	// Verifier cryptographically validates each attestation bundle the
	// built-in npm and forge resolvers record. Nil means record-only —
	// attestations land in the lockfile but the bundle's certificate
	// chain and inclusion proof are not checked. The pin CLI sets this
	// to sigstoreverifier.New(<TUF root>) when --verify-provenance is
	// passed; library consumers can supply any source.ProvenanceVerifier.
	Verifier source.ProvenanceVerifier
}

// Client holds the shared state used across pin operations: HTTP
// client, source resolvers keyed by purl type, and typed accessors
// for the built-in sources. A Client is safe for concurrent use
// across operations.
//
// Construct via New. Add or override resolvers via RegisterResolver.
// Use the operation methods (Sync, Verify, Outdated, ...) directly;
// the package-level functions of the same name are thin shims that
// construct a Client per call.
type Client struct {
	httpClient *http.Client

	// NPM, Forge, and URL are typed accessors to the built-in resolvers.
	// Operations that need source-specific APIs (npm.IsSticky for the
	// sticky-version check, npm.Status for `pin outdated`, the npm
	// tarball re-derive for `verify --strict`) use these. They stay
	// pointing at the resolvers initially registered by New, even when
	// a consumer overrides the same purl type via RegisterResolver.
	NPM   *npm.Source
	Forge *forge.Source
	URL   *rawurl.Source

	resolvers map[string]source.Resolver
}

// New returns a Client with the three built-in resolvers (npm, github,
// generic) registered. Consumers can add or replace resolvers via
// RegisterResolver before calling any operation method.
func New(opts ClientOptions) *Client {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = safehttp.New(nil, safehttp.Options{})
	}

	rc := rclient.NewClient()
	rc.HTTPClient = httpClient

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
		httpClient: httpClient,
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

// RegisterResolver attaches a resolver for the given purl type. Used
// internally by New for the built-in sources; exported so consumers
// can plug in additional source kinds (pkg:ipfs/..., pkg:internal/...)
// without forking pin. Overwrites any previously-registered resolver
// for the same type.
//
// Resolvers are read-only after registration; pin operations dispatch
// on resolved purl type at sync time.
func (c *Client) RegisterResolver(purlType string, r source.Resolver) {
	c.resolvers[purlType] = r
}

// Resolver returns the resolver registered for the given purl type,
// or nil if none. Useful for consumers that want to delegate to a
// built-in resolver from a custom one (e.g. an IPFS resolver that
// falls back to npm for non-IPFS purls).
//
//nolint:ireturn // the plug-in surface is interface-typed by design
func (c *Client) Resolver(purlType string) source.Resolver {
	return c.resolvers[purlType]
}

// loadTrustedRoot returns the Sigstore TUF trust root, caching it
// locally so a second sync within the metadata's validity window
// reuses the cached root without a network round-trip. Used by the
// top-level shims when SyncOptions.VerifyProvenance is set.
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

// clientFromSyncOptions builds a Client for the one-shot top-level
// pin.Sync path. Library consumers wanting reuse construct a Client
// directly with New.
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
		co.Verifier = sigstoreverifier.New(tr)
	}
	return New(co), nil
}
