package pin

import (
	"context"
	"testing"

	"github.com/git-pkgs/purl"

	"github.com/git-pkgs/pin/source"
)

func TestClient_DefaultResolversRegistered(t *testing.T) {
	c := New(ClientOptions{})
	for _, purlType := range []string{"npm", "github", "generic"} {
		if c.Resolver(purlType) == nil {
			t.Errorf("default Client has no resolver for purl type %q", purlType)
		}
	}
}

func TestClient_RegisterResolverOverridesDefault(t *testing.T) {
	c := New(ClientOptions{})
	stub := &stubResolver{name: "stub-npm"}
	c.RegisterResolver("npm", stub)

	got := c.Resolver("npm")
	if got != stub {
		t.Errorf("Resolver(\"npm\") = %v, want stub %v", got, stub)
	}
	// Typed accessor still points at the originally-registered npm source.
	// This is the documented behaviour: NPM/Forge/URL are stable typed
	// handles even after overrides.
	if c.NPM == nil {
		t.Error("Client.NPM should remain non-nil after RegisterResolver override")
	}
}

func TestClient_RegisterNewPurlType(t *testing.T) {
	c := New(ClientOptions{})
	stub := &stubResolver{name: "ipfs"}
	c.RegisterResolver("ipfs", stub)

	if c.Resolver("ipfs") != stub {
		t.Error("RegisterResolver did not attach the new resolver")
	}
	if c.Resolver("unknown") != nil {
		t.Error("Resolver(\"unknown\") should be nil")
	}
}

// stubResolver implements source.Resolver for tests that exercise
// dispatch without doing real network work.
type stubResolver struct {
	name string
}

func (s *stubResolver) Resolve(_ context.Context, _ *purl.PURL, _ []string) (*source.Resolved, error) {
	return &source.Resolved{Name: s.name}, nil
}

// TestClient_CustomResolverDrivesSync proves the plug-in surface
// end-to-end: a consumer-registered resolver for a novel purl type
// (here, "demosrc") produces files that Sync writes to disk and
// records in the lockfile. This is the contract the source extension
// docs in source/source.go describe.
func TestClient_CustomResolverDrivesSync(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "fake-pkg"
    version: "1.0.0"
    source: "url:demosrc://anything"
`)
	// The manifest above uses source: url: so it parses as a URL
	// source. We replace the "generic" resolver (the purl type url
	// sources map to) with a custom one that returns a synthetic file.
	c := New(ClientOptions{})
	c.RegisterResolver("generic", &fileEmittingResolver{
		path:    "synthetic.js",
		content: []byte("console.log('plug-in')"),
	})

	res, err := c.Sync(context.Background(), SyncOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Sync with custom resolver: %v", err)
	}
	if len(res.Lock.Assets) != 1 {
		t.Fatalf("Lock.Assets = %d, want 1", len(res.Lock.Assets))
	}
	on := res.Lock.Assets[0]
	if on.Out == "" || on.Integrity == "" {
		t.Errorf("asset not fully populated: %+v", on)
	}
}

type fileEmittingResolver struct {
	path    string
	content []byte
}

func (r *fileEmittingResolver) Resolve(_ context.Context, p *purl.PURL, _ []string) (*source.Resolved, error) {
	return &source.Resolved{
		PURL:    p.String(),
		Name:    p.Name,
		Version: p.Version,
		Files: []source.ResolvedFile{{
			Path:      r.path,
			Integrity: "sha384-plugin-test",
			Size:      int64(len(r.content)),
			Content:   r.content,
		}},
	}, nil
}
