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
