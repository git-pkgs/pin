//go:build smoke

package sigstoreverifier

import (
	"context"
	"crypto/sha512"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// TestVerifyAttestation_Real fetches a real sigstore attestation from
// the live npm registry and verifies it against the live Sigstore TUF
// trust root. Skipped unless built with -tags smoke.
func TestVerifyAttestation_Real(t *testing.T) {
	versionBody := mustGET(t, "https://registry.npmjs.org/sigstore/3.0.0")
	var v struct {
		Dist struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(versionBody, &v); err != nil {
		t.Fatal(err)
	}
	tarball := mustGET(t, v.Dist.Tarball)

	listBody := mustGET(t, "https://registry.npmjs.org/-/npm/v1/attestations/sigstore@3.0.0")
	var list struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(listBody, &list); err != nil {
		t.Fatal(err)
	}
	var bundleJSON []byte
	for _, a := range list.Attestations {
		if strings.HasPrefix(a.PredicateType, "https://slsa.dev/provenance/") {
			bundleJSON = a.Bundle
			break
		}
	}
	if bundleJSON == nil {
		t.Fatal("no SLSA bundle in attestations list")
	}

	tr, err := root.FetchTrustedRoot()
	if err != nil {
		t.Fatalf("fetch trusted root: %v", err)
	}

	v2 := New(tr)
	digest := sha512.Sum512(tarball)
	if err := v2.VerifyBundle(context.Background(), bundleJSON, "sha512", digest[:]); err != nil {
		t.Errorf("VerifyBundle: %v", err)
	}
}

func mustGET(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
