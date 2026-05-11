//go:build smoke

package npm

import (
	"encoding/base64"
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
	// 1. Fetch the version document to get the tarball.
	versionURL := "https://registry.npmjs.org/sigstore/3.0.0"
	versionBody := mustGET(t, versionURL)
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

	// 2. Fetch the attestation list and pick the SLSA bundle.
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

	// 3. Load the Sigstore trust root from TUF.
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		t.Fatalf("fetch trusted root: %v", err)
	}

	// 4. Verify.
	if err := VerifyAttestation(bundleJSON, tarball, tr); err != nil {
		t.Errorf("VerifyAttestation: %v", err)
	}

	// Anti-flake: silence base64 unused import in some paths.
	_ = base64.StdEncoding
}

func mustGET(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
