package npm

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeVerifier struct {
	err            error
	called         int
	lastDigestAlg  string
	lastDigest     []byte
	lastBundleBody []byte
}

func (f *fakeVerifier) VerifyBundle(_ context.Context, body []byte, alg string, digest []byte) error {
	f.called++
	f.lastDigestAlg = alg
	f.lastDigest = digest
	f.lastBundleBody = body
	return f.err
}

// buildNPMSLSABundle returns a minimal SLSA-Provenance-v1-shaped sigstore
// bundle that the npm path's parseBundle accepts.
func buildNPMSLSABundle() []byte {
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{
			{"name": "demo", "digest": map[string]string{"sha512": "dummy"}},
		},
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"externalParameters":   map[string]any{},
				"resolvedDependencies": []any{},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": "https://github.com/test/builder"},
			},
		},
	}
	stmtJSON, _ := json.Marshal(stmt)
	bundle := map[string]any{
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(stmtJSON),
			"payloadType": "application/vnd.in-toto+json",
		},
	}
	out, _ := json.Marshal(bundle)
	return out
}

// newFakeRegistryWithAttestation extends newFakeRegistry so that the
// version document includes a dist.attestations.url field and the
// attestation endpoint returns a SLSA Provenance v1 bundle. Returns
// the tarball bytes too so callers can compute the expected digest
// without re-tarring (which is non-deterministic over map iteration).
func newFakeRegistryWithAttestation(t *testing.T, pkg *fakePackage, bundle []byte) (*httptest.Server, []byte) {
	t.Helper()
	tb := pkg.tarball()
	tbPath := fmt.Sprintf("/%s/-/%s-%s.tgz", pkg.name, pkg.name, pkg.version)
	attPath := fmt.Sprintf("/-/npm/v1/attestations/%s@%s", pkg.name, pkg.version)

	mux := http.NewServeMux()
	var srvURL string

	mux.HandleFunc("/"+pkg.name+"/"+pkg.version, func(w http.ResponseWriter, _ *http.Request) {
		h := sha512.Sum512(tb)
		integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])
		resp := map[string]any{
			"name":    pkg.name,
			"version": pkg.version,
			"dist": map[string]any{
				"tarball":   srvURL + tbPath,
				"integrity": integrity,
				"attestations": map[string]any{
					"url":        srvURL + attPath,
					"provenance": map[string]string{"predicateType": "https://slsa.dev/provenance/v1"},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc(tbPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tb)
	})
	mux.HandleFunc(attPath, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"attestations": []map[string]any{
				{"predicateType": "https://slsa.dev/provenance/v1", "bundle": json.RawMessage(bundle)},
			},
		})
	})

	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv, tb
}

func attestationFixture(t *testing.T) (*fakePackage, *httptest.Server, []byte, []byte) {
	t.Helper()
	pkg := &fakePackage{
		name:    "demo",
		version: "1.0.0",
		pkgJSON: map[string]any{"name": "demo", "version": "1.0.0", "main": "index.js"},
		files:   map[string]string{"index.js": "module.exports = 1"},
	}
	bundle := buildNPMSLSABundle()
	srv, tarball := newFakeRegistryWithAttestation(t, pkg, bundle)
	return pkg, srv, bundle, tarball
}

func TestResolve_VerifierCalledWithTarballDigest(t *testing.T) {
	pkg, srv, _, tarball := attestationFixture(t)

	v := &fakeVerifier{}
	src := New(Options{RegistryURL: srv.URL, Verifier: v})
	_, err := src.Resolve(context.Background(), npmPURL(pkg.name, pkg.version), []string{"index.js"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v.called != 1 {
		t.Fatalf("VerifyBundle called %d times, want 1", v.called)
	}
	if v.lastDigestAlg != "sha512" {
		t.Errorf("digest alg = %q, want sha512", v.lastDigestAlg)
	}
	wantDigest := sha512.Sum512(tarball)
	if string(v.lastDigest) != string(wantDigest[:]) {
		t.Error("digest does not match the tarball sha512")
	}
}

func TestResolve_VerifierFailureBubbles(t *testing.T) {
	pkg, srv, _, _ := attestationFixture(t)

	v := &fakeVerifier{err: errors.New("bad bundle")}
	src := New(Options{RegistryURL: srv.URL, Verifier: v})
	_, err := src.Resolve(context.Background(), npmPURL(pkg.name, pkg.version), []string{"index.js"})
	if err == nil {
		t.Fatal("expected verifier error to bubble")
	}
}

func TestResolve_NilVerifierRecordsOnly(t *testing.T) {
	pkg, srv, _, _ := attestationFixture(t)

	src := New(Options{RegistryURL: srv.URL})
	got, err := src.Resolve(context.Background(), npmPURL(pkg.name, pkg.version), []string{"index.js"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Attestation == nil {
		t.Fatal("Attestation should be recorded even without verifier")
	}
}
