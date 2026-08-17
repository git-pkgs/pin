package forge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// buildSLSABundle returns a minimal sigstore-bundle-shaped JSON document
// that parseGitHubBundle accepts as a SLSA Provenance v1 attestation.
// The signing material is empty (zero certs); parseGitHubBundle is
// content-only, not signature-checking, so the bundle just needs the
// right DSSE envelope + in-toto statement to surface PredicateType.
func buildSLSABundle(t *testing.T) []byte {
	t.Helper()
	stmt := map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
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
			"payload": base64.StdEncoding.EncodeToString(stmtJSON),
		},
	}
	out, _ := json.Marshal(bundle)
	return out
}

func attestationServer(t *testing.T, expectDigest [32]byte, bundleBody []byte, cdnFiles map[string]string, sha string) (api, cdn string) {
	t.Helper()
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/repos/o/r/commits/v1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sha))
	})
	apiMux.HandleFunc("/repos/o/r/attestations/sha256:"+hex.EncodeToString(expectDigest[:]),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"attestations": []map[string]any{
					{"bundle": json.RawMessage(bundleBody)},
				},
			})
		})
	apiSrv := httptest.NewServer(apiMux)
	t.Cleanup(apiSrv.Close)

	cdnMux := http.NewServeMux()
	for path, content := range cdnFiles {
		body := content
		cdnMux.HandleFunc("/gh/o/r@"+sha+"/"+path, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		})
	}
	cdnSrv := httptest.NewServer(cdnMux)
	t.Cleanup(cdnSrv.Close)

	return apiSrv.URL, cdnSrv.URL
}

func TestResolveGitHub_VerifierCalled(t *testing.T) {
	bundle := buildSLSABundle(t)
	body := "var x=1"
	digest := sha256.Sum256([]byte(body))
	api, cdn := attestationServer(t, digest, bundle, map[string]string{"x.js": body},
		"0123456789012345678901234567890123456789")

	v := &fakeVerifier{}
	src := New(Options{GitHubAPI: api, JSDelivrCDN: cdn, Verifier: v})
	got, err := src.Resolve(context.Background(), ghPURL("o", "r", "v1"), []string{"x.js"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v.called != 1 {
		t.Errorf("VerifyBundle called %d times, want 1", v.called)
	}
	if v.lastDigestAlg != "sha256" {
		t.Errorf("digest alg = %q, want sha256", v.lastDigestAlg)
	}
	if string(v.lastDigest) != string(digest[:]) {
		t.Errorf("digest does not match the fetched file's sha256")
	}
	if got.Attestation == nil {
		t.Fatal("Attestation should be recorded")
	}
}

func TestResolveGitHub_VerifierFailureBubbles(t *testing.T) {
	bundle := buildSLSABundle(t)
	body := "var x=1"
	digest := sha256.Sum256([]byte(body))
	api, cdn := attestationServer(t, digest, bundle, map[string]string{"x.js": body},
		"0123456789012345678901234567890123456789")

	v := &fakeVerifier{err: errors.New("bad signature")}
	src := New(Options{GitHubAPI: api, JSDelivrCDN: cdn, Verifier: v})
	_, err := src.Resolve(context.Background(), ghPURL("o", "r", "v1"), []string{"x.js"})
	if err == nil {
		t.Fatal("expected verifier error to bubble")
	}
}

func TestResolveGitHub_NilVerifierRecordsOnly(t *testing.T) {
	bundle := buildSLSABundle(t)
	body := "var x=1"
	digest := sha256.Sum256([]byte(body))
	api, cdn := attestationServer(t, digest, bundle, map[string]string{"x.js": body},
		"0123456789012345678901234567890123456789")

	src := New(Options{GitHubAPI: api, JSDelivrCDN: cdn})
	got, err := src.Resolve(context.Background(), ghPURL("o", "r", "v1"), []string{"x.js"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Attestation == nil {
		t.Fatal("Attestation should be recorded even without verifier")
	}
}
