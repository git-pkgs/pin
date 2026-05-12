package npm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeKeyServer(t *testing.T, name, version, integrity string) (*httptest.Server, string, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyid := "SHA256:test-key-id"

	payload := []byte(name + "@" + version + ":" + integrity)
	digest := sha256.Sum256(payload)
	sigDER, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigDER)

	versionDoc := map[string]any{
		"name":    name,
		"version": version,
		"dist": map[string]any{
			"integrity": integrity,
			"signatures": []map[string]string{
				{"sig": sigB64, "keyid": keyid},
			},
		},
	}
	versionBody, _ := json.Marshal(versionDoc)

	mux := http.NewServeMux()
	mux.HandleFunc("/-/npm/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{"keyid": keyid, "scheme": "ecdsa-sha2-nistp256", "key": base64.StdEncoding.EncodeToString(pubDER)},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, "good-sig", versionBody
}

func TestVerifySignature_Good(t *testing.T) {
	srv, _, versionBody := fakeKeyServer(t, "demo", "1.0.0", "sha512-abc")
	src := New(Options{RegistryURL: srv.URL, SignatureMode: SignatureModeWarn})
	if err := src.verifySignature(context.Background(), "demo", "1.0.0", "sha512-abc", versionBody); err != nil {
		t.Errorf("good signature should verify: %v", err)
	}
}

func TestVerifySignature_BadPayload(t *testing.T) {
	srv, _, versionBody := fakeKeyServer(t, "demo", "1.0.0", "sha512-abc")
	src := New(Options{RegistryURL: srv.URL, SignatureMode: SignatureModeWarn})
	if err := src.verifySignature(context.Background(), "demo", "1.0.0", "sha512-DIFFERENT", versionBody); err == nil {
		t.Error("signature over a different payload should fail")
	}
}

func TestVerifySignature_NoSig_WarnMode(t *testing.T) {
	versionBody := []byte(`{"name":"demo","version":"1.0.0","dist":{"integrity":"sha512-abc"}}`)
	src := New(Options{SignatureMode: SignatureModeWarn})
	if err := src.verifySignature(context.Background(), "demo", "1.0.0", "sha512-abc", versionBody); err != nil {
		t.Errorf("warn mode should tolerate missing signature: %v", err)
	}
}

func TestVerifySignature_NoSig_EnforceMode(t *testing.T) {
	versionBody := []byte(`{"name":"demo","version":"1.0.0","dist":{"integrity":"sha512-abc"}}`)
	src := New(Options{SignatureMode: SignatureModeEnforce})
	err := src.verifySignature(context.Background(), "demo", "1.0.0", "sha512-abc", versionBody)
	if err == nil || !strings.Contains(err.Error(), "no dist.signatures") {
		t.Errorf("enforce mode should fail on missing signature, got %v", err)
	}
}

func TestVerifySignature_OffMode(t *testing.T) {
	versionBody := []byte(`{"name":"demo","version":"1.0.0","dist":{"integrity":"sha512-abc","signatures":[{"sig":"bogus","keyid":"nope"}]}}`)
	src := New(Options{SignatureMode: SignatureModeOff})
	if err := src.verifySignature(context.Background(), "demo", "1.0.0", "sha512-abc", versionBody); err != nil {
		t.Errorf("off mode should skip verification entirely: %v", err)
	}
}

func TestVerifySignature_UnknownKeyid(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/-/npm/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	versionBody := []byte(`{"name":"demo","version":"1.0.0","dist":{"integrity":"sha512-abc","signatures":[{"sig":"AAAA","keyid":"SHA256:unknown"}]}}`)
	src := New(Options{RegistryURL: srv.URL, SignatureMode: SignatureModeWarn})
	err := src.verifySignature(context.Background(), "demo", "1.0.0", "sha512-abc", versionBody)
	if err == nil || !strings.Contains(err.Error(), "not in npm's published key set") {
		t.Errorf("unknown keyid should fail, got %v", err)
	}
}
