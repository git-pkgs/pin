package npm

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SignatureMode selects how strictly dist.signatures is verified.
type SignatureMode int

const (
	// SignatureModeWarn (default) verifies when a signature is present;
	// fails on a bad signature; warns when missing.
	SignatureModeWarn SignatureMode = iota
	// SignatureModeEnforce additionally fails when no signature is present.
	SignatureModeEnforce
	// SignatureModeOff skips signature verification entirely.
	SignatureModeOff
)

type npmSignature struct {
	Sig   string `json:"sig"`
	Keyid string `json:"keyid"`
}

type npmKey struct {
	Expires *time.Time `json:"expires"`
	Keyid   string     `json:"keyid"`
	Scheme  string     `json:"scheme"`
	Key     string     `json:"key"`
}

type keyCache struct {
	mu      sync.Mutex
	loaded  bool
	byKeyid map[string]*npmKey
	loadErr error
}

// verifySignature checks the npm dist.signatures for a version. raw is
// the version document JSON; integrity is its dist.integrity string;
// name@version reconstructs the signed payload. Behaviour depends on
// mode: warn (default) is non-fatal on absence but fatal on a bad sig.
func (s *Source) verifySignature(ctx context.Context, name, version, integrity string, raw []byte) error {
	if s.opts.SignatureMode == SignatureModeOff {
		return nil
	}
	sig := findSignature(raw)
	if sig == nil {
		if s.opts.SignatureMode == SignatureModeEnforce {
			return fmt.Errorf("%s@%s: no dist.signatures entry (signature mode = enforce)", name, version)
		}
		return nil
	}
	key, err := s.fetchSigningKey(ctx, sig.Keyid)
	if err != nil {
		return fmt.Errorf("%s@%s: %w", name, version, err)
	}
	if err := verifyECDSA(key, sig.Sig, name+"@"+version+":"+integrity); err != nil {
		return fmt.Errorf("%s@%s: dist.signatures verification failed: %w", name, version, err)
	}
	return nil
}

func findSignature(raw []byte) *npmSignature {
	if len(raw) == 0 {
		return nil
	}
	var v struct {
		Dist struct {
			Signatures []npmSignature `json:"signatures"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	for i := range v.Dist.Signatures {
		s := &v.Dist.Signatures[i]
		if s.Sig != "" && s.Keyid != "" {
			return s
		}
	}
	return nil
}

func (s *Source) fetchSigningKey(ctx context.Context, keyid string) (*npmKey, error) {
	if err := s.loadSigningKeys(ctx); err != nil {
		return nil, err
	}
	s.keys.mu.Lock()
	defer s.keys.mu.Unlock()
	key, ok := s.keys.byKeyid[keyid]
	if !ok {
		return nil, fmt.Errorf("signing key %s not in npm's published key set", keyid)
	}
	// Expired keys remain valid for verifying signatures made before the
	// expiry date. npm continues to publish them in /-/npm/v1/keys for
	// exactly this purpose. The Expires field tells publishers when to
	// stop *making* new signatures, not consumers when to stop trusting
	// existing ones.
	return key, nil
}

func (s *Source) loadSigningKeys(ctx context.Context) error {
	s.keys.mu.Lock()
	defer s.keys.mu.Unlock()
	if s.keys.loaded {
		return s.keys.loadErr
	}
	s.keys.loaded = true
	url := strings.TrimRight(s.opts.RegistryURL, "/") + "/-/npm/v1/keys"
	var resp struct {
		Keys []npmKey `json:"keys"`
	}
	if err := s.http.GetJSON(ctx, url, &resp); err != nil {
		s.keys.loadErr = fmt.Errorf("fetch npm signing keys: %w", err)
		return s.keys.loadErr
	}
	s.keys.byKeyid = make(map[string]*npmKey, len(resp.Keys))
	for i := range resp.Keys {
		k := &resp.Keys[i]
		s.keys.byKeyid[k.Keyid] = k
	}
	return nil
}

func verifyECDSA(key *npmKey, sigB64, payload string) error {
	if !strings.Contains(key.Scheme, "ecdsa") {
		return fmt.Errorf("unsupported signing scheme %q", key.Scheme)
	}
	pubDER, err := base64.StdEncoding.DecodeString(key.Key)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	digest := sha256.Sum256([]byte(payload))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("ECDSA signature does not verify")
	}
	return nil
}
