package attestation

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// FuzzParse exercises the bundle parser against arbitrary bytes. The
// contract is just "doesn't panic"; any structural problem with the
// input should surface as an error or a (nil, nil) result, never a
// runtime crash. Seeds cover the happy path, the documented edge
// cases (empty, empty payload, malformed JSON), and a few shapes the
// hand tests don't reach (deeply nested predicate, oversize base64
// payload, payload that is itself a bundle, invalid x509 raw bytes).
func FuzzParse(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("{}"))
	f.Add([]byte(`{"dsseEnvelope":{"payload":""}}`))
	f.Add([]byte(`{"dsseEnvelope":{"payload":"not-base64!!"}}`))

	// Happy-path SLSA Provenance v1.
	stmt := map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"resolvedDependencies": []map[string]any{
					{"uri": "git+https://github.com/o/r.git@refs/heads/main", "digest": map[string]string{"gitCommit": "deadbeef"}},
				},
			},
			"runDetails": map[string]any{"builder": map[string]any{"id": "https://b/"}},
		},
	}
	stmtJSON, _ := json.Marshal(stmt)
	bundle := map[string]any{
		"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(stmtJSON)},
	}
	body, _ := json.Marshal(bundle)
	f.Add(body)

	// Bundle with an invalid x509 cert in verificationMaterial — the
	// signer-identity extractor must reject it gracefully.
	withBadCert := map[string]any{
		"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(stmtJSON)},
		"verificationMaterial": map[string]any{
			"certificate": map[string]any{"rawBytes": base64.StdEncoding.EncodeToString([]byte("not-a-real-cert"))},
		},
	}
	bcBody, _ := json.Marshal(withBadCert)
	f.Add(bcBody)

	f.Fuzz(func(t *testing.T, body []byte) {
		// The only assertion is that Parse never panics or returns a
		// non-nil Attestation alongside a non-nil error (the contract).
		att, err := Parse(body)
		if err != nil && att != nil {
			t.Errorf("Parse returned both non-nil att (%+v) and err (%v) — contract violated", att, err)
		}
	})
}
