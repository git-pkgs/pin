package integrity

import (
	"strings"
	"testing"
)

// FuzzParseSRI exercises the SRI string parser. ParseSRI runs strings.Cut
// then a map lookup then base64.StdEncoding.DecodeString — each step
// could panic or misbehave on malformed input. Contract: never panics,
// and when err is nil the returned alg is one of the three CycloneDX
// algorithm names.
func FuzzParseSRI(f *testing.F) {
	f.Add("")
	f.Add("-")
	f.Add("sha384-")
	f.Add("sha384")
	f.Add("sha384-aGVsbG8=") // valid: "hello"
	f.Add("SHA384-aGVsbG8=") // mixed case prefix
	f.Add("sha384-!!!!")     // bad base64
	f.Add("md5-aGVsbG8=")    // unsupported alg
	f.Add(strings.Repeat("sha384-", 100) + "aGVsbG8=")

	validAlgs := map[string]bool{CDXSHA256: true, CDXSHA384: true, CDXSHA512: true}
	f.Fuzz(func(t *testing.T, s string) {
		alg, _, err := ParseSRI(s)
		if err == nil && !validAlgs[alg] {
			t.Errorf("ParseSRI(%q) returned alg %q with nil error; want one of SHA-256/384/512", s, alg)
		}
	})
}

// FuzzRoundTrip covers FormatSRI ∘ ParseSRI. Anything ParseSRI accepts
// should round-trip through FormatSRI and parse again identically.
func FuzzRoundTrip(f *testing.F) {
	f.Add("sha384-aGVsbG8=")
	f.Add("sha256-aGVsbG8=")
	f.Add("sha512-AAAA")
	f.Add("SHA384-aGVsbG8=")

	f.Fuzz(func(t *testing.T, s string) {
		alg, digest, err := ParseSRI(s)
		if err != nil {
			return
		}
		out, err := FormatSRI(alg, digest)
		if err != nil {
			t.Fatalf("FormatSRI failed after ParseSRI(%q) accepted: %v", s, err)
		}
		alg2, digest2, err := ParseSRI(out)
		if err != nil {
			t.Fatalf("re-parse of round-tripped %q failed: %v", out, err)
		}
		if alg2 != alg || digest2 != digest {
			t.Errorf("round-trip drifted: in=(%q,%q) out=(%q,%q)", alg, digest, alg2, digest2)
		}
	})
}
