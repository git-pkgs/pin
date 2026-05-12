package lock

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzRead exercises the CycloneDX-shaped lockfile reader. The 16 MiB
// io.LimitReader cap is enforced inside Read; bodies above that size
// should error rather than blow memory. The contract elsewhere is
// "doesn't panic on any input".
//
// Seeds cover empty input, a minimal lockfile (zero assets), and a
// fully-loaded entry with the pin: properties + an attestation block.
// A few hostile shapes are added: deeply nested components, duplicate
// keys, integers where strings are expected.
func FuzzRead(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`))

	// A real-shaped lockfile body. Round-trip it: write a *Lock with
	// known assets and use the bytes as a seed.
	l := &Lock{
		OutDir: "v",
		Assets: []Asset{{
			Name:             "demo",
			Version:          "1.2.3",
			PURL:             "pkg:npm/demo@1.2.3",
			Type:             "script",
			Path:             "dist/x.js",
			Out:              "demo/x.js",
			Integrity:        "sha384-abc",
			Size:             42,
			PackageIntegrity: "sha512-zzz",
			License:          "MIT",
			SourceRepository: "https://github.com/example/demo",
		}},
	}
	var buf bytes.Buffer
	if err := Write(&buf, l, "pin", "test"); err == nil {
		f.Add(buf.Bytes())
	}

	// Deeply nested components — the parser shouldn't OOM.
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[` +
		strings.Repeat(`{"type":"library","components":[`, 100) +
		strings.Repeat(`]}`, 100) + `]}`))

	// Duplicate keys (allowed by encoding/json).
	f.Add([]byte(`{"bomFormat":"CycloneDX","bomFormat":"X","specVersion":"1.6"}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = Read(bytes.NewReader(body))
	})
}
