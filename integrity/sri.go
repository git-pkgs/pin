// Package integrity provides Subresource Integrity helpers.
package integrity

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

var sriAlgToCDX = map[string]string{
	"sha256": "SHA-256",
	"sha384": "SHA-384",
	"sha512": "SHA-512",
}

// ParseSRI decodes a Subresource Integrity string ("sha384-<base64>") into a
// CycloneDX hash algorithm name ("SHA-384") and hex-encoded digest.
func ParseSRI(sri string) (alg, hexDigest string, err error) {
	prefix, b64, ok := strings.Cut(sri, "-")
	if !ok {
		return "", "", fmt.Errorf("integrity %q: missing algorithm prefix", sri)
	}
	cdxAlg, ok := sriAlgToCDX[strings.ToLower(prefix)]
	if !ok {
		return "", "", fmt.Errorf("integrity %q: unsupported algorithm %q", sri, prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", fmt.Errorf("integrity %q: %w", sri, err)
	}
	return cdxAlg, hex.EncodeToString(raw), nil
}

// FormatSRI encodes a CycloneDX algorithm name and hex digest as an SRI string.
func FormatSRI(cdxAlg, hexDigest string) (string, error) {
	var prefix string
	for k, v := range sriAlgToCDX {
		if v == cdxAlg {
			prefix = k
			break
		}
	}
	if prefix == "" {
		return "", fmt.Errorf("unsupported CycloneDX algorithm %q", cdxAlg)
	}
	raw, err := hex.DecodeString(hexDigest)
	if err != nil {
		return "", err
	}
	return prefix + "-" + base64.StdEncoding.EncodeToString(raw), nil
}
