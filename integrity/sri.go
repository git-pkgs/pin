// Package integrity provides deprecated compatibility wrappers for
// github.com/git-pkgs/integrity.
package integrity

import (
	"fmt"

	shared "github.com/git-pkgs/integrity"
)

// CycloneDX hash-algorithm names retained for compatibility.
const (
	CDXSHA256 = "SHA-256"
	CDXSHA384 = "SHA-384"
	CDXSHA512 = "SHA-512"
)

// ParseSRI decodes the first digest in a Subresource Integrity metadata list
// into a CycloneDX hash algorithm name and hex-encoded digest.
//
// Deprecated: use github.com/git-pkgs/integrity.ParseSRI.
func ParseSRI(value string) (algorithm, hexDigest string, err error) {
	digests, err := shared.ParseSRI(value)
	if err != nil {
		return "", "", err
	}
	digest := digests[0]
	return cdxAlgorithm(digest.Algorithm()), digest.Hex(), nil
}

// FormatSRI encodes a CycloneDX algorithm name and hex digest as an SRI
// string.
//
// Deprecated: use github.com/git-pkgs/integrity.ParseHex and Digest.SRI.
func FormatSRI(cdxAlgorithm, hexDigest string) (string, error) {
	algorithm, err := sriAlgorithm(cdxAlgorithm)
	if err != nil {
		return "", err
	}
	digest, err := shared.ParseHex(algorithm, hexDigest)
	if err != nil {
		return "", err
	}
	return digest.SRI(), nil
}

func cdxAlgorithm(algorithm shared.Algorithm) string {
	switch algorithm {
	case shared.SHA256:
		return CDXSHA256
	case shared.SHA384:
		return CDXSHA384
	case shared.SHA512:
		return CDXSHA512
	default:
		return ""
	}
}

func sriAlgorithm(algorithm string) (shared.Algorithm, error) {
	switch algorithm {
	case CDXSHA256:
		return shared.SHA256, nil
	case CDXSHA384:
		return shared.SHA384, nil
	case CDXSHA512:
		return shared.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported CycloneDX algorithm %q", algorithm)
	}
}
