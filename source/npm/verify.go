package npm

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// VerifyAttestation cryptographically verifies the sigstore bundle that
// backs an npm provenance attestation:
//
//   - The bundle's Fulcio cert chains to Sigstore's trust root.
//   - The Rekor inclusion proof is valid.
//   - The DSSE envelope's signature matches.
//   - The in-toto subject digest matches the tarball's SHA-512.
//
// trustedRoot is the Sigstore TUF root; in tests, callers can construct
// one with sigstore-go's testdata helpers, and in production
// root.FetchTrustedRoot fetches and caches the live root.
func VerifyAttestation(bundleBody, tarball []byte, trustedRoot *root.TrustedRoot) error {
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(bundleBody, &pb); err != nil {
		// Fall back to plain JSON unmarshal for legacy bundle JSON shapes.
		if err2 := json.Unmarshal(bundleBody, &pb); err2 != nil {
			return fmt.Errorf("parse sigstore bundle: %w", err)
		}
	}
	b, err := bundle.NewBundle(&pb)
	if err != nil {
		return fmt.Errorf("wrap sigstore bundle: %w", err)
	}

	sev, err := verify.NewVerifier(trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("construct verifier: %w", err)
	}

	digest := sha512.Sum512(tarball)
	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha512", digest[:]),
		verify.WithoutIdentitiesUnsafe(),
	)
	if _, err := sev.Verify(b, policy); err != nil {
		return fmt.Errorf("sigstore verify: %w", err)
	}
	return nil
}

// HexDigest returns the SHA-512 hex digest of bytes, useful when
// constructing artifact policies by digest directly.
func HexDigest(b []byte) string {
	d := sha512.Sum512(b)
	return hex.EncodeToString(d[:])
}
