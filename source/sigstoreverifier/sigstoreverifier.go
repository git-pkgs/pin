// Package sigstoreverifier is the default source.ProvenanceVerifier
// implementation: it validates a sigstore bundle against the live (or
// cached) Sigstore TUF trust root via sigstore-go. Handles both npm
// (subject = sha512(tarball)) and GitHub artifact (subject = sha256(file))
// attestations.
//
// Wired in sync.go when --verify-provenance is set. Witness, SBOMit,
// and in-toto-plain verifiers can sit beside this one as separate
// implementations of source.ProvenanceVerifier without touching the
// npm or forge fetch paths.
package sigstoreverifier

import (
	"context"
	"encoding/json"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// Verifier wraps a Sigstore trust root. Construct via New; pass into
// source.Options.Verifier.
type Verifier struct {
	root *root.TrustedRoot
}

func New(trustedRoot *root.TrustedRoot) *Verifier {
	return &Verifier{root: trustedRoot}
}

// VerifyBundle satisfies source.ProvenanceVerifier. Cryptographic checks:
//
//   - bundle's Fulcio cert chains to the Sigstore trust root
//   - Rekor inclusion proof is valid
//   - DSSE envelope signature matches the cert
//   - in-toto subject digest matches the supplied (digestAlg, digest)
func (v *Verifier) VerifyBundle(_ context.Context, bundleBody []byte, digestAlg string, digest []byte) error {
	if v.root == nil {
		return fmt.Errorf("sigstoreverifier: nil trust root")
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(bundleBody, &pb); err != nil {
		if err2 := json.Unmarshal(bundleBody, &pb); err2 != nil {
			return fmt.Errorf("parse sigstore bundle: %w", err)
		}
	}
	b, err := bundle.NewBundle(&pb)
	if err != nil {
		return fmt.Errorf("wrap sigstore bundle: %w", err)
	}
	sev, err := verify.NewVerifier(v.root,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("construct verifier: %w", err)
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest(digestAlg, digest),
		verify.WithoutIdentitiesUnsafe(),
	)
	if _, err := sev.Verify(b, policy); err != nil {
		return fmt.Errorf("sigstore verify: %w", err)
	}
	return nil
}
