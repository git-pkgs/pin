// Package attestation parses a sigstore bundle's DSSE envelope and the
// in-toto statement inside it, returning the SLSA Provenance v1
// identity fields (predicate type, builder, source repo, source
// revision, signer identity).
//
// The package has no dependencies outside the standard library. It's
// intentionally self-contained so it can lift out to its own module
// without dragging pin-specific types along; the npm and forge source
// paths each map the parsed result into their own Attestation shape.
//
// Parse extracts identity fields only. It does NOT verify the
// signature, certificate chain, or transparency-log inclusion proof —
// that's the job of a separate verifier (e.g., sigstore-go).
package attestation

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// SLSA Provenance v1 uses these two digest names for the source-commit
// revision, depending on the producer.
const (
	digestAlgSHA1      = "sha1"
	digestAlgGitCommit = "gitCommit"
)

// Attestation is the identity-side projection of a SLSA Provenance v1
// statement carried inside a sigstore bundle. Field names follow the
// SLSA v1 vocabulary; the parser populates whichever fields the
// statement carries and leaves the rest as zero values.
type Attestation struct {
	// PredicateType is the in-toto statement's predicate type URI,
	// "https://slsa.dev/provenance/v1" for SLSA Provenance v1.
	PredicateType string

	// BuilderID is runDetails.builder.id — the canonical identity of
	// the builder that produced the artifact. For GitHub-Actions builds
	// this is the workflow URI with @refs/tags/<tag>.
	BuilderID string

	// SourceRepository is the git+https URL the build was driven from,
	// with the git+ prefix and trailing .git/@refs suffix stripped.
	SourceRepository string

	// SourceRevision is the commit SHA from the build's first
	// resolvedDependencies entry that carries a sha1 or gitCommit digest.
	SourceRevision string

	// SignerIdentity is the Fulcio certificate's subject — either its
	// first URI SAN (the OIDC identity that was bound at signing time)
	// or its first email SAN if no URIs are present.
	SignerIdentity string
}

// Parse decodes a sigstore bundle body and returns the SLSA Provenance
// v1 identity fields it claims. Returns (nil, nil) for an empty body
// or for a bundle whose DSSE payload is empty (the latter happens for
// non-provenance bundles that share the sigstore shape). Errors on
// malformed DSSE / in-toto JSON.
func Parse(body []byte) (*Attestation, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var b bundle
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}
	if b.DSSEEnvelope.Payload == "" {
		return nil, nil
	}
	payload, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}
	var stmt statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("decode in-toto statement: %w", err)
	}

	att := &Attestation{
		PredicateType: stmt.PredicateType,
		BuilderID:     stmt.Predicate.RunDetails.Builder.ID,
	}
	for _, dep := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		rest, ok := strings.CutPrefix(dep.URI, "git+")
		if !ok {
			continue
		}
		// Strip the @refs/<...> ref segment first so any trailing .git
		// sits at the end of the string for TrimSuffix to find.
		if i := strings.Index(rest, "@refs/"); i >= 0 {
			rest = rest[:i]
		}
		att.SourceRepository = strings.TrimSuffix(rest, ".git")
		for alg, hex := range dep.Digest {
			if alg == digestAlgSHA1 || alg == digestAlgGitCommit {
				att.SourceRevision = hex
				break
			}
		}
		break
	}
	att.SignerIdentity = extractSignerIdentity(b.VerificationMaterial)
	return att, nil
}

type bundle struct {
	DSSEEnvelope         dsseEnvelope         `json:"dsseEnvelope"`
	VerificationMaterial verificationMaterial `json:"verificationMaterial"`
}

type dsseEnvelope struct {
	Payload string `json:"payload"`
}

type verificationMaterial struct {
	Certificate          *cert  `json:"certificate"`
	X509CertificateChain *chain `json:"x509CertificateChain"`
}

type cert struct {
	RawBytes string `json:"rawBytes"`
}

type chain struct {
	Certificates []cert `json:"certificates"`
}

type statement struct {
	PredicateType string    `json:"predicateType"`
	Predicate     predicate `json:"predicate"`
}

type predicate struct {
	BuildDefinition buildDefinition `json:"buildDefinition"`
	RunDetails      runDetails      `json:"runDetails"`
}

type buildDefinition struct {
	ResolvedDependencies []resource `json:"resolvedDependencies"`
}

type resource struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type runDetails struct {
	Builder builder `json:"builder"`
}

type builder struct {
	ID string `json:"id"`
}

func extractSignerIdentity(m verificationMaterial) string {
	var raw string
	switch {
	case m.Certificate != nil && m.Certificate.RawBytes != "":
		raw = m.Certificate.RawBytes
	case m.X509CertificateChain != nil && len(m.X509CertificateChain.Certificates) > 0:
		raw = m.X509CertificateChain.Certificates[0].RawBytes
	default:
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	if block, _ := pem.Decode(der); block != nil {
		der = block.Bytes
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	if len(c.URIs) > 0 {
		return c.URIs[0].String()
	}
	if len(c.EmailAddresses) > 0 {
		return c.EmailAddresses[0]
	}
	return ""
}
