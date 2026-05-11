package npm

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/git-pkgs/pin/source"
)

// Attestation re-exports source.Attestation for internal use.
type Attestation = source.Attestation

// distAttestationsRef is the shape of dist.attestations in an npm version
// document: a single pointer to a separate attestations endpoint, plus a
// hint about what predicate types live there.
type distAttestationsRef struct {
	URL        string `json:"url"`
	Provenance struct {
		PredicateType string `json:"predicateType"`
	} `json:"provenance"`
}

// attestationListResponse is what the npm /-/npm/v1/attestations endpoint
// returns: an array of {predicateType, bundle} entries.
type attestationListResponse struct {
	Attestations []struct {
		PredicateType string         `json:"predicateType"`
		Bundle        sigstoreBundle `json:"bundle"`
	} `json:"attestations"`
}

// fetchAttestation looks up the SLSA Provenance attestation for a version.
// Returns nil with no error when the version has no attestation pointer.
func (s *Source) fetchAttestation(ctx context.Context, raw json.RawMessage) (*Attestation, error) {
	ref := findAttestationRef(raw)
	if ref == nil {
		return nil, nil
	}
	var list attestationListResponse
	if err := s.http.GetJSON(ctx, ref.URL, &list); err != nil {
		return nil, fmt.Errorf("fetch attestations %s: %w", ref.URL, err)
	}
	for _, a := range list.Attestations {
		if !strings.HasPrefix(a.PredicateType, "https://slsa.dev/provenance/") {
			continue
		}
		att, err := extractFromBundle(&a.Bundle)
		if err != nil {
			return nil, fmt.Errorf("parse attestation bundle %s: %w", ref.URL, err)
		}
		att.BundleURL = ref.URL
		if att.PredicateType == "" {
			att.PredicateType = a.PredicateType
		}
		return att, nil
	}
	return nil, nil
}

func findAttestationRef(raw json.RawMessage) *distAttestationsRef {
	if len(raw) == 0 {
		return nil
	}
	var v struct {
		Dist struct {
			Attestations *distAttestationsRef `json:"attestations"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	if v.Dist.Attestations != nil && v.Dist.Attestations.URL != "" {
		return v.Dist.Attestations
	}
	return nil
}

type sigstoreBundle struct {
	DSSEEnvelope         dsseEnvelope         `json:"dsseEnvelope"`
	VerificationMaterial verificationMaterial `json:"verificationMaterial"`
}

type dsseEnvelope struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
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

type inTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []inTotoSubject `json:"subject"`
	Predicate     slsaPredicate   `json:"predicate"`
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type slsaPredicate struct {
	BuildDefinition slsaBuildDefinition `json:"buildDefinition"`
	RunDetails      slsaRunDetails      `json:"runDetails"`
}

type slsaBuildDefinition struct {
	ExternalParameters   json.RawMessage `json:"externalParameters"`
	ResolvedDependencies []slsaResource  `json:"resolvedDependencies"`
}

type slsaResource struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type slsaRunDetails struct {
	Builder slsaBuilder `json:"builder"`
}

type slsaBuilder struct {
	ID string `json:"id"`
}

func extractFromBundle(b *sigstoreBundle) (*Attestation, error) {
	if b.DSSEEnvelope.Payload == "" {
		return nil, fmt.Errorf("bundle has no DSSE payload")
	}

	payload, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}

	var stmt inTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("decode in-toto statement: %w", err)
	}

	att := &Attestation{
		PredicateType: stmt.PredicateType,
		BuilderID:     stmt.Predicate.RunDetails.Builder.ID,
	}

	// resolvedDependencies[0] is conventionally the source repo by URI/digest
	for _, dep := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		if strings.HasPrefix(dep.URI, "git+") {
			att.SourceRepository = strings.TrimSuffix(strings.TrimPrefix(dep.URI, "git+"), ".git")
			for alg, hex := range dep.Digest {
				if alg == "sha1" || alg == "gitCommit" {
					att.SourceRevision = hex
					break
				}
			}
			break
		}
	}

	att.SignerIdentity = extractSignerIdentity(b.VerificationMaterial)

	// resolvedDependencies often record the source repo as a git+https URI
	// with refs/heads/... in the path; clean that for SourceRepository,
	// and pull SourceRevision from the digest if present.
	if att.SourceRepository != "" {
		if i := strings.Index(att.SourceRepository, "@refs/"); i >= 0 {
			att.SourceRepository = att.SourceRepository[:i]
		}
	}
	return att, nil
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
