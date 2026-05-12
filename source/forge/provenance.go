package forge

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// parseGitHubBundle pulls SLSA Provenance fields out of a sigstore bundle
// returned by GitHub's attestations API. Same DSSE-envelope + in-toto
// statement shape as npm's attestation bundles; the source package
// duplicates a minimal copy of the parser rather than importing
// source/npm to keep package coupling one-way.
func parseGitHubBundle(body []byte) (*Attestation, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var b struct {
		DSSEEnvelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
		VerificationMaterial struct {
			Certificate *struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificate"`
			X509CertificateChain *struct {
				Certificates []struct {
					RawBytes string `json:"rawBytes"`
				} `json:"certificates"`
			} `json:"x509CertificateChain"`
		} `json:"verificationMaterial"`
	}
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
	var stmt struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			BuildDefinition struct {
				ResolvedDependencies []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
			} `json:"runDetails"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("decode in-toto statement: %w", err)
	}
	att := &Attestation{
		PredicateType: stmt.PredicateType,
		BuilderID:     stmt.Predicate.RunDetails.Builder.ID,
	}
	for _, dep := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		if rest, ok := strings.CutPrefix(dep.URI, "git+"); ok {
			att.SourceRepository = strings.TrimSuffix(rest, ".git")
			if i := strings.Index(att.SourceRepository, "@refs/"); i >= 0 {
				att.SourceRepository = att.SourceRepository[:i]
			}
			for alg, hex := range dep.Digest {
				if alg == "sha1" || alg == "gitCommit" {
					att.SourceRevision = hex
					break
				}
			}
			break
		}
	}
	att.SignerIdentity = extractGitHubSignerIdentity(b.VerificationMaterial)
	return att, nil
}

func extractGitHubSignerIdentity(m struct {
	Certificate *struct {
		RawBytes string `json:"rawBytes"`
	} `json:"certificate"`
	X509CertificateChain *struct {
		Certificates []struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificates"`
	} `json:"x509CertificateChain"`
},
) string {
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
