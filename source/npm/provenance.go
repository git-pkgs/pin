package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/pin/source"
	"github.com/git-pkgs/pin/source/attestation"
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

// fetchAttestationWithBundle returns both the parsed metadata and the raw
// bundle JSON, the latter useful for cryptographic verification.
func (s *Source) fetchAttestationWithBundle(ctx context.Context, raw json.RawMessage) (*Attestation, []byte, error) {
	ref := findAttestationRef(raw)
	if ref == nil {
		return nil, nil, nil
	}
	var list struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := s.http.GetJSON(ctx, ref.URL, &list); err != nil {
		return nil, nil, fmt.Errorf("fetch attestations %s: %w", ref.URL, err)
	}
	for _, a := range list.Attestations {
		if !strings.HasPrefix(a.PredicateType, "https://slsa.dev/provenance/") {
			continue
		}
		parsed, err := attestation.Parse(a.Bundle)
		if err != nil {
			return nil, nil, fmt.Errorf("parse attestation bundle %s: %w", ref.URL, err)
		}
		if parsed == nil {
			continue
		}
		predicateType := parsed.PredicateType
		if predicateType == "" {
			predicateType = a.PredicateType
		}
		return &Attestation{
			PredicateType:    predicateType,
			BuilderID:        parsed.BuilderID,
			SourceRepository: parsed.SourceRepository,
			SourceRevision:   parsed.SourceRevision,
			SignerIdentity:   parsed.SignerIdentity,
			BundleURL:        ref.URL,
		}, []byte(a.Bundle), nil
	}
	return nil, nil, nil
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
