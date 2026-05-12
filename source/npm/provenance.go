package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/attestation"
	"github.com/git-pkgs/registries"

	"github.com/git-pkgs/pin/source"
)

type Attestation = source.Attestation

// fetchAttestationWithBundle returns parsed metadata plus the raw
// bundle bytes for the caller to verify cryptographically.
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

func findAttestationRef(raw json.RawMessage) *registries.NPMAttestationRef {
	if len(raw) == 0 {
		return nil
	}
	var v struct {
		Dist struct {
			Attestations *registries.NPMAttestationRef `json:"attestations"`
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
