package attestation

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func buildBundle(t *testing.T, predicateType, builderID, sourceURI, commitSHA string) []byte {
	t.Helper()
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": predicateType,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"resolvedDependencies": []map[string]any{
					{"uri": sourceURI, "digest": map[string]string{"gitCommit": commitSHA}},
				},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": builderID},
			},
		},
	}
	stmtJSON, _ := json.Marshal(stmt)
	b := map[string]any{
		"dsseEnvelope": map[string]any{
			"payload": base64.StdEncoding.EncodeToString(stmtJSON),
		},
	}
	out, _ := json.Marshal(b)
	return out
}

func TestParse_HappyPath(t *testing.T) {
	body := buildBundle(t,
		"https://slsa.dev/provenance/v1",
		"https://github.com/owner/builder/.github/workflows/release.yml@refs/tags/v1",
		"git+https://github.com/owner/repo.git@refs/heads/main",
		"deadbeef0123456789abcdef0123456789abcdef")
	att, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if att == nil {
		t.Fatal("Parse returned nil for valid bundle")
	}
	if att.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("PredicateType = %q", att.PredicateType)
	}
	if att.BuilderID != "https://github.com/owner/builder/.github/workflows/release.yml@refs/tags/v1" {
		t.Errorf("BuilderID = %q", att.BuilderID)
	}
	if att.SourceRepository != "https://github.com/owner/repo" {
		t.Errorf("SourceRepository = %q, want git+ prefix stripped and @refs/ trimmed", att.SourceRepository)
	}
	if att.SourceRevision != "deadbeef0123456789abcdef0123456789abcdef" {
		t.Errorf("SourceRevision = %q", att.SourceRevision)
	}
}

func TestParse_Empty(t *testing.T) {
	att, err := Parse(nil)
	if err != nil || att != nil {
		t.Errorf("Parse(nil) = (%v, %v), want (nil, nil)", att, err)
	}
}

func TestParse_EmptyPayload(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"dsseEnvelope": map[string]any{"payload": ""}})
	att, err := Parse(body)
	if err != nil || att != nil {
		t.Errorf("Parse(empty-payload) = (%v, %v), want (nil, nil)", att, err)
	}
}

func TestParse_MalformedJSON(t *testing.T) {
	if _, err := Parse([]byte("{not-json")); err == nil {
		t.Error("Parse(garbage) should error")
	}
}

func TestParse_NonGitURI(t *testing.T) {
	body := buildBundle(t,
		"https://slsa.dev/provenance/v1",
		"https://builder/",
		"https://example.com/not-a-git-uri", // missing git+ prefix
		"deadbeef")
	att, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if att.SourceRepository != "" {
		t.Errorf("SourceRepository = %q, want empty when no git+ URI in resolvedDependencies", att.SourceRepository)
	}
	if att.SourceRevision != "" {
		t.Errorf("SourceRevision = %q, want empty when no git+ URI matched", att.SourceRevision)
	}
}
