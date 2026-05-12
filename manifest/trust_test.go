package manifest

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestEffectiveTrust(t *testing.T) {
	yes, no := boolPtr(true), boolPtr(false)

	cases := []struct {
		name          string
		manifestTrust *Trust
		entryTrust    *Trust
		wantProv      bool
		wantPublisher bool
		wantIssuers   []string
		wantWorkflows []string
	}{
		{
			"defaults nil/nil",
			nil, nil,
			false, false, nil, nil,
		},
		{
			"manifest sets both, entry inherits",
			&Trust{RequireProvenance: yes, RequirePublisherMatchesRepository: yes},
			nil,
			true, true, nil, nil,
		},
		{
			"entry opts out of provenance only",
			&Trust{RequireProvenance: yes, RequirePublisherMatchesRepository: yes},
			&Trust{RequireProvenance: no},
			false, true, nil, nil,
		},
		{
			"workflow lists merge",
			&Trust{TrustedWorkflows: []string{"https://github.com/a/wf"}},
			&Trust{TrustedWorkflows: []string{"https://github.com/b/wf"}},
			false, false, nil,
			[]string{"https://github.com/a/wf", "https://github.com/b/wf"},
		},
		{
			"duplicate workflow dedupes",
			&Trust{TrustedWorkflows: []string{"https://github.com/a/wf"}},
			&Trust{TrustedWorkflows: []string{"https://github.com/a/wf"}},
			false, false, nil,
			[]string{"https://github.com/a/wf"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manifest{Trust: tc.manifestTrust}
			e := &Entry{Trust: tc.entryTrust}
			got := m.EffectiveTrust(e)
			if BoolValue(got.RequireProvenance) != tc.wantProv {
				t.Errorf("RequireProvenance = %v, want %v", BoolValue(got.RequireProvenance), tc.wantProv)
			}
			if BoolValue(got.RequirePublisherMatchesRepository) != tc.wantPublisher {
				t.Errorf("RequirePublisherMatchesRepository = %v, want %v", BoolValue(got.RequirePublisherMatchesRepository), tc.wantPublisher)
			}
			if !sliceEqual(got.TrustedWorkflows, tc.wantWorkflows) {
				t.Errorf("TrustedWorkflows = %v, want %v", got.TrustedWorkflows, tc.wantWorkflows)
			}
		})
	}
}

func TestTrustParsesFromYAML(t *testing.T) {
	src := `out: v
trust:
  require_provenance: true
  trusted_workflows:
    - https://github.com/some-org/builder/.github/workflows/release.yml
assets:
  - name: foo
    version: "1.0.0"
    files: [dist/x.js]
  - name: bar
    version: "1.0.0"
    files: [dist/y.js]
    trust:
      require_provenance: false
`
	m, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if m.Trust == nil || !BoolValue(m.Trust.RequireProvenance) {
		t.Errorf("manifest.Trust = %+v", m.Trust)
	}
	if len(m.Trust.TrustedWorkflows) != 1 {
		t.Errorf("TrustedWorkflows = %v", m.Trust.TrustedWorkflows)
	}
	fooTrust := m.EffectiveTrust(&m.Assets[0])
	if !BoolValue(fooTrust.RequireProvenance) {
		t.Error("foo should inherit require_provenance=true")
	}
	barTrust := m.EffectiveTrust(&m.Assets[1])
	if BoolValue(barTrust.RequireProvenance) {
		t.Error("bar should override require_provenance to false")
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
