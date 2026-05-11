package lock

import (
	"testing"

	"github.com/git-pkgs/sbom"
)

func TestOutputIsValidCycloneDX(t *testing.T) {
	encoded := write(t, sample())

	doc, err := sbom.Parse([]byte(encoded))
	if err != nil {
		t.Fatalf("git-pkgs/sbom.Parse rejected pin.lock output: %v\n%s", err, encoded)
	}
	if sbom.Detect([]byte(encoded)) != sbom.TypeCycloneDX {
		t.Errorf("Detect did not classify output as CycloneDX")
	}
	if len(doc.Packages) == 0 {
		t.Errorf("parsed SBOM has no packages")
	}

	purls := map[string]bool{}
	for _, p := range doc.Packages {
		purls[p.PURL()] = true
	}
	for _, want := range []string{"pkg:npm/htmx.org@2.0.6", "pkg:npm/basecoat-css@0.3.11"} {
		if !purls[want] {
			t.Errorf("parsed SBOM missing package %q; got %v", want, purls)
		}
	}
}
