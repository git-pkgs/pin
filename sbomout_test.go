package pin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/git-pkgs/sbom"
)

func TestSBOMCycloneDXPassthrough(t *testing.T) {
	dir, _ := setupSynced(t)
	var buf bytes.Buffer
	if err := SBOM(&buf, SBOMOptions{Dir: dir, Format: SBOMCycloneDXJSON}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"bomFormat": "CycloneDX"`) {
		t.Error("output is not CycloneDX")
	}
	if sbom.Detect(buf.Bytes()) != sbom.TypeCycloneDX {
		t.Error("git-pkgs/sbom did not detect output as CycloneDX")
	}
}

func TestSBOMSPDX(t *testing.T) {
	dir, _ := setupSynced(t)
	var buf bytes.Buffer
	if err := SBOM(&buf, SBOMOptions{Dir: dir, Format: SBOMSPDXJSON}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "spdxVersion") && !strings.Contains(buf.String(), "SPDX") {
		t.Errorf("output does not look like SPDX:\n%s", buf.String()[:min(200, len(buf.String()))])
	}
	doc, err := sbom.Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("SPDX output not parseable: %v", err)
	}
	if len(doc.Packages) == 0 {
		t.Error("SPDX output has no packages")
	}
}

func TestSBOMCycloneDXXML(t *testing.T) {
	dir, _ := setupSynced(t)
	var buf bytes.Buffer
	if err := SBOM(&buf, SBOMOptions{Dir: dir, Format: SBOMCycloneDXXML}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<?xml") || !strings.Contains(out, "<bom") {
		t.Errorf("output does not look like CycloneDX XML:\n%s", out[:min(200, len(out))])
	}
}

func TestSBOMUnknownFormat(t *testing.T) {
	dir, _ := setupSynced(t)
	var buf bytes.Buffer
	if err := SBOM(&buf, SBOMOptions{Dir: dir, Format: "csv"}); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
