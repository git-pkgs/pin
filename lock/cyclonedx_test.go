package lock

import (
	"strings"
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

func TestCycloneDXMultiHashRoundTrip(t *testing.T) {
	const sri256 = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	fileIntegrity := strings.Join([]string{sri256, sri384a, sri384b}, " ")
	packageIntegrity := strings.Join([]string{sri256, sri512}, " ")
	want := &Lock{Assets: []Asset{{
		Name:             "multi-hash",
		Version:          "1.0.0",
		PURL:             "pkg:npm/multi-hash@1.0.0",
		Path:             "dist/index.js",
		Out:              "multi-hash/index.js",
		Integrity:        fileIntegrity,
		PackageIntegrity: packageIntegrity,
	}}}

	encoded := write(t, want)
	got, err := Read(strings.NewReader(encoded))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.Assets) != 1 {
		t.Fatalf("Assets = %d, want 1", len(got.Assets))
	}
	if got.Assets[0].Integrity != fileIntegrity {
		t.Errorf("Integrity = %q, want %q", got.Assets[0].Integrity, fileIntegrity)
	}
	if got.Assets[0].PackageIntegrity != packageIntegrity {
		t.Errorf("PackageIntegrity = %q, want %q", got.Assets[0].PackageIntegrity, packageIntegrity)
	}
}

func TestCycloneDXRejectsMalformedSupportedHashes(t *testing.T) {
	tests := []struct {
		name string
		bom  cdxBOM
	}{
		{
			name: "package hash",
			bom: cdxBOM{Components: []cdxComponent{{
				Name:   "bad-package",
				Hashes: []cdxHash{{Alg: "SHA-512", Content: "abcd"}},
			}}},
		},
		{
			name: "file hash",
			bom: cdxBOM{Components: []cdxComponent{{
				Name: "bad-file",
				Components: []cdxComponent{{
					Name:   "index.js",
					Hashes: []cdxHash{{Alg: "SHA-384", Content: "not-hex"}},
				}},
			}}},
		},
		{
			name: "forge commit hash",
			bom: cdxBOM{Components: []cdxComponent{{
				Name:   "bad-commit",
				Hashes: []cdxHash{{Alg: "SHA-1", Content: "abc123"}},
			}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fromCDX(&test.bom); err == nil {
				t.Fatal("fromCDX returned nil error")
			}
		})
	}
}

func TestCycloneDXIgnoresUnsupportedHashes(t *testing.T) {
	bom := cdxBOM{Components: []cdxComponent{{
		Name: "other-hash",
		Components: []cdxComponent{{
			Name:   "index.js",
			Hashes: []cdxHash{{Alg: "BLAKE3", Content: "abcd"}},
		}},
	}}}
	lock, err := fromCDX(&bom)
	if err != nil {
		t.Fatalf("fromCDX: %v", err)
	}
	if len(lock.Assets) != 1 || lock.Assets[0].Integrity != "" {
		t.Errorf("Assets = %+v", lock.Assets)
	}
}
