package lock

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/golden_*.json files from current Write output")

const (
	sri384a = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
	sri384b = "sha384-fFzT/J/M5jeR8X8U8Z9Z8X8U8Z9Z8X8U8Z9Z8X8U8Z9Z8X8U8Z9Z8X8U8Z9Z8X8U"
	sri512  = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
)

func sample() *Lock {
	return &Lock{
		OutDir: "internal/web/static/vendor",
		Assets: []Asset{
			{
				Name:             "htmx.org",
				Version:          "2.0.6",
				PURL:             "pkg:npm/htmx.org@2.0.6",
				Type:             "script",
				Format:           "iife",
				Path:             "dist/htmx.min.js",
				Out:              "htmx.org/htmx.min.js",
				URL:              "https://cdn.jsdelivr.net/npm/htmx.org@2.0.6/dist/htmx.min.js",
				Integrity:        sri384a,
				Size:             51007,
				PackageIntegrity: sri512,
				License:          "0BSD",
				Repository:       "https://github.com/bigskysoftware/htmx",
			},
			{
				Name:             "basecoat-css",
				Version:          "0.3.11",
				PURL:             "pkg:npm/basecoat-css@0.3.11",
				Type:             "style",
				Path:             "dist/basecoat.cdn.min.css",
				Out:              "basecoat-css/basecoat.cdn.min.css",
				URL:              "https://cdn.jsdelivr.net/npm/basecoat-css@0.3.11/dist/basecoat.cdn.min.css",
				Integrity:        sri384b,
				Size:             12345,
				PackageIntegrity: sri512,
				License:          "MIT",
			},
			{
				Name:             "basecoat-css",
				Version:          "0.3.11",
				PURL:             "pkg:npm/basecoat-css@0.3.11",
				Type:             "script",
				Path:             "dist/js/all.min.js",
				Out:              "basecoat-css/all.min.js",
				URL:              "https://cdn.jsdelivr.net/npm/basecoat-css@0.3.11/dist/js/all.min.js",
				Integrity:        sri384a,
				Size:             6789,
				PackageIntegrity: sri512,
				License:          "MIT",
			},
		},
	}
}

// sampleMixed returns a Lock covering one entry per source kind (npm,
// github forge, url TOFU). Used by TestGoldenLockfile as the
// regression fixture so any change to Write's output is a visible diff
// against testdata/golden_mixed.json.
func sampleMixed() *Lock {
	return &Lock{
		OutDir: "internal/web/static/vendor",
		Assets: []Asset{
			{
				Name:             "htmx.org",
				Version:          "2.0.6",
				PURL:             "pkg:npm/htmx.org@2.0.6",
				Type:             "script",
				Format:           "iife",
				Path:             "dist/htmx.min.js",
				Out:              "htmx.org/htmx.min.js",
				URL:              "https://cdn.jsdelivr.net/npm/htmx.org@2.0.6/dist/htmx.min.js",
				Integrity:        sri384a,
				Size:             51007,
				PackageIntegrity: sri512,
				License:          "0BSD",
				Repository:       "https://github.com/bigskysoftware/htmx",
			},
			{
				Name:             "highlight.js",
				Version:          "11.11.1",
				PURL:             "pkg:github/highlightjs/cdn-release@11.11.1?vcs_revision=abc123def4567890abc123def4567890abc12345",
				Type:             "script",
				Path:             "build/highlight.min.js",
				Out:              "highlightjs__cdn-release/highlight.min.js",
				URL:              "https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@abc123def4567890abc123def4567890abc12345/build/highlight.min.js",
				Integrity:        sri384a,
				Size:             8000,
				PackageIntegrity: "abc123def4567890abc123def4567890abc12345",
				Repository:       "https://github.com/highlightjs/cdn-release",
			},
			{
				Name:      "my-asset",
				Version:   "1.0.0",
				PURL:      "pkg:generic/my-asset@1.0.0?download_url=https%3A%2F%2Fexample.com%2Fdist%2Fasset.js",
				Type:      "script",
				Path:      "asset.js",
				Out:       "my-asset/asset.js",
				URL:       "https://example.com/dist/asset.js",
				Integrity: sri384b,
				Size:      1024,
				// url sources use the per-file SHA-384 as their package anchor;
				// PackageIntegrity equals Integrity by construction.
				PackageIntegrity: sri384b,
			},
		},
	}
}

func TestGoldenLockfile(t *testing.T) {
	got := write(t, sampleMixed())
	path := filepath.Join("testdata", "golden_mixed.json")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skip("golden updated; re-run without -update to verify")
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (run `go test ./lock -update` to create)", err)
	}
	if got != string(want) {
		t.Errorf("Write output diverges from %s — re-run with -update if the change is intentional\n--- got ---\n%s\n--- want ---\n%s",
			path, got, want)
	}
}

func write(t *testing.T, l *Lock) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, l, "pin", "test"); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestRoundTrip(t *testing.T) {
	encoded := write(t, sample())

	if !strings.HasSuffix(encoded, "\n") {
		t.Error("output should end with a trailing newline")
	}
	if strings.Contains(encoded, "\t") {
		t.Error("output should use spaces, not tabs")
	}
	if !strings.Contains(encoded, `"bomFormat": "CycloneDX"`) {
		t.Error("output should be a CycloneDX BOM")
	}
	if !strings.Contains(encoded, `"specVersion": "1.6"`) {
		t.Error("output should declare specVersion 1.6")
	}
	if strings.Contains(encoded, "serialNumber") {
		t.Error("output must not contain serialNumber (idempotence)")
	}
	if strings.Contains(encoded, "timestamp") {
		t.Error("output must not contain timestamp (merge conflicts)")
	}

	got, err := Read(strings.NewReader(encoded))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.GeneratedBy != "pin test" {
		t.Errorf("GeneratedBy = %q", got.GeneratedBy)
	}
	if got.OutDir != "internal/web/static/vendor" {
		t.Errorf("OutDir = %q", got.OutDir)
	}
	if len(got.Assets) != 3 {
		t.Fatalf("Assets = %d, want 3", len(got.Assets))
	}

	encoded2 := write(t, got)
	if encoded != encoded2 {
		t.Errorf("Write is not byte-stable:\nfirst:\n%s\nsecond:\n%s", encoded, encoded2)
	}
}

func TestRoundTripFields(t *testing.T) {
	want := sample()
	got, err := Read(strings.NewReader(write(t, want)))
	if err != nil {
		t.Fatal(err)
	}

	wantByOut := map[string]Asset{}
	for _, a := range want.Assets {
		wantByOut[a.Out] = a
	}
	for _, a := range got.Assets {
		w, ok := wantByOut[a.Out]
		if !ok {
			t.Errorf("unexpected asset %q", a.Out)
			continue
		}
		if !reflect.DeepEqual(a, w) {
			t.Errorf("asset %q:\n got  %+v\n want %+v", a.Out, a, w)
		}
	}
}

func TestSortedByPURL(t *testing.T) {
	out := write(t, sample())
	if strings.Index(out, "pkg:npm/basecoat-css@0.3.11") > strings.Index(out, "pkg:npm/htmx.org@2.0.6") {
		t.Error("library components not sorted by purl")
	}
}

func TestNestedFilesSortedByPath(t *testing.T) {
	out := write(t, sample())
	bcStart := strings.Index(out, `"bom-ref": "pkg:npm/basecoat-css@0.3.11"`)
	bcEnd := strings.Index(out, `"bom-ref": "pkg:npm/htmx.org@2.0.6"`)
	bcBlock := out[bcStart:bcEnd]
	if strings.Index(bcBlock, "#dist/basecoat.cdn.min.css") > strings.Index(bcBlock, "#dist/js/all.min.js") {
		t.Error("file components not sorted by path within package")
	}
}

func TestUnknownKeysIgnored(t *testing.T) {
	js := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "future_top_level": true,
  "metadata": {
    "tools": {"components": [{"type": "application", "name": "pin", "version": "x"}]},
    "properties": [{"name": "pin:lockfile_version", "value": "1"}]
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/foo@1.0.0",
      "name": "foo",
      "version": "1.0.0",
      "purl": "pkg:npm/foo@1.0.0",
      "pedigree": {"ancestors": []},
      "components": [
        {
          "type": "file",
          "bom-ref": "pkg:npm/foo@1.0.0#x.js",
          "name": "x.js",
          "properties": [{"name": "pin:out", "value": "foo/x.js"}],
          "evidence": {"identity": [{"field": "purl"}]}
        }
      ]
    }
  ]
}`
	got, err := Read(strings.NewReader(js))
	if err != nil {
		t.Fatalf("Read with unknown keys: %v", err)
	}
	if len(got.Assets) != 1 || got.Assets[0].Name != "foo" || got.Assets[0].Out != "foo/x.js" {
		t.Errorf("Assets = %+v", got.Assets)
	}
}

func TestRejectsNonCycloneDX(t *testing.T) {
	if _, err := Read(strings.NewReader(`{"lockfile_version": 1}`)); err == nil {
		t.Fatal("Read accepted non-CycloneDX JSON")
	}
}

func TestRejectsWrongLockfileVersion(t *testing.T) {
	js := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "tools": {"components": []},
    "properties": [{"name": "pin:lockfile_version", "value": "999"}]
  },
  "components": []
}`
	if _, err := Read(strings.NewReader(js)); err == nil {
		t.Fatal("Read accepted unknown pin:lockfile_version")
	}
}

func TestDiff(t *testing.T) {
	prev := &Lock{Assets: []Asset{
		{Name: "a", Out: "a/x.js", Integrity: sri384a},
		{Name: "b", Out: "b/y.css", Integrity: sri384a},
		{Name: "d", Out: "d/z.js", Integrity: sri384a},
	}}
	next := &Lock{Assets: []Asset{
		{Name: "a", Out: "a/x.js", Integrity: sri384a},
		{Name: "b", Out: "b/y.css", Integrity: sri384b},
		{Name: "c", Out: "c/w.js", Integrity: sri384a},
	}}
	d := Diff(prev, next)
	if got := keys(d.Added); got != "c/w.js" {
		t.Errorf("Added = %q", got)
	}
	if got := keys(d.Updated); got != "b/y.css" {
		t.Errorf("Updated = %q", got)
	}
	if got := keys(d.Removed); got != "d/z.js" {
		t.Errorf("Removed = %q", got)
	}
	if got := keys(d.Unchanged); got != "a/x.js" {
		t.Errorf("Unchanged = %q", got)
	}
}

func keys(as []Asset) string {
	var sb strings.Builder
	for i, a := range as {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(a.Out)
	}
	return sb.String()
}

func TestClassifyType(t *testing.T) {
	cases := []struct {
		path string
		want AssetType
	}{
		{"foo.js", TypeScript},
		{"foo.mjs", TypeScript},
		{"foo.cjs", TypeScript},
		{"foo.css", TypeStyle},
		{"foo.woff2", TypeFont},
		{"foo.woff", TypeFont},
		{"foo.ttf", TypeFont},
		{"foo.otf", TypeFont},
		{"foo.png", TypeImage},
		{"foo.svg", TypeImage},
		{"foo.webp", TypeImage},
		{"foo.wasm", TypeWASM},
		{"foo.js.map", TypeMap},
		{"foo.txt", TypeOther},
		{"foo", TypeOther},
	}
	for _, tc := range cases {
		if got := ClassifyType(tc.path); got != tc.want {
			t.Errorf("ClassifyType(%q) = %s, want %s", tc.path, got, tc.want)
		}
	}
}
