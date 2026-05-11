package manifest

import (
	"os"
	"strings"
	"testing"
)

func mustRead(t *testing.T, path string) *Manifest {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	m, err := Read(f)
	if err != nil {
		t.Fatalf("Read(%s): %v", path, err)
	}
	return m
}

func TestReadScrutineer(t *testing.T) {
	m := mustRead(t, "testdata/scrutineer.yaml")

	if m.Out != "internal/web/static/vendor" {
		t.Errorf("Out = %q", m.Out)
	}
	if m.Layout != LayoutNested {
		t.Errorf("Layout = %q, want default nested", m.Layout)
	}
	if got := len(m.Assets); got != 6 {
		t.Fatalf("Assets = %d, want 6", got)
	}

	tw := m.Assets[0]
	if tw.Name != "@tailwindcss/browser" || tw.Version != "4.3.0" {
		t.Errorf("tailwind = %+v", tw)
	}
	if tw.Files != nil {
		t.Errorf("tailwind.Files should be nil (omitted), got %v", tw.Files)
	}
	if tw.Source().Kind != SourceNPM {
		t.Errorf("tailwind source kind = %s, want npm", tw.Source().Kind)
	}

	hl := m.Assets[2]
	if hl.Name != "highlight.js" {
		t.Fatalf("assets[2] = %s, want highlight.js", hl.Name)
	}
	src := hl.Source()
	if src.Kind != SourceForge || src.Forge != "github" || src.Owner != "highlightjs" || src.Repo != "cdn-release" {
		t.Errorf("highlight source = %+v", src)
	}
	if got := len(hl.Files); got != 3 {
		t.Errorf("highlight files = %d, want 3", got)
	}

	htmx := m.Assets[4]
	if htmx.Name != "htmx.org" || htmx.Version != "^2.0" {
		t.Errorf("htmx = %+v", htmx)
	}

	lucide := m.Assets[5]
	if lucide.Format != "umd" {
		t.Errorf("lucide format = %q, want umd", lucide.Format)
	}
}

func TestReadErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			"missing out",
			`assets: [{name: foo, version: "1.0"}]`,
			`out is required`,
		},
		{
			"no assets",
			`out: "x"`,
			`at least one asset`,
		},
		{
			"empty name",
			`out: "x"
assets:
  - name: ""
    version: "1.0"`,
			`name is required`,
		},
		{
			"empty version",
			`out: "x"
assets:
  - name: "foo"
    version: ""`,
			`version is required`,
		},
		{
			"explicit empty files",
			`out: "x"
assets:
  - name: "foo"
    version: "1.0"
    files: []`,
			`files: []`,
		},
		{
			"absolute file path",
			`out: "x"
assets:
  - name: "foo"
    version: "1.0"
    files: ["/etc/passwd"]`,
			`absolute path`,
		},
		{
			"path traversal",
			`out: "x"
assets:
  - name: "foo"
    version: "1.0"
    files: ["../escape"]`,
			`escapes`,
		},
		{
			"unknown asset field",
			`out: "x"
assets:
  - name: "foo"
    version: "1.0"
    bogus: true`,
			`bogus`,
		},
		{
			"bad source",
			`out: "x"
assets:
  - name: "foo"
    version: "1.0"
    source: "ftp:foo"`,
			`unknown source`,
		},
		{
			"bad layout",
			`out: "x"
layout: "weird"
assets: [{name: foo, version: "1.0"}]`,
			`layout`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(tc.yaml))
			if err == nil {
				t.Fatalf("Read succeeded, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want containing %q", err, tc.want)
			}
		})
	}
}

func TestUnknownTopLevelKey(t *testing.T) {
	yaml := `out: "x"
trust:
  require_provenance: true
future_field: "ignored"
assets:
  - name: "foo"
    version: "1.0"`
	m, err := Read(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Read failed on unknown top-level key: %v", err)
	}
	if len(m.Assets) != 1 {
		t.Errorf("Assets = %d", len(m.Assets))
	}
}

func TestLayoutFlat(t *testing.T) {
	yaml := `out: "x"
layout: "flat"
assets: [{name: foo, version: "1.0"}]`
	m, err := Read(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if m.Layout != LayoutFlat {
		t.Errorf("Layout = %q", m.Layout)
	}
}
