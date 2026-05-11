package manifest

import (
	"bytes"
	"strings"
	"testing"
)

func TestAddEntry(t *testing.T) {
	in := `# scrutineer assets
out: "static/vendor"

assets:
  - name: "alpha"
    version: "1.0.0"
  - name: "zebra"
    version: "2.0.0"
`
	var out bytes.Buffer
	err := AddEntry(strings.NewReader(in), &out, Entry{
		Name:    "middle",
		Version: "^1.5",
		Files:   []string{"dist/x.js"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()

	if !strings.Contains(got, "# scrutineer assets") {
		t.Error("comment not preserved")
	}
	posAlpha := strings.Index(got, "alpha")
	posMiddle := strings.Index(got, "middle")
	posZebra := strings.Index(got, "zebra")
	if posAlpha >= posMiddle || posMiddle >= posZebra {
		t.Errorf("alphabetic order: alpha=%d middle=%d zebra=%d\n%s", posAlpha, posMiddle, posZebra, got)
	}
	if !strings.Contains(got, "version: ^1.5") {
		t.Errorf("version not written:\n%s", got)
	}
	if !strings.Contains(got, "dist/x.js") {
		t.Errorf("files not written:\n%s", got)
	}

	m, err := Read(strings.NewReader(got))
	if err != nil {
		t.Fatalf("output not re-parseable: %v\n%s", err, got)
	}
	if len(m.Assets) != 3 {
		t.Errorf("Assets = %d, want 3", len(m.Assets))
	}
}

func TestAddEntryDuplicate(t *testing.T) {
	in := `out: "x"
assets:
  - name: "foo"
    version: "1.0.0"
`
	var out bytes.Buffer
	err := AddEntry(strings.NewReader(in), &out, Entry{Name: "foo", Version: "2.0.0"})
	if err == nil || !strings.Contains(err.Error(), "already in the manifest") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestAddEntryKeyOrder(t *testing.T) {
	in := `out: "x"
assets: []
`
	var out bytes.Buffer
	err := AddEntry(strings.NewReader(in), &out, Entry{
		Name:      "foo",
		Version:   "1.0.0",
		RawSource: "github:owner/repo",
		Files:     []string{"a.js"},
		Format:    "esm",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, pair := range [][2]string{
		{"name:", "version:"},
		{"version:", "source:"},
		{"source:", "files:"},
		{"files:", "format:"},
	} {
		if strings.Index(got, pair[0]) > strings.Index(got, pair[1]) {
			t.Errorf("key order: %q should come before %q\n%s", pair[0], pair[1], got)
		}
	}
}
