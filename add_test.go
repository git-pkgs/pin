package pin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdd_EndToEnd(t *testing.T) {
	srv := fakeNPM(t, "newpkg", "1.2.3", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "existing"
    version: "1.0.0"
    files: ["x.js"]
`)
	// Seed lockfile with an unrelated entry so Add's call to Sync has
	// something to start from. We won't actually fetch existing — give
	// it a registry that 404s and the manifest already has the locked
	// version. Easier path: just add to an empty manifest.
	writeManifest(t, dir, `out: "v"
assets: []
`)

	res, err := Add(context.Background(),
		"newpkg@1.2.3",
		[]string{"dist/x.js"},
		AddOptions{Dir: dir, RegistryURL: srv.URL})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if res.Resolved != "1.2.3" {
		t.Errorf("Resolved = %q, want 1.2.3", res.Resolved)
	}
	if res.SyncResult == nil || len(res.SyncResult.Lock.Assets) != 1 {
		t.Errorf("SyncResult missing or empty: %+v", res.SyncResult)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(dir, DefaultManifest))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifestBytes), "newpkg") {
		t.Errorf("manifest does not contain newpkg after Add:\n%s", manifestBytes)
	}
}

func TestAdd_DryRun(t *testing.T) {
	srv := fakeNPM(t, "newpkg", "1.0.0", map[string]string{"index.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets: []
`)
	original, _ := os.ReadFile(filepath.Join(dir, DefaultManifest))

	res, err := Add(context.Background(),
		"newpkg@1.0.0",
		[]string{"index.js"},
		AddOptions{Dir: dir, RegistryURL: srv.URL, DryRun: true})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if res.Resolved != "1.0.0" {
		t.Errorf("Resolved = %q", res.Resolved)
	}

	after, _ := os.ReadFile(filepath.Join(dir, DefaultManifest))
	if string(original) != string(after) {
		t.Error("--dry-run modified the manifest:\nbefore:\n" + string(original) + "\nafter:\n" + string(after))
	}
}

func TestAdd_EmptyNameRejected(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "out: v\nassets: []\n")
	_, err := Add(context.Background(), "", nil, AddOptions{Dir: dir})
	if err == nil {
		t.Error("Add with empty spec should error")
	}
}

func TestParseSpec(t *testing.T) {
	cases := []struct {
		in               string
		name, constraint string
	}{
		{"htmx.org", "htmx.org", ""},
		{"htmx.org@2.0.6", "htmx.org", "2.0.6"},
		{"htmx.org@^2.0", "htmx.org", "^2.0"},
		{"htmx.org@latest", "htmx.org", "latest"},
		{"@scope/pkg", "@scope/pkg", ""},
		{"@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"},
		{"@scope/pkg@^1.0", "@scope/pkg", "^1.0"},
	}
	for _, tc := range cases {
		name, c := parseSpec(tc.in)
		if name != tc.name || c != tc.constraint {
			t.Errorf("parseSpec(%q) = %q, %q; want %q, %q", tc.in, name, c, tc.name, tc.constraint)
		}
	}
}

func TestCaretMajorMinor(t *testing.T) {
	cases := map[string]string{
		"2.0.6":        "^2.0",
		"1.5.0":        "^1.5",
		"0.3.11":       "^0.3",
		"4.0.0-beta.1": "^4.0",
		"1":            "^1",
	}
	for in, want := range cases {
		if got := caretMajorMinor(in); got != want {
			t.Errorf("caretMajorMinor(%q) = %q, want %q", in, got, want)
		}
	}
}
