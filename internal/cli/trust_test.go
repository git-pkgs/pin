package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pin "github.com/git-pkgs/pin"
)

func TestCLI_SyncRejectsProvenanceBeforeWriting(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "rejected content"})
	for _, tc := range []struct {
		name  string
		trust string
		flags []string
	}{
		{name: "manifest", trust: "trust:\n  require_provenance: true\n"},
		{name: "flag", flags: []string{"--strict-provenance"}},
		{name: "dry-run", trust: "trust:\n  require_provenance: true\n", flags: []string{"--dry-run"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeManifest(t, dir, tc.trust+`out: v
assets:
  - name: demo
    version: 1.0.0
    files: [dist/x.js]
`)
			args := append([]string{"sync", "-C", dir, "--registry", srv.URL}, tc.flags...)
			if _, err := runCmd(t, args...); !errors.Is(err, pin.ErrProvenanceMissing) {
				t.Fatalf("sync error = %v, want ErrProvenanceMissing", err)
			}
			for _, path := range []string{"v", "pin.lock"} {
				if _, err := os.Stat(filepath.Join(dir, path)); !os.IsNotExist(err) {
					t.Errorf("rejected sync created %s: stat error = %v", path, err)
				}
			}
		})
	}
}

func TestCLI_SyncTrustFailurePreservesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	oldRegistry := fakeRegistry(t, "demo", "1.0.0", map[string]string{
		"dist/x.js":   "original content",
		"dist/old.js": "orphan content",
	})
	writeManifest(t, dir, `out: v
assets:
  - name: demo
    version: 1.0.0
    files: [dist/x.js, dist/old.js]
`)
	if _, err := runCmd(t, "sync", "-C", dir, "--registry", oldRegistry.URL); err != nil {
		t.Fatal(err)
	}
	oldLock, err := os.ReadFile(filepath.Join(dir, "pin.lock"))
	if err != nil {
		t.Fatal(err)
	}

	newRegistry := fakeRegistry(t, "demo", "2.0.0", map[string]string{
		"dist/x.js":   "rejected content",
		"dist/new.js": "new rejected content",
	})
	writeManifest(t, dir, `out: v
trust:
  require_provenance: true
assets:
  - name: demo
    version: 2.0.0
    files: [dist/x.js, dist/new.js]
`)
	if _, err := runCmd(t, "sync", "-C", dir, "--registry", newRegistry.URL); !errors.Is(err, pin.ErrProvenanceMissing) {
		t.Fatalf("sync error = %v, want ErrProvenanceMissing", err)
	}
	for path, want := range map[string][]byte{
		"v/demo/x.js":   []byte("original content"),
		"v/demo/old.js": []byte("orphan content"),
		"pin.lock":      oldLock,
	} {
		got, err := os.ReadFile(filepath.Join(dir, path))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("rejected sync changed %s", path)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "v/demo/new.js")); !os.IsNotExist(err) {
		t.Errorf("rejected sync created new asset: stat error = %v", err)
	}
}
