package pin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func setupSynced(t *testing.T) (dir string, srv string) {
	t.Helper()
	srvT := fakeNPM(t, "demo", "1.0.0", map[string]string{
		"dist/a.js":  "alpha",
		"dist/b.css": "beta",
	})
	dir = t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/a.js", "dist/b.css"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srvT.URL}); err != nil {
		t.Fatal(err)
	}
	return dir, srvT.URL
}

func TestVerifyClean(t *testing.T) {
	dir, _ := setupSynced(t)
	res, err := Verify(VerifyOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed() {
		t.Errorf("clean verify failed: %+v", res)
	}
	if len(res.OK) != 2 {
		t.Errorf("OK = %d, want 2", len(res.OK))
	}
	if len(res.Extra) != 0 {
		t.Errorf("Extra = %v", res.Extra)
	}
}

func TestVerifyMissing(t *testing.T) {
	dir, _ := setupSynced(t)
	if err := os.Remove(filepath.Join(dir, "v/demo/a.js")); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(VerifyOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed() {
		t.Error("missing file should fail verify")
	}
	if len(res.Missing) != 1 || res.Missing[0] != "demo/a.js" {
		t.Errorf("Missing = %v", res.Missing)
	}
	if len(res.OK) != 1 {
		t.Errorf("OK = %d, want 1", len(res.OK))
	}
}

func TestVerifyDrifted(t *testing.T) {
	dir, _ := setupSynced(t)
	if err := os.WriteFile(filepath.Join(dir, "v/demo/a.js"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(VerifyOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed() {
		t.Error("drifted file should fail verify")
	}
	if len(res.Drifted) != 1 || res.Drifted[0].Out != "demo/a.js" {
		t.Errorf("Drifted = %v", res.Drifted)
	}
	if res.Drifted[0].Expected == res.Drifted[0].Actual {
		t.Error("expected != actual")
	}
}

func TestVerifyExtra(t *testing.T) {
	dir, _ := setupSynced(t)
	if err := os.WriteFile(filepath.Join(dir, "v/demo/leftover.js"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(VerifyOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed() {
		t.Error("extra files should not fail verify by default")
	}
	if len(res.Extra) != 1 || res.Extra[0] != "demo/leftover.js" {
		t.Errorf("Extra = %v", res.Extra)
	}
}

func TestVerifyNoLockfile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Verify(VerifyOptions{Dir: dir}); err == nil {
		t.Fatal("verify without lockfile should error")
	}
}

func TestVerifySummary(t *testing.T) {
	r := &VerifyResult{
		OK:      []string{"a", "b"},
		Missing: []string{"c"},
		Drifted: []Drift{{Out: "d"}},
		Extra:   []string{"e", "f"},
	}
	got := r.Summary()
	want := "2 ok, 1 missing, 1 drifted, 2 extra"
	if got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
}
