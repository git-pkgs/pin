package pin

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
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

func TestVerifyMultiHash(t *testing.T) {
	dir, _ := setupSynced(t)
	addMultiHashIntegrity(t, dir)
	res, err := Verify(VerifyOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed() {
		t.Errorf("clean multi-hash verify failed: %+v", res)
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

// TestVerifyStrict exercises the --strict re-derive path: the inner
// verifyStrictNPM that re-fetches each npm package's tarball and
// verifies each file against the lockfile-recorded integrity.
func TestVerifyStrict(t *testing.T) {
	dir, srvURL := setupSynced(t)
	res, err := Verify(VerifyOptions{Dir: dir, Strict: true, RegistryURL: srvURL})
	if err != nil {
		t.Fatalf("Verify --strict: %v", err)
	}
	if res.Failed() {
		t.Errorf("clean --strict verify failed: %+v", res)
	}
}

func TestVerifyStrictMultiHash(t *testing.T) {
	dir, srvURL := setupSynced(t)
	addMultiHashIntegrity(t, dir)
	res, err := Verify(VerifyOptions{Dir: dir, Strict: true, RegistryURL: srvURL})
	if err != nil {
		t.Fatalf("Verify --strict: %v", err)
	}
	if res.Failed() {
		t.Errorf("clean multi-hash --strict verify failed: %+v", res)
	}
}

func TestSyncNoFetchMultiHash(t *testing.T) {
	dir, _ := setupSynced(t)
	addMultiHashIntegrity(t, dir)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, NoFetch: true}); err != nil {
		t.Errorf("--no-fetch on clean multi-hash tree: %v", err)
	}
}

// TestVerifyStrict_TarballMismatch covers the case where the
// registry-side bytes drift from what the lockfile recorded. We swap
// in a fakeNPM that returns a different tarball than the one we
// originally synced from; --strict catches it.
func TestVerifyStrict_TarballMismatch(t *testing.T) {
	dir, _ := setupSynced(t)
	// Different files = different per-file SHA-384, but the lockfile
	// still has the original integrity. --strict re-derives from the
	// new tarball and sees the mismatch.
	srvNew := fakeNPM(t, "demo", "1.0.0", map[string]string{
		"dist/a.js":  "ALPHA-MODIFIED",
		"dist/b.css": "BETA-MODIFIED",
	})
	res, err := Verify(VerifyOptions{Dir: dir, Strict: true, RegistryURL: srvNew.URL})
	if err != nil {
		t.Fatalf("Verify --strict: %v", err)
	}
	if !res.Failed() {
		t.Error("--strict against a drifted tarball should fail")
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

func addMultiHashIntegrity(t *testing.T, dir string) {
	t.Helper()
	l, err := readLock(filepath.Join(dir, DefaultLock))
	if err != nil {
		t.Fatal(err)
	}
	for i, asset := range l.Assets {
		content, err := os.ReadFile(filepath.Join(dir, l.OutDir, asset.Out))
		if err != nil {
			t.Fatal(err)
		}
		digest256 := sha256.Sum256(content)
		digest512 := sha512.Sum512(content)
		l.Assets[i].Integrity = "sha256-" + base64.StdEncoding.EncodeToString(digest256[:]) + " " +
			asset.Integrity + " sha512-" + base64.StdEncoding.EncodeToString(digest512[:])
	}
	encoded, err := EncodeLock(l)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, DefaultLock), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
