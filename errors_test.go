package pin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestErrors_NoLockfile(t *testing.T) {
	dir := t.TempDir()
	_, err := Verify(VerifyOptions{Dir: dir})
	if !errors.Is(err, ErrNoLockfile) {
		t.Errorf("Verify with no lockfile: err=%v; want errors.Is(ErrNoLockfile)", err)
	}

	_, err = Outdated(context.Background(), OutdatedOptions{Dir: dir})
	if !errors.Is(err, ErrNoLockfile) {
		t.Errorf("Outdated with no lockfile: err=%v; want errors.Is(ErrNoLockfile)", err)
	}
}

func TestErrors_FrozenDrift(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["x.js"]
`)
	// No lockfile -> --frozen fails with ErrFrozenDrift (the lockfile-
	// missing case is wrapped under the same umbrella).
	_, err := Sync(context.Background(), SyncOptions{Dir: dir, Frozen: true})
	if !errors.Is(err, ErrFrozenDrift) {
		t.Errorf("Sync --frozen with no lockfile: err=%v; want errors.Is(ErrFrozenDrift)", err)
	}
}

func TestErrors_VerifyFailedViaNoFetch(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	// Tamper a vendored file.
	if err := os.WriteFile(filepath.Join(dir, "v/demo/x.js"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Sync(context.Background(), SyncOptions{Dir: dir, NoFetch: true})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Errorf("Sync --no-fetch on tampered tree: err=%v; want errors.Is(ErrVerifyFailed)", err)
	}
}

func TestErrors_PathEscape(t *testing.T) {
	_, err := safeOut("/tmp/x", "v", "../../etc/passwd")
	if !errors.Is(err, ErrPathEscape) {
		t.Errorf("safeOut on escape attempt: err=%v; want errors.Is(ErrPathEscape)", err)
	}
}

func TestErrors_ProvenanceMissing(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	_, err := Sync(context.Background(), SyncOptions{
		Dir: dir, RegistryURL: srv.URL, StrictProvenance: true,
	})
	if !errors.Is(err, ErrProvenanceMissing) {
		t.Errorf("Sync --strict-provenance on attestation-less version: err=%v; want errors.Is(ErrProvenanceMissing)", err)
	}
}
