package pin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/git-pkgs/pin/source/npm"
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
	_, err := safeOut("v", "../../etc/passwd")
	if !errors.Is(err, ErrPathEscape) {
		t.Errorf("safeOut on escape attempt: err=%v; want errors.Is(ErrPathEscape)", err)
	}
}

// TestErrors_UnsafeTarballEntry asserts pin's full Sync pipeline
// refuses a malicious tarball whose entries include a symlink, even
// though the registry-recorded integrity matches. Defence-in-depth
// on top of any check the underlying archives package may or may not
// do — pin owns the safety property and fails closed.
func TestErrors_UnsafeTarballEntry(t *testing.T) {
	// Build a tarball with one regular file (package.json) and one
	// symlink masquerading as the asset the manifest asks for.
	pj := []byte(`{"name":"demo","version":"1.0.0"}`)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "package/package.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(pj))})
	_, _ = tw.Write(pj)
	_ = tw.WriteHeader(&tar.Header{Name: "package/dist/x.js", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o644})
	_ = tw.Close()
	_ = gz.Close()
	tarball := buf.Bytes()

	h := sha512.Sum512(tarball)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/demo/1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "demo", "version": "1.0.0",
			"dist": map[string]any{"tarball": srvURL + "/tarball.tgz", "integrity": integrity},
		})
	})
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball)
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	defer srv.Close()

	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	_, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL})
	if !errors.Is(err, npm.ErrUnsafeTarballEntry) {
		t.Errorf("Sync against symlink-bearing tarball: err=%v; want errors.Is(npm.ErrUnsafeTarballEntry)", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "v/demo/x.js")); !os.IsNotExist(statErr) {
		t.Errorf("no bytes should have hit disk; stat=%v", statErr)
	}
}

// TestErrors_PathCollision asserts pin fails closed when two
// resolved files share an Out. The cheapest trigger is layout: flat
// with a single entry whose files list contains two paths sharing a
// basename — both collapse to "<slug>-<version>-<base>".
func TestErrors_PathCollision(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{
		"dist/x.js": "a",
		"src/x.js":  "b",
	})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
layout: flat
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js", "src/x.js"]
`)
	_, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL})
	if !errors.Is(err, ErrPathCollision) {
		t.Errorf("Sync with colliding basenames: err=%v; want errors.Is(ErrPathCollision)", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "v")); !os.IsNotExist(statErr) {
		t.Errorf("no bytes should have hit disk; stat=%v", statErr)
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
