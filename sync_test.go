package pin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/pin/lock"
)

func makeTarball(files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for p, c := range files {
		_ = tw.WriteHeader(&tar.Header{Name: "package/" + p, Mode: 0o644, Size: int64(len(c))})
		_, _ = tw.Write([]byte(c))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func fakeNPM(t *testing.T, name, version string, pkgFiles map[string]string) *httptest.Server {
	t.Helper()
	pj, _ := json.Marshal(map[string]any{"name": name, "version": version, "main": "index.js"})
	all := map[string]string{"package.json": string(pj)}
	maps.Copy(all, pkgFiles)
	tb := makeTarball(all)
	h := sha512.Sum512(tb)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/"+name+"/"+version, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":    name,
			"version": version,
			"license": "MIT",
			"dist":    map[string]any{"tarball": srvURL + "/tarball.tgz", "integrity": integrity},
		})
	})
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tb)
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func writeManifest(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, DefaultManifest), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSyncEndToEnd(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.2.3", map[string]string{
		"dist/demo.min.js":  "console.log('demo')",
		"dist/demo.min.css": "body{}",
	})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "static/vendor"
assets:
  - name: "demo"
    version: "1.2.3"
    files: ["dist/demo.min.js", "dist/demo.min.css"]
`)

	res, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if len(res.Lock.Assets) != 2 {
		t.Fatalf("lock assets = %d, want 2", len(res.Lock.Assets))
	}
	if len(res.Changes.Added) != 2 {
		t.Errorf("Added = %d, want 2", len(res.Changes.Added))
	}

	for _, p := range []string{"static/vendor/demo/demo.min.js", "static/vendor/demo/demo.min.css"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("expected file %s on disk: %v", p, err)
		}
	}

	lockBytes, err := os.ReadFile(filepath.Join(dir, DefaultLock))
	if err != nil {
		t.Fatalf("read pin.lock: %v", err)
	}
	if !strings.Contains(string(lockBytes), `"bomFormat": "CycloneDX"`) {
		t.Error("pin.lock should be CycloneDX")
	}
	if _, err := lock.Read(bytes.NewReader(lockBytes)); err != nil {
		t.Errorf("pin.lock not parseable: %v", err)
	}
}

func TestSyncIdempotent(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)

	first, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	lock1, _ := os.ReadFile(filepath.Join(dir, DefaultLock))

	second, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	lock2, _ := os.ReadFile(filepath.Join(dir, DefaultLock))

	if !bytes.Equal(lock1, lock2) {
		t.Error("second sync produced different lockfile bytes")
	}
	if len(first.Changes.Added) != 1 || len(second.Changes.Added) != 0 {
		t.Errorf("first.Added = %d, second.Added = %d", len(first.Changes.Added), len(second.Changes.Added))
	}
	if len(second.Changes.Unchanged) != 1 {
		t.Errorf("second.Unchanged = %d, want 1", len(second.Changes.Unchanged))
	}
}

func TestSyncFrozen(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)

	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL, Frozen: true}); err == nil {
		t.Fatal("frozen sync with no lockfile should fail")
	}

	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}

	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL, Frozen: true}); err != nil {
		t.Errorf("frozen sync after clean sync should succeed: %v", err)
	}
}

func TestSyncOrphanRemoval(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"dist/a.js": "a", "dist/b.js": "b"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/a.js", "dist/b.js"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}

	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/a.js"]
`)
	res, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "demo/b.js" {
		t.Errorf("Removed = %v, want [demo/b.js]", res.Removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "v/demo/b.js")); !os.IsNotExist(err) {
		t.Error("orphan b.js should have been removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "v/demo/a.js")); err != nil {
		t.Error("a.js should still exist")
	}
}

func TestSyncDryRun(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	res, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lock.Assets) != 1 {
		t.Error("dry-run should still produce a lock model")
	}
	if _, err := os.Stat(filepath.Join(dir, DefaultLock)); !os.IsNotExist(err) {
		t.Error("dry-run should not write pin.lock")
	}
	if _, err := os.Stat(filepath.Join(dir, "v/demo/x.js")); !os.IsNotExist(err) {
		t.Error("dry-run should not write asset files")
	}
}
