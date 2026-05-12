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

	info1, _ := os.Stat(filepath.Join(dir, DefaultLock))
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	info2, _ := os.Stat(filepath.Join(dir, DefaultLock))
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Error("third sync touched lockfile mtime despite identical bytes")
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

func TestSyncPrunesEmptyDirs(t *testing.T) {
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
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	if err := os.RemoveAll(filepath.Join(dir, "v/demo")); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(dir, "v/gone/nested"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "pin.lock"), mustEncodeLock(t, &lock.Lock{
		OutDir: "v",
		Assets: []lock.Asset{{Name: "gone", Version: "1.0.0", PURL: "pkg:npm/gone@1.0.0", Path: "nested/y.js", Out: "gone/nested/y.js"}},
	}), 0o644)

	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "v/gone")); !os.IsNotExist(err) {
		t.Error("empty 'gone' directory should have been pruned")
	}
}

func mustEncodeLock(t *testing.T, l *lock.Lock) []byte {
	t.Helper()
	b, err := EncodeLock(l)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSyncConcurrencyDeterministic asserts the lockfile bytes are
// independent of the resolve completion order: the same manifest with
// --concurrency=1 and --concurrency=8 produces the same lockfile.
// Combined with `go test -race`, this also catches data races in the
// per-entry resolve path.
func TestSyncConcurrencyDeterministic(t *testing.T) {
	pkgs := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"}

	mux := http.NewServeMux()
	tarballs := map[string][]byte{}
	sharedURL := ""
	for _, name := range pkgs {
		pj, _ := json.Marshal(map[string]any{"name": name, "version": "1.0.0", "main": "index.js"})
		tb := makeTarball(map[string]string{
			"package.json": string(pj),
			"index.js":     "module.exports='" + name + "'",
		})
		tarballs["/"+name+"/-/"+name+"-1.0.0.tgz"] = tb
		h := sha512.Sum512(tb)
		integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])
		n := name
		mux.HandleFunc("/"+n+"/1.0.0", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":    n,
				"version": "1.0.0",
				"dist":    map[string]any{"tarball": sharedURL + "/" + n + "/-/" + n + "-1.0.0.tgz", "integrity": integrity},
			})
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if tb, ok := tarballs[r.URL.Path]; ok {
			_, _ = w.Write(tb)
			return
		}
		http.NotFound(w, r)
	})
	sharedSrv := httptest.NewServer(mux)
	sharedURL = sharedSrv.URL
	t.Cleanup(sharedSrv.Close)

	build := func(concurrency int) []byte {
		dir := t.TempDir()
		var mf strings.Builder
		mf.WriteString("out: \"v\"\nassets:\n")
		for _, name := range pkgs {
			mf.WriteString("  - name: \"" + name + "\"\n    version: \"1.0.0\"\n    files: [\"index.js\"]\n")
		}
		writeManifest(t, dir, mf.String())
		if _, err := Sync(context.Background(), SyncOptions{
			Dir:         dir,
			RegistryURL: sharedURL,
			Concurrency: concurrency,
		}); err != nil {
			t.Fatalf("Sync concurrency=%d: %v", concurrency, err)
		}
		b, err := os.ReadFile(filepath.Join(dir, DefaultLock))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	serial := build(1)
	parallel := build(8)
	if !bytes.Equal(serial, parallel) {
		t.Error("lockfile differs between --concurrency=1 and --concurrency=8 — resolves must be order-independent")
	}

	l, err := lock.Read(bytes.NewReader(parallel))
	if err != nil {
		t.Fatalf("lock.Read: %v", err)
	}
	if len(l.Assets) != len(pkgs) {
		t.Errorf("got %d assets, want %d", len(l.Assets), len(pkgs))
	}
}

func TestSyncNoFetch(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	// First seed the vendored files + lockfile with a normal sync.
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	srv.Close() // ensure --no-fetch cannot reach the registry

	// Happy path: identical disk, identical lockfile, identical manifest.
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, NoFetch: true}); err != nil {
		t.Errorf("--no-fetch on clean tree: %v", err)
	}

	// Tampered: an attacker edits a vendored file post-checkout. --no-fetch
	// re-hashes and surfaces the drift.
	if err := os.WriteFile(filepath.Join(dir, "v/demo/x.js"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, NoFetch: true}); err == nil {
		t.Error("--no-fetch should fail when a vendored file was tampered with")
	}
}

func TestSyncNoFetchManifestDrift(t *testing.T) {
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
	srv.Close()

	// Manifest now references a version the lockfile doesn't have. --no-fetch
	// must bail via the frozen check before any verification.
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "2.0.0"
    files: ["dist/x.js"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, NoFetch: true}); err == nil {
		t.Error("--no-fetch should fail when manifest drifts ahead of the lockfile")
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
