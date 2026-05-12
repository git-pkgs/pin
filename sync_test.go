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
	"github.com/git-pkgs/pin/source/forge"
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

// fakeGitHub mirrors source/forge's test helper: stub /repos commits
// lookup + jsdelivr-style /gh/{owner}/{repo}@{sha}/ file fetches. The
// pin root sync test needs both endpoints on the same httptest server
// so we can wire them through SyncOptions.Forge in one go.
func fakeGitHub(t *testing.T, owner, repo, tag, sha string, files map[string]string) (api, cdn string) {
	t.Helper()
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/repos/"+owner+"/"+repo+"/commits/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"sha": sha})
	})
	apiSrv := httptest.NewServer(apiMux)
	t.Cleanup(apiSrv.Close)

	cdnMux := http.NewServeMux()
	for path, content := range files {
		p := "/gh/" + owner + "/" + repo + "@" + sha + "/" + path
		body := content
		cdnMux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		})
	}
	cdnSrv := httptest.NewServer(cdnMux)
	t.Cleanup(cdnSrv.Close)

	return apiSrv.URL, cdnSrv.URL
}

func TestSyncForgeEntry(t *testing.T) {
	api, cdn := fakeGitHub(t, "highlightjs", "cdn-release", "11.11.1",
		"abc123def4567890abc123def4567890abc12345",
		map[string]string{
			"build/highlight.min.js": "var hljs={}",
		})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "highlight.js"
    source: "github:highlightjs/cdn-release"
    version: "11.11.1"
    files: ["build/highlight.min.js"]
`)
	res, err := Sync(context.Background(), SyncOptions{
		Dir: dir,
		Forge: forge.Options{
			GitHubAPI:   api,
			JSDelivrCDN: cdn,
		},
	})
	if err != nil {
		t.Fatalf("forge Sync: %v", err)
	}
	if len(res.Lock.Assets) != 1 {
		t.Fatalf("Lock.Assets = %d, want 1", len(res.Lock.Assets))
	}
	a := res.Lock.Assets[0]
	if !strings.HasPrefix(a.PURL, "pkg:github/highlightjs/cdn-release@11.11.1") {
		t.Errorf("PURL = %q, want pkg:github/... prefix", a.PURL)
	}
	if a.PackageIntegrity != "abc123def4567890abc123def4567890abc12345" {
		t.Errorf("PackageIntegrity = %q, want the SHA", a.PackageIntegrity)
	}
	got, err := os.ReadFile(filepath.Join(dir, "v/highlightjs__cdn-release/highlight.min.js"))
	if err != nil {
		t.Fatalf("vendored file missing: %v", err)
	}
	if string(got) != "var hljs={}" {
		t.Errorf("file bytes = %q", got)
	}
}

// TestParallelAdds_MergeFriendly simulates two branches each running
// `pin add` on a different package. If branch A adds foo and branch B
// adds bar, the resulting lockfiles must converge to byte-identical
// output regardless of which branch's add ran first. That's what makes
// pin.lock survive `git merge` without conflict: assets sort by name,
// so two non-overlapping additions land at disjoint positions in the
// file.
func TestParallelAdds_MergeFriendly(t *testing.T) {
	mux := http.NewServeMux()
	tarballs := map[string][]byte{}
	sharedURL := ""
	for _, name := range []string{"foo", "bar", "common"} {
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
	srv := httptest.NewServer(mux)
	sharedURL = srv.URL
	t.Cleanup(srv.Close)

	// Set up a base manifest+lockfile with one common asset, then on
	// two divergent branches add foo and bar respectively.
	makeBase := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		writeManifest(t, dir, `out: "v"
assets:
  - name: "common"
    version: "1.0.0"
    files: ["index.js"]
`)
		if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	// Branch A: add foo to the base.
	dirA := makeBase(t)
	if _, err := Add(context.Background(), "foo@1.0.0", []string{"index.js"},
		AddOptions{Dir: dirA, RegistryURL: srv.URL}); err != nil {
		t.Fatalf("branch A add: %v", err)
	}

	// Branch B: add bar to the base.
	dirB := makeBase(t)
	if _, err := Add(context.Background(), "bar@1.0.0", []string{"index.js"},
		AddOptions{Dir: dirB, RegistryURL: srv.URL}); err != nil {
		t.Fatalf("branch B add: %v", err)
	}

	// Merge: a third tree with both foo and bar added (either order).
	mergeOrder1 := makeBase(t)
	for _, name := range []string{"foo", "bar"} {
		if _, err := Add(context.Background(), name+"@1.0.0", []string{"index.js"},
			AddOptions{Dir: mergeOrder1, RegistryURL: srv.URL}); err != nil {
			t.Fatalf("merge order 1 add %s: %v", name, err)
		}
	}
	mergeOrder2 := makeBase(t)
	for _, name := range []string{"bar", "foo"} {
		if _, err := Add(context.Background(), name+"@1.0.0", []string{"index.js"},
			AddOptions{Dir: mergeOrder2, RegistryURL: srv.URL}); err != nil {
			t.Fatalf("merge order 2 add %s: %v", name, err)
		}
	}

	// Order independence: adds in either order produce identical bytes.
	lock1, _ := os.ReadFile(filepath.Join(mergeOrder1, DefaultLock))
	lock2, _ := os.ReadFile(filepath.Join(mergeOrder2, DefaultLock))
	if !bytes.Equal(lock1, lock2) {
		t.Error("lockfile bytes differ between add-order foo→bar and bar→foo")
	}
	mf1, _ := os.ReadFile(filepath.Join(mergeOrder1, DefaultManifest))
	mf2, _ := os.ReadFile(filepath.Join(mergeOrder2, DefaultManifest))
	if !bytes.Equal(mf1, mf2) {
		t.Error("manifest bytes differ between add-order foo→bar and bar→foo")
	}

	// Disjoint-diff property: branch A's lockfile and branch B's
	// lockfile each differ from the base only by additions. Lines
	// belonging to the common asset must appear unchanged in both.
	base, _ := os.ReadFile(filepath.Join(mergeOrder1, DefaultLock))
	lockA, _ := os.ReadFile(filepath.Join(dirA, DefaultLock))
	lockB, _ := os.ReadFile(filepath.Join(dirB, DefaultLock))
	for ln := range strings.SplitSeq(string(base), "\n") {
		if !strings.Contains(ln, "common") {
			continue
		}
		if !strings.Contains(string(lockA), ln) {
			t.Errorf("base line %q changed on branch A — common-asset lines should be stable", strings.TrimSpace(ln))
		}
		if !strings.Contains(string(lockB), ln) {
			t.Errorf("base line %q changed on branch B — common-asset lines should be stable", strings.TrimSpace(ln))
		}
	}
}

// TestUpdate_FloatingRangeBumps asserts that `pin update` re-resolves
// a floating range to the highest currently-satisfying version even
// when the lockfile already has a (lower) satisfying version pinned.
// `pin sync` without UpdateAll is lock-is-sticky and leaves the older
// version in place.
func TestUpdate_FloatingRangeBumps(t *testing.T) {
	srv := twoVersionRegistry(t, "demo")
	dir := t.TempDir()

	// Start with an exact pin so the first sync locks at 1.0.0.
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["index.js"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, DefaultLock)
	got, _ := os.ReadFile(lockPath)
	if !strings.Contains(string(got), `pkg:npm/demo@1.0.0"`) {
		t.Fatalf("first sync should lock at 1.0.0; lockfile:\n%s", got)
	}

	// Widen to a floating range. Plain Sync is sticky and keeps 1.0.0.
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "^1.0"
    files: ["index.js"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(lockPath)
	if !strings.Contains(string(got), `pkg:npm/demo@1.0.0"`) {
		t.Errorf("plain Sync should keep 1.0.0 (lock-is-sticky); got:\n%s", got)
	}

	// UpdateAll bumps to the latest satisfying version.
	if _, err := Sync(context.Background(), SyncOptions{
		Dir: dir, RegistryURL: srv.URL, UpdateAll: true,
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(lockPath)
	if !strings.Contains(string(got), `pkg:npm/demo@1.5.0"`) {
		t.Errorf("UpdateAll should bump to 1.5.0; lockfile:\n%s", got)
	}
}

// twoVersionRegistry serves npm packument + version docs for {name}
// at versions 1.0.0 and 1.5.0, with 1.5.0 as `latest`.
func twoVersionRegistry(t *testing.T, name string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	tarballs := map[string][]byte{}
	var sharedURL string
	for _, v := range []string{"1.0.0", "1.5.0"} {
		pj, _ := json.Marshal(map[string]any{"name": name, "version": v, "main": "index.js"})
		tb := makeTarball(map[string]string{
			"package.json": string(pj),
			"index.js":     "module.exports='" + name + "@" + v + "'",
		})
		tarballs["/"+name+"/-/"+name+"-"+v+".tgz"] = tb
		h := sha512.Sum512(tb)
		integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])
		ver := v
		mux.HandleFunc("/"+name+"/"+ver, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":    name,
				"version": ver,
				"dist":    map[string]any{"tarball": sharedURL + "/" + name + "/-/" + name + "-" + ver + ".tgz", "integrity": integrity},
			})
		})
	}
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      name,
			"dist-tags": map[string]string{"latest": "1.5.0"},
			"versions": map[string]any{
				"1.0.0": map[string]any{"name": name, "version": "1.0.0"},
				"1.5.0": map[string]any{"name": name, "version": "1.5.0"},
			},
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if tb, ok := tarballs[r.URL.Path]; ok {
			_, _ = w.Write(tb)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	sharedURL = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

// TestUpdate_ExactPinIsNoOp asserts `pin update` against a manifest
// with an exact-version pin is a no-op: the locked version stays at
// the named version regardless of what's in the registry.
func TestUpdate_ExactPinIsNoOp(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"index.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["index.js"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(dir, DefaultLock))

	if _, err := Sync(context.Background(), SyncOptions{
		Dir: dir, RegistryURL: srv.URL, UpdateAll: true,
	}); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(dir, DefaultLock))

	if !bytes.Equal(first, second) {
		t.Error("Update with an exact pin should be a no-op; lockfile changed")
	}
}

// TestUpdate_NamedEntry exercises the Update slice path: only the
// named entries re-resolve, others stay sticky.
func TestUpdate_NamedEntry(t *testing.T) {
	mux := http.NewServeMux()
	tarballs := map[string][]byte{}
	var sharedURL string
	for _, name := range []string{"alpha", "beta"} {
		for _, v := range []string{"1.0.0", "1.5.0"} {
			pj, _ := json.Marshal(map[string]any{"name": name, "version": v, "main": "index.js"})
			tb := makeTarball(map[string]string{
				"package.json": string(pj),
				"index.js":     "module.exports='" + name + "@" + v + "'",
			})
			tarballs["/"+name+"/-/"+name+"-"+v+".tgz"] = tb
			h := sha512.Sum512(tb)
			integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])
			n, ver := name, v
			mux.HandleFunc("/"+n+"/"+ver, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"name":    n,
					"version": ver,
					"dist":    map[string]any{"tarball": sharedURL + "/" + n + "/-/" + n + "-" + ver + ".tgz", "integrity": integrity},
				})
			})
		}
		n := name
		mux.HandleFunc("/"+n, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":      n,
				"dist-tags": map[string]string{"latest": "1.5.0"},
				"versions": map[string]any{
					"1.0.0": map[string]any{"name": n, "version": "1.0.0"},
					"1.5.0": map[string]any{"name": n, "version": "1.5.0"},
				},
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
	srv := httptest.NewServer(mux)
	sharedURL = srv.URL
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	// Start with both at exact 1.0.0 to seed the lockfile.
	writeManifest(t, dir, `out: "v"
assets:
  - name: "alpha"
    version: "1.0.0"
    files: ["index.js"]
  - name: "beta"
    version: "1.0.0"
    files: ["index.js"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	// Widen both to floating ranges. Sync stays sticky on both.
	writeManifest(t, dir, `out: "v"
assets:
  - name: "alpha"
    version: "^1.0"
    files: ["index.js"]
  - name: "beta"
    version: "^1.0"
    files: ["index.js"]
`)

	// Update only "alpha"; beta stays at 1.0.0.
	if _, err := Sync(context.Background(), SyncOptions{
		Dir: dir, RegistryURL: srv.URL, Update: []string{"alpha"},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, DefaultLock))
	if !strings.Contains(string(got), `pkg:npm/alpha@1.5.0"`) {
		t.Errorf("alpha should be bumped to 1.5.0; got:\n%s", got)
	}
	if !strings.Contains(string(got), `pkg:npm/beta@1.0.0"`) {
		t.Errorf("beta should stay at 1.0.0 (not named in Update); got:\n%s", got)
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
