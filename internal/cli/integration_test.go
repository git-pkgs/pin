package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

	"github.com/git-pkgs/registries/safehttp"
)

func TestMain(m *testing.M) {
	safehttp.EnableLoopbackForTesting()
	os.Exit(m.Run())
}

// fakeRegistry serves one npm package on an httptest.Server. Adapted
// from pin/sync_test.go's fakeNPM helper — duplicated to keep the cli
// package's tests self-contained.
func fakeRegistry(t *testing.T, name, version string, pkgFiles map[string]string) *httptest.Server {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	pj, _ := json.Marshal(map[string]any{"name": name, "version": version, "main": "index.js"})
	all := map[string]string{"package.json": string(pj)}
	maps.Copy(all, pkgFiles)
	for p, c := range all {
		_ = tw.WriteHeader(&tar.Header{Name: "package/" + p, Mode: 0o644, Size: int64(len(c))})
		_, _ = tw.Write([]byte(c))
	}
	_ = tw.Close()
	_ = gz.Close()
	tb := buf.Bytes()
	h := sha512.Sum512(tb)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	mux := http.NewServeMux()
	var srvURL string
	versionDoc := func() map[string]any {
		return map[string]any{
			"name":    name,
			"version": version,
			"dist":    map[string]any{"tarball": srvURL + "/tarball.tgz", "integrity": integrity},
		}
	}
	mux.HandleFunc("/"+name+"/"+version, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(versionDoc())
	})
	// Packument shape that npm.Source.Status reads (for outdated).
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      name,
			"dist-tags": map[string]string{"latest": version},
			"versions":  map[string]any{version: versionDoc()},
			"time":      map[string]string{version: "2026-01-01T00:00:00.000Z"},
		})
	})
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tb)
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func writeManifest(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "pin.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runCmd invokes the pin CLI with the given args against a buffer for
// stdout/stderr. Returns the captured stdout and the Execute error.
// The cobra command tree is rebuilt per call so each test is isolated.
func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := Root()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), err
}

func TestCLI_Sync(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	out, err := runCmd(t, "sync", "-C", dir, "--registry", srv.URL)
	if err != nil {
		t.Fatalf("sync: %v\nout: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "pin.lock")); err != nil {
		t.Errorf("pin.lock not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "v/demo/x.js")); err != nil {
		t.Errorf("vendored file not written: %v", err)
	}
}

func TestCLI_SyncDryRunJSON(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	out, err := runCmd(t, "sync", "-C", dir, "--registry", srv.URL, "--dry-run", "--json")
	if err != nil {
		t.Fatalf("sync --dry-run --json: %v", err)
	}
	if !strings.Contains(out, "CycloneDX") {
		t.Errorf("dry-run --json should emit CycloneDX; got: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "pin.lock")); !os.IsNotExist(err) {
		t.Error("dry-run should not write pin.lock")
	}
}

func TestCLI_Verify(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	if _, err := runCmd(t, "sync", "-C", dir, "--registry", srv.URL); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, err := runCmd(t, "verify", "-C", dir); err != nil {
		t.Errorf("verify on clean tree: %v", err)
	}

	// Tamper a vendored file → verify must exit non-zero.
	if err := os.WriteFile(filepath.Join(dir, "v/demo/x.js"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runCmd(t, "verify", "-C", dir); err == nil {
		t.Error("verify on tampered tree should fail")
	}
}

func TestCLI_List(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	if _, err := runCmd(t, "sync", "-C", dir, "--registry", srv.URL); err != nil {
		t.Fatalf("sync: %v", err)
	}
	out, err := runCmd(t, "list", "-C", dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "demo") {
		t.Errorf("list should mention demo, got: %s", out)
	}

	jsonOut, err := runCmd(t, "list", "-C", dir, "--json")
	if err != nil {
		t.Fatalf("list --json: %v", err)
	}
	if !strings.Contains(jsonOut, `"name"`) {
		t.Errorf("list --json should be JSON, got: %s", jsonOut)
	}
}

func TestCLI_Path(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	if _, err := runCmd(t, "sync", "-C", dir, "--registry", srv.URL); err != nil {
		t.Fatalf("sync: %v", err)
	}
	out, err := runCmd(t, "path", "-C", dir, "demo")
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	if !strings.Contains(out, "x.js") {
		t.Errorf("path output missing x.js: %s", out)
	}

	if _, err := runCmd(t, "path", "-C", dir, "nope"); err == nil {
		t.Error("path for unknown package should fail")
	}
}

func TestCLI_Init(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCmd(t, "init", "-C", dir); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pin.yaml")); err != nil {
		t.Errorf("init did not write pin.yaml: %v", err)
	}
	// Second init must fail.
	if _, err := runCmd(t, "init", "-C", dir); err == nil {
		t.Error("init on existing manifest should fail")
	}
}

func TestCLI_Add(t *testing.T) {
	srv := fakeRegistry(t, "newpkg", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, "out: v\nassets: []\n")
	if _, err := runCmd(t, "add", "-C", dir, "--registry", srv.URL, "newpkg@1.0.0", "dist/x.js"); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "pin.yaml"))
	if !strings.Contains(string(got), "newpkg") {
		t.Errorf("manifest does not contain newpkg after add:\n%s", got)
	}
}

func TestCLI_Rm(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	if _, err := runCmd(t, "sync", "-C", dir, "--registry", srv.URL); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, err := runCmd(t, "rm", "-C", dir, "demo"); err != nil {
		t.Fatalf("rm: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "pin.yaml"))
	if strings.Contains(string(got), `name: "demo"`) {
		t.Errorf("manifest still contains demo after rm:\n%s", got)
	}
}

func TestCLI_Outdated(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	if _, err := runCmd(t, "sync", "-C", dir, "--registry", srv.URL); err != nil {
		t.Fatalf("sync: %v", err)
	}
	out, err := runCmd(t, "outdated", "-C", dir, "--registry", srv.URL, "--exit-zero")
	if err != nil {
		t.Fatalf("outdated: %v\nout: %s", err, out)
	}
}

func TestCLI_SBOM(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	if _, err := runCmd(t, "sync", "-C", dir, "--registry", srv.URL); err != nil {
		t.Fatalf("sync: %v", err)
	}
	out, err := runCmd(t, "sbom", "-C", dir)
	if err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if !strings.Contains(out, "CycloneDX") {
		t.Errorf("sbom output is not CycloneDX: %s", out)
	}
}

func TestCLI_Update(t *testing.T) {
	srv := fakeRegistry(t, "demo", "1.0.0", map[string]string{"dist/x.js": "x"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/x.js"]
`)
	if _, err := runCmd(t, "sync", "-C", dir, "--registry", srv.URL); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, err := runCmd(t, "update", "-C", dir, "--registry", srv.URL); err != nil {
		t.Errorf("update: %v", err)
	}
}

func TestDetectCI(t *testing.T) {
	for _, env := range ciEnvVars {
		t.Setenv(env, "")
	}
	if got := detectCI(); got != "" {
		t.Errorf("with all CI env vars cleared, detectCI = %q; want empty", got)
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	if got := detectCI(); got != "GITHUB_ACTIONS" {
		t.Errorf("with GITHUB_ACTIONS set, detectCI = %q; want GITHUB_ACTIONS", got)
	}
}

func TestExitError(t *testing.T) {
	e := &exitError{code: 42, msg: "boom"}
	if e.Error() != "boom" {
		t.Errorf("Error() = %q", e.Error())
	}
	if e.ExitCode() != 42 {
		t.Errorf("ExitCode() = %d", e.ExitCode())
	}
}
