package pin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crypto/sha512"
)

// benchSyncRegistry serves N synthetic npm packages on one httptest
// server so a Sync benchmark can fan out without per-package server
// overhead.
func benchSyncRegistry(b *testing.B, n int) (*httptest.Server, []string) {
	b.Helper()
	mux := http.NewServeMux()
	tarballs := map[string][]byte{}
	names := make([]string, n)
	var sharedURL string
	for i := range n {
		name := fmt.Sprintf("pkg-%04d", i)
		names[i] = name
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
	b.Cleanup(srv.Close)
	return srv, names
}

func benchSyncManifest(names []string) string {
	var sb strings.Builder
	sb.WriteString("out: \"v\"\nassets:\n")
	for _, n := range names {
		sb.WriteString("  - name: \"" + n + "\"\n    version: \"1.0.0\"\n    files: [\"index.js\"]\n")
	}
	return sb.String()
}

// BenchmarkSync measures the end-to-end Sync wall-clock against a
// local httptest server. Network is the limiting factor; this number
// reflects pin's in-process work plus loopback HTTP. Compare runs to
// confirm a refactor hasn't regressed the per-entry overhead. Sizes
// stay at or below 50 to keep the ephemeral-port pool from running
// out on macOS during long benchtime sweeps; bigger numbers ARE worth
// running ad-hoc on Linux.
func BenchmarkSync10(b *testing.B) { benchSync(b, 10) }
func BenchmarkSync50(b *testing.B) { benchSync(b, 50) }

func benchSync(b *testing.B, n int) {
	b.Helper()
	srv, names := benchSyncRegistry(b, n)
	manifest := benchSyncManifest(names)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		dir := b.TempDir()
		if err := os.WriteFile(filepath.Join(dir, DefaultManifest), []byte(manifest), 0o644); err != nil {
			b.Fatal(err)
		}
		if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerify is a hash-and-disk-IO benchmark. Compare runs to
// confirm Verify's per-file overhead stays flat as the rest of the
// codebase moves.
func BenchmarkVerify10(b *testing.B)  { benchVerify(b, 10) }
func BenchmarkVerify100(b *testing.B) { benchVerify(b, 100) }

func benchVerify(b *testing.B, n int) {
	b.Helper()
	srv, names := benchSyncRegistry(b, n)
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DefaultManifest), []byte(benchSyncManifest(names)), 0o644); err != nil {
		b.Fatal(err)
	}
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := Verify(VerifyOptions{Dir: dir}); err != nil {
			b.Fatal(err)
		}
	}
}
