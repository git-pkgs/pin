package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakePackage struct {
	name    string
	version string
	license string
	repo    string
	pkgJSON map[string]any
	files   map[string]string
}

func (p *fakePackage) tarball() []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	pj, _ := json.Marshal(p.pkgJSON)
	all := map[string][]byte{"package.json": pj}
	for k, v := range p.files {
		all[k] = []byte(v)
	}
	for path, content := range all {
		hdr := &tar.Header{
			Name: "package/" + path,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		_ = tw.WriteHeader(hdr)
		_, _ = tw.Write(content)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func newFakeRegistry(t *testing.T, pkgs ...*fakePackage) *httptest.Server {
	t.Helper()
	tarballs := map[string][]byte{}
	mux := http.NewServeMux()

	for _, p := range pkgs {
		tb := p.tarball()
		tbPath := fmt.Sprintf("/%s/-/%s-%s.tgz", p.name, p.name, p.version)
		tarballs[tbPath] = tb
	}

	var srvURL string
	for _, p := range pkgs {
		tbPath := fmt.Sprintf("/%s/-/%s-%s.tgz", p.name, p.name, p.version)
		mux.HandleFunc("/"+p.name+"/"+p.version, func(w http.ResponseWriter, r *http.Request) {
			h := sha512.Sum512(tarballs[tbPath])
			integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])
			resp := map[string]any{
				"name":    p.name,
				"version": p.version,
				"license": p.license,
				"dist": map[string]any{
					"tarball":   srvURL + tbPath,
					"integrity": integrity,
				},
			}
			if p.repo != "" {
				resp["repository"] = map[string]any{"url": p.repo}
			}
			_ = json.NewEncoder(w).Encode(resp)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if tb, ok := tarballs[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(tb)
			return
		}
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func TestResolve(t *testing.T) {
	pkg := &fakePackage{
		name:    "demo",
		version: "1.2.3",
		license: "MIT",
		repo:    "git+https://github.com/example/demo.git",
		pkgJSON: map[string]any{
			"name":    "demo",
			"version": "1.2.3",
			"main":    "dist/demo.min.js",
		},
		files: map[string]string{
			"dist/demo.min.js":  "console.log('demo')",
			"dist/demo.min.css": "body{color:red}",
		},
	}
	srv := newFakeRegistry(t, pkg)

	src := New(Options{RegistryURL: srv.URL})
	got, err := src.Resolve(context.Background(), "demo", "1.2.3", []string{"dist/demo.min.js", "dist/demo.min.css"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if got.Name != "demo" || got.Version != "1.2.3" {
		t.Errorf("name/version = %s@%s", got.Name, got.Version)
	}
	if got.PURL != "pkg:npm/demo@1.2.3" {
		t.Errorf("PURL = %q", got.PURL)
	}
	if got.License != "MIT" {
		t.Errorf("License = %q", got.License)
	}
	if got.SourceRepository != "https://github.com/example/demo" {
		t.Errorf("SourceRepository = %q", got.SourceRepository)
	}
	if !strings.HasPrefix(got.PackageIntegrity, "sha512-") {
		t.Errorf("PackageIntegrity = %q, want sha512-...", got.PackageIntegrity)
	}
	if len(got.Files) != 2 {
		t.Fatalf("Files = %d, want 2", len(got.Files))
	}
	for _, f := range got.Files {
		if !strings.HasPrefix(f.Integrity, "sha384-") {
			t.Errorf("file %s integrity = %q, want sha384-...", f.Path, f.Integrity)
		}
		if f.Size == 0 {
			t.Errorf("file %s size is zero", f.Path)
		}
		if len(f.Content) == 0 {
			t.Errorf("file %s content is empty", f.Path)
		}
	}
}

func TestResolveDefaultEntryPoint(t *testing.T) {
	pkg := &fakePackage{
		name:    "demo",
		version: "1.0.0",
		pkgJSON: map[string]any{
			"name":     "demo",
			"version":  "1.0.0",
			"jsdelivr": "dist/cdn.js",
			"main":     "index.js",
		},
		files: map[string]string{
			"dist/cdn.js": "/* cdn build */",
			"index.js":    "module.exports = 1",
		},
	}
	srv := newFakeRegistry(t, pkg)
	src := New(Options{RegistryURL: srv.URL})

	got, err := src.Resolve(context.Background(), "demo", "1.0.0", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Files) != 1 || got.Files[0].Path != "dist/cdn.js" {
		t.Errorf("default entry-point: got %+v, want dist/cdn.js", got.Files)
	}
}

func TestResolveMissingFile(t *testing.T) {
	pkg := &fakePackage{
		name:    "demo",
		version: "1.0.0",
		pkgJSON: map[string]any{"name": "demo", "version": "1.0.0", "main": "index.js"},
		files:   map[string]string{"index.js": "x"},
	}
	srv := newFakeRegistry(t, pkg)
	src := New(Options{RegistryURL: srv.URL})

	_, err := src.Resolve(context.Background(), "demo", "1.0.0", []string{"does/not/exist.js"})
	if err == nil || !strings.Contains(err.Error(), "does/not/exist.js") {
		t.Fatalf("expected error mentioning missing file, got %v", err)
	}
}

func TestResolveIntegrityMismatch(t *testing.T) {
	pkg := &fakePackage{
		name:    "demo",
		version: "1.0.0",
		pkgJSON: map[string]any{"name": "demo", "version": "1.0.0", "main": "index.js"},
		files:   map[string]string{"index.js": "x"},
	}
	srv := newFakeRegistry(t, pkg)
	src := New(Options{
		RegistryURL: srv.URL,
		overrideIntegrity: func(string) string {
			return "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
		},
	})

	_, err := src.Resolve(context.Background(), "demo", "1.0.0", nil)
	if err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("expected integrity mismatch error, got %v", err)
	}
}

func TestResolveTarballSizeCap(t *testing.T) {
	pkg := &fakePackage{
		name:    "demo",
		version: "1.0.0",
		pkgJSON: map[string]any{"name": "demo", "version": "1.0.0", "main": "index.js"},
		files:   map[string]string{"index.js": strings.Repeat("x", 1000)},
	}
	srv := newFakeRegistry(t, pkg)
	src := New(Options{RegistryURL: srv.URL, MaxTarballBytes: 100})

	_, err := src.Resolve(context.Background(), "demo", "1.0.0", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size cap error, got %v", err)
	}
}

func TestScopedPackagePURL(t *testing.T) {
	pkg := &fakePackage{
		name:    "@scope/pkg",
		version: "1.0.0",
		pkgJSON: map[string]any{"name": "@scope/pkg", "version": "1.0.0", "main": "index.js"},
		files:   map[string]string{"index.js": "x"},
	}
	srv := newFakeRegistry(t, pkg)
	src := New(Options{RegistryURL: srv.URL})

	got, err := src.Resolve(context.Background(), "@scope/pkg", "1.0.0", []string{"index.js"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.PURL != "pkg:npm/%40scope/pkg@1.0.0" {
		t.Errorf("PURL = %q, want pkg:npm/%%40scope/pkg@1.0.0", got.PURL)
	}
}
