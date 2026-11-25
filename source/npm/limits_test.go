package npm

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/git-pkgs/registries/client"
)

// The registries client caps buffered bodies at 10 MiB by default.
// Packuments and tarballs can be bigger, so the npm source reads both
// through the streaming calls. The small-limit clients below stand in
// for that cap without serving 10 MiB per test.

func smallBufferClient() *client.Client {
	return client.NewClient(client.WithMaxResponseSize(1024))
}

func manyVersions(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("1.0.%d", i)
	}
	return out
}

func TestPackageDocLargerThanBufferLimit(t *testing.T) {
	srv := fakePackageDoc(t, "big", map[string]string{"latest": "1.0.299"}, manyVersions(300))
	src := New(Options{RegistryURL: srv.URL, HTTPClient: smallBufferClient()})
	ctx := context.Background()

	got, err := src.ResolveVersion(ctx, npmPURL("big", ""), "^1.0.0", nil)
	if err != nil || got != "1.0.299" {
		t.Fatalf("ResolveVersion = %q, %v; want 1.0.299", got, err)
	}
	st, err := src.Status(ctx, npmPURL("big", "1.0.0"))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Latest != "1.0.299" || st.Yanked {
		t.Errorf("Status = latest %q yanked %v; want 1.0.299, false", st.Latest, st.Yanked)
	}
}

func TestPackageDocOverTenMiBWithDefaultClient(t *testing.T) {
	readme := strings.Repeat("x", 11<<20)
	mux := http.NewServeMux()
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      "big",
			"dist-tags": map[string]string{"latest": "2.0.0"},
			"versions": map[string]any{
				"1.0.0": map[string]any{"name": "big", "version": "1.0.0"},
				"2.0.0": map[string]any{"name": "big", "version": "2.0.0"},
			},
			"readme": readme,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	src := New(Options{RegistryURL: srv.URL})
	got, err := src.ResolveVersion(context.Background(), npmPURL("big", ""), "^2", nil)
	if err != nil || got != "2.0.0" {
		t.Fatalf("ResolveVersion = %q, %v; want 2.0.0", got, err)
	}
}

func TestPackageDocStillBoundedByStreamLimit(t *testing.T) {
	srv := fakePackageDoc(t, "big", map[string]string{"latest": "1.0.299"}, manyVersions(300))
	src := New(Options{
		RegistryURL: srv.URL,
		HTTPClient:  client.NewClient(client.WithMaxStreamSize(1024)),
	})
	_, err := src.ResolveVersion(context.Background(), npmPURL("big", ""), "^1.0.0", nil)
	if !errors.Is(err, client.ErrResponseTooLarge) {
		t.Fatalf("err = %v; want ErrResponseTooLarge", err)
	}
}

func noisePackage(t *testing.T, size int) *fakePackage {
	t.Helper()
	noise := make([]byte, size)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	return &fakePackage{
		name:    "demo",
		version: "1.0.0",
		pkgJSON: map[string]any{"name": "demo", "version": "1.0.0", "main": "index.js"},
		files:   map[string]string{"index.js": string(noise)},
	}
}

func TestResolveTarballLargerThanBufferLimit(t *testing.T) {
	pkg := noisePackage(t, 4096)
	srv := newFakeRegistry(t, pkg)
	if n := servedSize(t, srv, pkg); n <= 1024 {
		t.Fatalf("tarball is %d bytes; the test needs it over the 1024 byte buffer limit", n)
	}
	src := New(Options{RegistryURL: srv.URL, HTTPClient: smallBufferClient()})

	res, err := src.Resolve(context.Background(), npmPURL("demo", "1.0.0"), nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Files) != 1 || len(res.Files[0].Content) != 4096 {
		t.Fatalf("got %d files; want index.js with 4096 bytes", len(res.Files))
	}
}

// servedSize reads the tarball back from the fake registry. tarball()
// writes files in map order, so a second call can differ by a few bytes.
func servedSize(t *testing.T, srv *httptest.Server, pkg *fakePackage) int64 {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/%s/-/%s-%s.tgz", srv.URL, pkg.name, pkg.name, pkg.version))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("read tarball: %d bytes, status %d, %v", n, resp.StatusCode, err)
	}
	return n
}

func TestResolveTarballCapBoundary(t *testing.T) {
	pkg := noisePackage(t, 2048)
	srv := newFakeRegistry(t, pkg)
	size := servedSize(t, srv, pkg)
	ctx := context.Background()

	src := New(Options{RegistryURL: srv.URL, MaxTarballBytes: size})
	if _, err := src.Resolve(ctx, npmPURL("demo", "1.0.0"), nil); err != nil {
		t.Fatalf("tarball of exactly MaxTarballBytes: %v", err)
	}

	src = New(Options{RegistryURL: srv.URL, MaxTarballBytes: size - 1})
	_, err := src.Resolve(ctx, npmPURL("demo", "1.0.0"), nil)
	want := fmt.Sprintf("exceeds cap of %d bytes", size-1)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v; want %q", err, want)
	}
}

// The tarball cap is checked while reading, so an oversized body stops at
// MaxTarballBytes+1 instead of running on to the client's stream limit.
func TestResolveTarballCapStopsReading(t *testing.T) {
	pkg := noisePackage(t, 8192)
	srv := newFakeRegistry(t, pkg)
	src := New(Options{
		RegistryURL:     srv.URL,
		MaxTarballBytes: 1024,
		HTTPClient:      client.NewClient(client.WithMaxStreamSize(4096)),
	})
	_, err := src.Resolve(context.Background(), npmPURL("demo", "1.0.0"), nil)
	if err == nil || errors.Is(err, client.ErrResponseTooLarge) || !strings.Contains(err.Error(), "exceeds cap of 1024 bytes") {
		t.Fatalf("err = %v; want the 1024 byte tarball cap", err)
	}
}
