package npm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakePackageDoc(t *testing.T, name string, distTags map[string]string, versions []string) *httptest.Server {
	t.Helper()
	vmap := map[string]any{}
	for _, v := range versions {
		vmap[v] = map[string]any{"name": name, "version": v}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      name,
			"dist-tags": distTags,
			"versions":  vmap,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveVersionExact(t *testing.T) {
	src := New(Options{})
	got, err := src.ResolveVersion(context.Background(), "x", "2.0.6")
	if err != nil || got != "2.0.6" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestResolveVersionDistTag(t *testing.T) {
	srv := fakePackageDoc(t, "demo",
		map[string]string{"latest": "3.1.0", "next": "4.0.0-beta.1"},
		[]string{"2.0.0", "3.0.0", "3.1.0", "4.0.0-beta.1"})
	src := New(Options{RegistryURL: srv.URL})

	for tag, want := range map[string]string{"latest": "3.1.0", "next": "4.0.0-beta.1"} {
		got, err := src.ResolveVersion(context.Background(), "demo", tag)
		if err != nil || got != want {
			t.Errorf("ResolveVersion(%q) = %q, %v; want %q", tag, got, err, want)
		}
	}
}

func TestResolveVersionRange(t *testing.T) {
	srv := fakePackageDoc(t, "demo",
		map[string]string{"latest": "2.5.1"},
		[]string{"1.0.0", "1.9.0", "2.0.0", "2.5.0", "2.5.1", "3.0.0-rc.1"})
	src := New(Options{RegistryURL: srv.URL})

	cases := []struct {
		constraint string
		want       string
	}{
		{"^2.0", "2.5.1"},
		{"~2.5.0", "2.5.1"},
		{"^1.0", "1.9.0"},
		{">=1.0.0 <2.0.0", "1.9.0"},
	}
	for _, tc := range cases {
		got, err := src.ResolveVersion(context.Background(), "demo", tc.constraint)
		if err != nil || got != tc.want {
			t.Errorf("ResolveVersion(%q) = %q, %v; want %q", tc.constraint, got, err, tc.want)
		}
	}
}

func TestResolveVersionNoMatch(t *testing.T) {
	srv := fakePackageDoc(t, "demo", map[string]string{}, []string{"1.0.0"})
	src := New(Options{RegistryURL: srv.URL})

	if _, err := src.ResolveVersion(context.Background(), "demo", "^9.0"); err == nil {
		t.Fatal("expected error for unsatisfiable range")
	}
}

func TestIsSticky(t *testing.T) {
	cases := []struct {
		locked, constraint string
		want               bool
	}{
		{"2.0.6", "2.0.6", true},
		{"2.0.6", "2.0.7", false},
		{"2.0.6", "^2.0", true},
		{"2.0.6", "^2.0.0", true},
		{"2.0.6", "~2.0.5", true},
		{"1.9.0", "^2.0", false},
		{"2.0.6", "latest", false},
		{"2.0.6", "next", false},
		{"", "^2.0", false},
	}
	for _, tc := range cases {
		if got := IsSticky(tc.locked, tc.constraint); got != tc.want {
			t.Errorf("IsSticky(%q, %q) = %v, want %v", tc.locked, tc.constraint, got, tc.want)
		}
	}
}
