package npm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fakePackageDoc(t *testing.T, name string, distTags map[string]string, versions []string) *httptest.Server {
	t.Helper()
	return fakePackageDocAt(t, name, distTags, versions, nil)
}

func fakePackageDocAt(t *testing.T, name string, distTags map[string]string, versions []string, times map[string]string) *httptest.Server {
	t.Helper()
	vmap := map[string]any{}
	for _, v := range versions {
		vmap[v] = map[string]any{"name": name, "version": v}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{
			"name":      name,
			"dist-tags": distTags,
			"versions":  vmap,
		}
		if times != nil {
			body["time"] = times
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveVersionExact(t *testing.T) {
	src := New(Options{})
	got, err := src.ResolveVersion(context.Background(), "x", "2.0.6", 0)
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
		got, err := src.ResolveVersion(context.Background(), "demo", tag, 0)
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
		got, err := src.ResolveVersion(context.Background(), "demo", tc.constraint, 0)
		if err != nil || got != tc.want {
			t.Errorf("ResolveVersion(%q) = %q, %v; want %q", tc.constraint, got, err, tc.want)
		}
	}
}

func TestResolveVersionNoMatch(t *testing.T) {
	srv := fakePackageDoc(t, "demo", map[string]string{}, []string{"1.0.0"})
	src := New(Options{RegistryURL: srv.URL})

	if _, err := src.ResolveVersion(context.Background(), "demo", "^9.0", 0); err == nil {
		t.Fatal("expected error for unsatisfiable range")
	}
}

func TestResolveVersionCooldown(t *testing.T) {
	now := time.Now().UTC()
	old := now.AddDate(0, 0, -10).Format(time.RFC3339)
	recent := now.Add(-2 * time.Hour).Format(time.RFC3339)
	srv := fakePackageDocAt(t, "demo",
		map[string]string{"latest": "2.0.0", "next": "2.0.0"},
		[]string{"1.0.0", "1.5.0", "2.0.0"},
		map[string]string{
			"1.0.0":    old,
			"1.5.0":    old,
			"2.0.0":    recent,
			"modified": recent,
		})
	src := New(Options{RegistryURL: srv.URL})

	t.Run("range falls back to older version", func(t *testing.T) {
		got, err := src.ResolveVersion(context.Background(), "demo", "^1.0", 48*time.Hour)
		if err != nil || got != "1.5.0" {
			t.Errorf("got %q, %v; want 1.5.0", got, err)
		}
	})

	t.Run("range to fresh major fails", func(t *testing.T) {
		_, err := src.ResolveVersion(context.Background(), "demo", "^2.0", 48*time.Hour)
		if err == nil || !strings.Contains(err.Error(), "cooldown") {
			t.Errorf("expected cooldown error, got %v", err)
		}
	})

	t.Run("dist-tag pointing at fresh version fails", func(t *testing.T) {
		_, err := src.ResolveVersion(context.Background(), "demo", "latest", 48*time.Hour)
		if err == nil || !strings.Contains(err.Error(), "cooldown") {
			t.Errorf("expected cooldown error, got %v", err)
		}
	})

	t.Run("exact pin bypasses cooldown", func(t *testing.T) {
		got, err := src.ResolveVersion(context.Background(), "demo", "2.0.0", 48*time.Hour)
		if err != nil || got != "2.0.0" {
			t.Errorf("got %q, %v; want 2.0.0", got, err)
		}
	})

	t.Run("zero cooldown is opt-out", func(t *testing.T) {
		got, err := src.ResolveVersion(context.Background(), "demo", "^2.0", 0)
		if err != nil || got != "2.0.0" {
			t.Errorf("got %q, %v; want 2.0.0", got, err)
		}
	})
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
