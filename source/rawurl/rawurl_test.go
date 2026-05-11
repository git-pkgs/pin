package rawurl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/git-pkgs/purl"
)

func TestResolveURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/some/file.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("console.log('hello')"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := purl.New("generic", "", "my-asset", "1.0.0", map[string]string{
		"download_url": srv.URL + "/some/file.js",
	})

	got, err := New(Options{}).Resolve(context.Background(), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "my-asset" || got.Version != "1.0.0" {
		t.Errorf("name/version = %s@%s", got.Name, got.Version)
	}
	if len(got.Files) != 1 {
		t.Fatalf("Files = %d", len(got.Files))
	}
	f := got.Files[0]
	if f.Path != "file.js" {
		t.Errorf("Path = %q", f.Path)
	}
	if !strings.HasPrefix(f.Integrity, "sha384-") {
		t.Errorf("Integrity = %q", f.Integrity)
	}
	if string(f.Content) != "console.log('hello')" {
		t.Errorf("Content = %q", f.Content)
	}
}

func TestResolveMissingURL(t *testing.T) {
	p := purl.New("generic", "", "x", "1.0.0", nil)
	if _, err := New(Options{}).Resolve(context.Background(), p, nil); err == nil {
		t.Fatal("expected error when download_url qualifier is missing")
	}
}
