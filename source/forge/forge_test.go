package forge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/git-pkgs/purl"
)

func fakeGitHub(t *testing.T, owner, repo, tag, sha string, files map[string]string) (api, cdn string) {
	t.Helper()
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/repos/"+owner+"/"+repo+"/commits/"+tag, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"sha": sha})
	})
	apiSrv := httptest.NewServer(apiMux)
	t.Cleanup(apiSrv.Close)

	cdnMux := http.NewServeMux()
	for path, content := range files {
		p := "/gh/" + owner + "/" + repo + "@" + sha + "/" + path
		body := content
		cdnMux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		})
	}
	cdnSrv := httptest.NewServer(cdnMux)
	t.Cleanup(cdnSrv.Close)

	return apiSrv.URL, cdnSrv.URL
}

func ghPURL(owner, repo, version string) *purl.PURL {
	return purl.New("github", owner, repo, version, nil)
}

func TestResolveGitHub(t *testing.T) {
	api, cdn := fakeGitHub(t, "highlightjs", "cdn-release", "11.11.1",
		"abc123def4567890abc123def4567890abc12345",
		map[string]string{
			"build/highlight.min.js":      "var hljs={}",
			"build/styles/github.min.css": ".hljs{}",
		})

	src := New(Options{GitHubAPI: api, JSDelivrCDN: cdn})
	got, err := src.Resolve(context.Background(),
		ghPURL("highlightjs", "cdn-release", "11.11.1"),
		[]string{"build/highlight.min.js", "build/styles/github.min.css"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if got.PackageIntegrity != "abc123def4567890abc123def4567890abc12345" {
		t.Errorf("PackageIntegrity = %q", got.PackageIntegrity)
	}
	if got.Version != "11.11.1" {
		t.Errorf("Version = %q", got.Version)
	}
	if got.SourceRepository != "https://github.com/highlightjs/cdn-release" {
		t.Errorf("SourceRepository = %q", got.SourceRepository)
	}
	if !strings.HasPrefix(got.PURL, "pkg:github/highlightjs/cdn-release@11.11.1") {
		t.Errorf("PURL = %q", got.PURL)
	}
	if !strings.Contains(got.PURL, "vcs_revision=abc123") {
		t.Errorf("PURL missing vcs_revision qualifier: %q", got.PURL)
	}
	if len(got.Files) != 2 {
		t.Fatalf("Files = %d", len(got.Files))
	}
	for _, f := range got.Files {
		if !strings.HasPrefix(f.Integrity, "sha384-") {
			t.Errorf("file %s integrity = %q", f.Path, f.Integrity)
		}
		if !strings.Contains(f.URL, "@abc123def") {
			t.Errorf("file %s URL should be SHA-pinned: %q", f.Path, f.URL)
		}
	}
}

func TestResolveGitHubSHADirect(t *testing.T) {
	sha := "1234567890123456789012345678901234567890"
	_, cdn := fakeGitHub(t, "o", "r", "ignored", sha, map[string]string{"x.js": "x"})
	src := New(Options{JSDelivrCDN: cdn})

	got, err := src.Resolve(context.Background(), ghPURL("o", "r", sha), []string{"x.js"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.PackageIntegrity != sha {
		t.Errorf("PackageIntegrity = %q, want passthrough", got.PackageIntegrity)
	}
}

func TestResolveRequiresFiles(t *testing.T) {
	src := New(Options{})
	if _, err := src.Resolve(context.Background(), ghPURL("o", "r", "v1"), nil); err == nil {
		t.Fatal("expected error when files: is empty")
	}
}

func TestResolveUnsupportedForge(t *testing.T) {
	src := New(Options{})
	if _, err := src.Resolve(context.Background(), purl.New("gitlab", "o", "r", "v1", nil), []string{"x"}); err == nil {
		t.Fatal("expected error for unsupported forge type")
	}
}

func TestIsHex(t *testing.T) {
	if !isHex("abc123DEF") {
		t.Error("hex string not recognised")
	}
	if isHex("ghijk") {
		t.Error("non-hex accepted")
	}
}
