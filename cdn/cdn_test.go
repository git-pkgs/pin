package cdn

import "testing"

func TestNPMFileURL(t *testing.T) {
	cases := []struct {
		m                   Mirror
		name, version, path string
		want                string
	}{
		{JSDelivr, "htmx.org", "2.0.6", "dist/htmx.min.js", "https://cdn.jsdelivr.net/npm/htmx.org@2.0.6/dist/htmx.min.js"},
		{JSDelivr, "@scope/pkg", "1.0.0", "x.js", "https://cdn.jsdelivr.net/npm/@scope/pkg@1.0.0/x.js"},
		{Unpkg, "htmx.org", "2.0.6", "dist/htmx.min.js", "https://unpkg.com/htmx.org@2.0.6/dist/htmx.min.js"},
		{"", "x", "1", "y", "https://cdn.jsdelivr.net/npm/x@1/y"},
	}
	for _, tc := range cases {
		if got := NPMFileURL(tc.m, tc.name, tc.version, tc.path); got != tc.want {
			t.Errorf("NPMFileURL(%s, %s, %s, %s) = %q, want %q", tc.m, tc.name, tc.version, tc.path, got, tc.want)
		}
	}
}

func TestForgeFileURL(t *testing.T) {
	if got := ForgeFileURL(JSDelivr, "github", "owner", "repo", "v1.0", "dist/x.js"); got != "https://cdn.jsdelivr.net/gh/owner/repo@v1.0/dist/x.js" {
		t.Errorf("github = %q", got)
	}
	if got := ForgeFileURL(JSDelivr, "gitlab", "owner", "repo", "v1.0", "dist/x.js"); got != "https://cdn.jsdelivr.net/gl/owner/repo@v1.0/dist/x.js" {
		t.Errorf("gitlab = %q", got)
	}
	if got := ForgeFileURL(JSDelivr, "gitea", "o", "r", "v1", "x"); got != "" {
		t.Errorf("unsupported forge should return empty, got %q", got)
	}
}
