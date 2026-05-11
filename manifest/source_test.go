package manifest

import "testing"

func TestParseSource(t *testing.T) {
	cases := []struct {
		in   string
		want Source
	}{
		{"", Source{Kind: SourceNPM}},
		{"npm", Source{Kind: SourceNPM}},
		{"github:owner/repo", Source{Kind: SourceForge, Forge: "github", Owner: "owner", Repo: "repo"}},
		{"gitlab:group/sub/repo", Source{Kind: SourceForge, Forge: "gitlab", Owner: "group/sub", Repo: "repo"}},
		{"gitea:host.example.com/owner/repo", Source{Kind: SourceForge, Forge: "gitea", Host: "host.example.com", Owner: "owner", Repo: "repo"}},
		{"codeberg:owner/repo", Source{Kind: SourceForge, Forge: "codeberg", Owner: "owner", Repo: "repo"}},
		{"bitbucket:workspace/repo", Source{Kind: SourceForge, Forge: "bitbucket", Owner: "workspace", Repo: "repo"}},
		{"git:https://forge.example.com/owner/repo", Source{Kind: SourceForge, Forge: "git", URL: "https://forge.example.com/owner/repo"}},
		{"url:https://example.com/foo.js", Source{Kind: SourceURL, URL: "https://example.com/foo.js"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSource(tc.in)
			if err != nil {
				t.Fatalf("ParseSource(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseSource(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseSourceErrors(t *testing.T) {
	cases := []string{
		"github:",
		"github:owner",
		"gitea:owner/repo",
		"url:",
		"git:",
		"unknown:foo",
		"ftp:foo",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseSource(in); err == nil {
				t.Fatalf("ParseSource(%q) succeeded, want error", in)
			}
		})
	}
}

func TestSlug(t *testing.T) {
	cases := []struct {
		entry Entry
		want  string
	}{
		{Entry{Name: "htmx.org"}, "htmx.org"},
		{Entry{Name: "@tailwindcss/browser"}, "tailwindcss__browser"},
		{Entry{Name: "@scope/pkg-name"}, "scope__pkg-name"},
		{Entry{Name: "highlight.js", RawSource: "github:highlightjs/cdn-release"}, "highlightjs__cdn-release"},
		{Entry{Name: "x", RawSource: "gitlab:group/sub/repo"}, "group__sub__repo"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.entry.Slug(); got != tc.want {
				t.Errorf("Slug() = %q, want %q", got, tc.want)
			}
		})
	}
}
