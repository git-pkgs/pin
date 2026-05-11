package manifest

import "testing"

func TestEntryPURL(t *testing.T) {
	cases := []struct {
		name     string
		entry    Entry
		version  string
		wantPURL string
	}{
		{
			"npm-plain",
			Entry{Name: "htmx.org"},
			"2.0.6",
			"pkg:npm/htmx.org@2.0.6",
		},
		{
			"npm-scoped",
			Entry{Name: "@tailwindcss/browser"},
			"4.1.13",
			"pkg:npm/%40tailwindcss/browser@4.1.13",
		},
		{
			"github",
			Entry{Name: "highlight.js", RawSource: "github:highlightjs/cdn-release"},
			"11.11.1",
			"pkg:github/highlightjs/cdn-release@11.11.1",
		},
		{
			"gitlab",
			Entry{Name: "x", RawSource: "gitlab:group/sub/repo"},
			"1.0.0",
			"pkg:gitlab/group/sub/repo@1.0.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.entry.PURL(tc.version).String()
			if got != tc.wantPURL {
				t.Errorf("PURL() = %q, want %q", got, tc.wantPURL)
			}
		})
	}
}
