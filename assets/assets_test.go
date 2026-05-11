package assets

import (
	"strings"
	"testing"

	"github.com/git-pkgs/pin/lock"
)

func sample() *Lock {
	return &Lock{
		OutDir: "static/vendor",
		Assets: []Asset{
			{Name: "htmx.org", Type: "script", Out: "htmx.org/htmx.min.js", Integrity: "sha384-aaa"},
			{Name: "basecoat-css", Type: "style", Out: "basecoat-css/basecoat.cdn.min.css", Integrity: "sha384-bbb"},
			{Name: "basecoat-css", Type: "script", Out: "basecoat-css/all.min.js", Integrity: "sha384-ccc"},
			{Name: "inter", Type: "font", Out: "inter/Inter.woff2", Integrity: "sha384-ddd"},
		},
	}
}

func TestTagScript(t *testing.T) {
	l := sample()
	got := Tag(l, "htmx.org", Options{Prefix: "/static/vendor/"})
	if len(got) != 1 {
		t.Fatalf("Tag = %d, want 1", len(got))
	}
	s := string(got[0])
	if !strings.HasPrefix(s, "<script ") {
		t.Errorf("expected <script>, got %q", s)
	}
	for _, want := range []string{
		`src="/static/vendor/htmx.org/htmx.min.js"`,
		`integrity="sha384-aaa"`,
		`crossorigin="anonymous"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %q", want, s)
		}
	}
}

func TestTagStyle(t *testing.T) {
	l := sample()
	got := Tag(l, "basecoat-css", Options{Prefix: "/v/"})
	if len(got) != 2 {
		t.Fatalf("Tag = %d, want 2 (one css, one js)", len(got))
	}
	style := string(got[0])
	if !strings.Contains(style, `rel="stylesheet"`) || !strings.Contains(style, `href="/v/basecoat-css/basecoat.cdn.min.css"`) {
		t.Errorf("style = %q", style)
	}
	if !strings.Contains(string(got[1]), "<script ") {
		t.Errorf("second basecoat tag should be script: %q", got[1])
	}
}

func TestTagFont(t *testing.T) {
	l := sample()
	got := Tag(l, "inter", Options{})
	s := string(got[0])
	if !strings.Contains(s, `rel="preload"`) || !strings.Contains(s, `as="font"`) {
		t.Errorf("font = %q", s)
	}
}

func TestTagsByType(t *testing.T) {
	l := sample()
	scripts := Tags(l, "script", Options{})
	if len(scripts) != 2 {
		t.Errorf("scripts = %d, want 2", len(scripts))
	}
	styles := Tags(l, "style", Options{})
	if len(styles) != 1 {
		t.Errorf("styles = %d, want 1", len(styles))
	}
}

func TestTagEscaping(t *testing.T) {
	l := &Lock{Assets: []Asset{{
		Name: "evil", Type: "script",
		Out:       `evil/"><script>alert(1)</script>`,
		Integrity: `"><img src=x onerror=alert(1)>`,
	}}}
	s := string(Tag(l, "evil", Options{})[0])
	if strings.Contains(s, "<script>alert") || strings.Contains(s, "<img") {
		t.Errorf("output is not escaped: %q", s)
	}
}

func TestSRI(t *testing.T) {
	l := sample()
	if got := SRI(l, "htmx.org"); got != "sha384-aaa" {
		t.Errorf("SRI = %q", got)
	}
	if got := SRI(l, "nope"); got != "" {
		t.Errorf("SRI for missing = %q", got)
	}
}

func TestParseRoundTrip(t *testing.T) {
	var sb strings.Builder
	if err := lock.Write(&sb, sample(), "pin", "test"); err != nil {
		t.Fatal(err)
	}
	got, err := Parse(strings.NewReader(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assets) != 4 {
		t.Errorf("Assets = %d", len(got.Assets))
	}
}
