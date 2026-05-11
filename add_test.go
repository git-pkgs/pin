package pin

import (
	"testing"
)

func TestParseSpec(t *testing.T) {
	cases := []struct {
		in               string
		name, constraint string
	}{
		{"htmx.org", "htmx.org", ""},
		{"htmx.org@2.0.6", "htmx.org", "2.0.6"},
		{"htmx.org@^2.0", "htmx.org", "^2.0"},
		{"htmx.org@latest", "htmx.org", "latest"},
		{"@scope/pkg", "@scope/pkg", ""},
		{"@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"},
		{"@scope/pkg@^1.0", "@scope/pkg", "^1.0"},
	}
	for _, tc := range cases {
		name, c := parseSpec(tc.in)
		if name != tc.name || c != tc.constraint {
			t.Errorf("parseSpec(%q) = %q, %q; want %q, %q", tc.in, name, c, tc.name, tc.constraint)
		}
	}
}

func TestCaretMajorMinor(t *testing.T) {
	cases := map[string]string{
		"2.0.6":        "^2.0",
		"1.5.0":        "^1.5",
		"0.3.11":       "^0.3",
		"4.0.0-beta.1": "^4.0",
		"1":            "^1",
	}
	for in, want := range cases {
		if got := caretMajorMinor(in); got != want {
			t.Errorf("caretMajorMinor(%q) = %q, want %q", in, got, want)
		}
	}
}
