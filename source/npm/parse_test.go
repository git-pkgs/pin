package npm

import (
	"encoding/json"
	"testing"
)

func TestParseLicense(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`"MIT"`, "MIT"},
		{`{"type":"Apache-2.0","url":"..."}`, "Apache-2.0"},
		{``, ""},
		{`null`, ""},
	}
	for _, tc := range cases {
		if got := parseLicense(json.RawMessage(tc.in)); got != tc.want {
			t.Errorf("parseLicense(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseRepository(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`"https://github.com/foo/bar"`, "https://github.com/foo/bar"},
		{`{"url":"git+https://github.com/foo/bar.git"}`, "https://github.com/foo/bar"},
		{`{"url":"git://github.com/foo/bar.git"}`, "https://github.com/foo/bar"},
		{`{"url":"ssh://git@gitlab.com/foo/bar.git"}`, "https://gitlab.com/foo/bar"},
		{`{"url":"git@github.com:foo/bar.git"}`, "https://github.com/foo/bar"},
		{``, ""},
	}
	for _, tc := range cases {
		if got := parseRepository(json.RawMessage(tc.in)); got != tc.want {
			t.Errorf("parseRepository(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
