package sniff

import (
	"testing"
)

func TestFormatRealMinified(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"tailwind-shape", `"use strict";(()=>{var x=1;})();`, IIFE},
		{"highlight-shape", "\nvar hljs=function(){\"use strict\";return{};}();", IIFE},
		{"highlight-banner", "/*!\n  Highlight.js v11\n  License: BSD-3-Clause\n */\nvar hljs=function(){\"use strict\";return{};}();", IIFE},
		{"tailwind-banner", "/*!\n  Tailwind v4\n */\n\"use strict\";(()=>{var x=1;})();", IIFE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Format([]byte(tc.src)); got != tc.want {
				masked := stripStringsAndComments([]byte(tc.src))
				t.Errorf("Format() = %q, want %q\nmasked: %q", got, tc.want, masked)
			}
		})
	}
}
