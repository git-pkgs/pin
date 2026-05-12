package sniff

import (
	"strings"
	"testing"
)

// FuzzFormat throws arbitrary bytes at the module-format sniffer. The
// scan is comment- and string-aware, walks the buffer byte by byte with
// hand-rolled state, and runs several regexes; plenty of room for off-
// by-one panics on partial strings, unbalanced quotes, BOMs, or
// pathological backtracking inputs. Contract is "doesn't panic", and
// "returns one of the documented formats" (Unknown for anything that
// doesn't match).
func FuzzFormat(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("export const x = 1"))
	f.Add([]byte("module.exports = {}"))
	f.Add([]byte("(function(global, factory){})(this, function(){})"))
	f.Add([]byte("System.register([], function(){})"))
	f.Add([]byte("define(['a','b'], function(a, b){})"))
	f.Add([]byte("(function(){})()"))
	// Unterminated string — stripStringsAndComments must not run past EOF.
	f.Add([]byte(`"never closes`))
	// Unterminated block comment.
	f.Add([]byte(`/* never closes`))
	// Nested escape sequences inside a string.
	f.Add([]byte(`"\\\"\\\\"`))
	// BOM + ESM marker.
	f.Add([]byte("\xef\xbb\xbfexport default 1"))
	// 1 MiB of "//" line-comment fodder.
	f.Add([]byte(strings.Repeat("// pad\n", 100000)))
	// Single-byte inputs — the byte-walk state machine has to cope.
	for _, b := range []byte{'\x00', '"', '\'', '/', '`', '\\', '\n', 0xff} {
		f.Add([]byte{b})
	}

	valid := map[string]bool{
		UMD: true, SystemJS: true, AMD: true, ESM: true, CJS: true, IIFE: true, Unknown: true,
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		got := Format(src)
		if !valid[got] {
			t.Errorf("Format returned undocumented format %q", got)
		}
	})
}
