// Package sniff detects the module format of a JavaScript file from its
// bytes. No JS parser; it strips string and comment content and looks for
// reserved-token signatures that survive minification. Best-effort.
package sniff

import (
	"bytes"
	"regexp"
)

const (
	ESM      = "esm"
	UMD      = "umd"
	IIFE     = "iife"
	CJS      = "cjs"
	AMD      = "amd"
	SystemJS = "system"
	Unknown  = "unknown"
)

const (
	maxScanBytes = 64 << 10
	tailScanLen  = 4 << 10
	delimLen     = 2
)

// Both line- and block-comment forms of //# sourceMappingURL and
// //@ sourceMappingURL. Browsers honour only the LAST occurrence;
// stripping all of them is safe and simpler.
var reSourceMappingURL = regexp.MustCompile(`(?m)(^[\t ]*//[#@]\s+sourceMappingURL=[^\r\n]*$|/\*[#@]\s+sourceMappingURL=[^*]*\*+(?:[^/*][^*]*\*+)*/)`)

// StripSourcemapURL removes every sourceMappingURL directive,
// preserving surrounding newlines so stack traces stay aligned.
func StripSourcemapURL(src []byte) []byte {
	return reSourceMappingURL.ReplaceAll(src, nil)
}

var (
	reTypeofDefine = regexp.MustCompile(`\btypeof\s+define\b`)
	reDefineAMD    = regexp.MustCompile(`\bdefine\.amd\b`)
	reSystem       = regexp.MustCompile(`\bSystem\.register\s*\(`)
	reAMDDefine    = regexp.MustCompile(`\bdefine\s*\(\s*(\[|['"])`)
	reESMExportKW  = regexp.MustCompile(`\bexport\s+(default\b|const\b|let\b|var\b|function\b|class\b|async\b)`)
	reESMExportBr  = regexp.MustCompile(`\bexport\s*[\{\*]`)
	reESMImportBr  = regexp.MustCompile(`\bimport\s*[\{\*]`)
	reESMImportBnd = regexp.MustCompile(`\bimport\s+[A-Za-z_$]`)
	reESMImportStr = regexp.MustCompile(`\bimport\s*['"]`)
	reCJSModule    = regexp.MustCompile(`\bmodule\.exports\b|\bexports\.[A-Za-z_$]|\bexports\s*\[`)
	reCJSDefine    = regexp.MustCompile(`Object\.defineProperty\s*\(\s*exports\s*,`)
	reIIFEWrapped  = regexp.MustCompile("^[\\s;\"'`]*[!~+\\-]?\\s*\\(?\\s*(function\\s*\\(|\\(\\s*\\)\\s*=>)")
	reIIFEAssigned = regexp.MustCompile(`^[\s;]*(var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*\(?\s*function\s*\(`)
	reTrailingCall = regexp.MustCompile(`\}\s*\)?\s*\(\s*[^)]{0,200}\)\s*;`)
)

// Format detects the module format. Order matters: UMD wrappers
// contain markers for several other formats, so UMD wins first.
func Format(src []byte) string {
	if len(src) == 0 {
		return Unknown
	}
	headSrc := src
	if len(headSrc) > maxScanBytes {
		headSrc = src[:maxScanBytes]
	}
	masked := stripStringsAndComments(headSrc)
	// Tail is unmasked: walking stripStringsAndComments from
	// mid-string misreads context, and reTrailingCall is structural
	// enough to avoid false positives.
	tail := tailBytes(src, tailScanLen)

	if reTypeofDefine.Match(masked) && reDefineAMD.Match(masked) {
		return UMD
	}
	if reSystem.Match(masked) {
		return SystemJS
	}
	if reAMDDefine.Match(masked) && !bytes.Contains(masked, []byte("module.exports")) {
		return AMD
	}
	if reESMExportKW.Match(masked) || reESMExportBr.Match(masked) ||
		reESMImportBr.Match(masked) || reESMImportBnd.Match(masked) || reESMImportStr.Match(masked) {
		return ESM
	}
	if reCJSModule.Match(masked) || reCJSDefine.Match(masked) {
		return CJS
	}
	if (reIIFEWrapped.Match(masked) || reIIFEAssigned.Match(masked)) && reTrailingCall.Match(tail) {
		return IIFE
	}
	return Unknown
}

func tailBytes(src []byte, n int) []byte {
	if len(src) <= n {
		return src
	}
	return src[len(src)-n:]
}

// stripStringsAndComments empties string-literal and comment bodies
// while preserving delimiters, so regex matches don't fire inside
// quoted text and offsets stay approximately aligned.
func stripStringsAndComments(src []byte) []byte {
	out := make([]byte, 0, len(src))
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			i = skipUntil(src, i+delimLen, '\n')
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i = skipBlockComment(src, i+delimLen)
		case c == '"' || c == '\'' || c == '`':
			out = append(out, c)
			i = skipString(src, i+1, c)
			out = append(out, c)
		default:
			out = append(out, c)
			i++
		}
	}
	return out
}

func skipUntil(src []byte, i int, stop byte) int {
	for i < len(src) && src[i] != stop {
		i++
	}
	return i
}

func skipBlockComment(src []byte, i int) int {
	for i+1 < len(src) {
		if src[i] == '*' && src[i+1] == '/' {
			return i + delimLen
		}
		i++
	}
	return len(src)
}

func skipString(src []byte, i int, quote byte) int {
	for i < len(src) {
		c := src[i]
		if c == '\\' && i+1 < len(src) {
			i += 2
			continue
		}
		if c == quote {
			return i + 1
		}
		if quote != '`' && c == '\n' {
			return i
		}
		i++
	}
	return len(src)
}
