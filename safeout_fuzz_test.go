package pin

import (
	"io/fs"
	"strings"
	"testing"
)

// FuzzSafeOut exercises the final path-traversal check. safeOut is
// the last line of defence before any vendored bytes leave pin: the
// manifest validates files: paths and slugs are built from sanitised
// names, but safeOut is what catches anything that slipped through.
//
// Two assertions, both tight:
//
//  1. When safeOut returns no error, the resolved slash path MUST
//     be a valid relative path (fs.ValidPath) and MUST remain rooted
//     at the cleaned outDir. Any escape is a security failure
//     regardless of how the input was crafted.
//
//  2. safeOut must never panic on any input.
//
// Seeds cover the common shapes the manifest validator already
// rejects (absolute paths, .., scheme prefixes) so safeOut's
// belt-and-braces role is exercised end-to-end.
func FuzzSafeOut(f *testing.F) {
	f.Add("v", "demo/x.js")
	f.Add("v", "")
	f.Add("v", "/etc/passwd")
	f.Add("v", "../../etc/passwd")
	f.Add("v", "./../../etc/passwd")
	f.Add("v", "./demo/x.js")
	f.Add("v", "demo/./../../x.js")
	f.Add("v", "demo/../v2/x.js") // illegal: leaves outDir
	f.Add("", "x.js")
	f.Add(".", "x.js")
	f.Add("v", "demo\\x.js") // Windows-style separator
	f.Add("v", "\x00null")
	f.Add("v", strings.Repeat("a/", 1000)+"x.js")
	f.Add("..", "x.js")      // outDir escape
	f.Add("v/../..", "x.js") // outDir escape (cleaned)
	f.Add("vendor", "sub/x.js")

	f.Fuzz(func(t *testing.T, outDir, out string) {
		dst, err := safeOut(outDir, out)
		if err != nil {
			return
		}
		if !fs.ValidPath(dst) {
			t.Errorf("safeOut(%q, %q) returned %q which is not fs.ValidPath",
				outDir, out, dst)
			return
		}
		// Accepted: dst must equal cleaned outDir, or start with cleaned outDir + "/".
		// Empty / "." outDir means "no subdir" — any valid relative path is fine.
		switch outDir {
		case "", ".":
			return
		}
		// Compute the cleaned outDir the same way safeOut did.
		// (Tests should mirror the implementation, not reproduce it
		// from scratch, but we keep the assertion close to invariant.)
		if dst == outDir || strings.HasPrefix(dst, outDir+"/") {
			return
		}
		// safeOut may have cleaned outDir before comparing; allow that.
		cleaned := strings.TrimSuffix(outDir, "/")
		if dst == cleaned || strings.HasPrefix(dst, cleaned+"/") {
			return
		}
		t.Errorf("safeOut(%q, %q) accepted %q which escapes outDir",
			outDir, out, dst)
	})
}
