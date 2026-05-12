package pin

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzSafeOut exercises the final path-traversal check. safeOut is the
// last line of defence before any vendored bytes hit disk: the
// manifest validates file: paths, slug sanitisation handles the name
// half, but safeOut is what catches anything that slipped through.
//
// Two assertions, both tight:
//
//  1. When safeOut returns no error, the resolved path MUST stay
//     rooted at filepath.Clean(filepath.Join(dir, outDir)).
//     Any escape (computed path outside the root) is a security
//     failure regardless of how the input was crafted.
//
//  2. safeOut must never panic on any input.
//
// Seeds cover the common shapes the manifest validator already
// rejects (absolute paths, .., scheme prefixes) so safeOut's
// belt-and-braces role is exercised end-to-end.
func FuzzSafeOut(f *testing.F) {
	f.Add("/tmp/proj", "v", "demo/x.js")
	f.Add("/tmp/proj", "v", "")
	f.Add("/tmp/proj", "v", "/etc/passwd")
	f.Add("/tmp/proj", "v", "../../etc/passwd")
	f.Add("/tmp/proj", "v", "./../../etc/passwd")
	f.Add("/tmp/proj", "v", "./demo/x.js")
	f.Add("/tmp/proj", "v", "demo/./../../x.js")
	f.Add("/tmp/proj", "v", "demo/../v2/x.js") // legal escape: stays inside dir
	f.Add("/tmp/proj", "", "x.js")
	f.Add("", "v", "x.js")
	f.Add(".", "v", "x.js")
	f.Add("/tmp/proj", "v", "demo\\x.js") // Windows-style separator
	f.Add("/tmp/proj", "v", "\x00null")
	f.Add("/tmp/proj", "v", strings.Repeat("a/", 1000)+"x.js")
	f.Add("/tmp/proj", "..", "x.js") // outDir escape
	f.Add("/tmp/proj", "v/../..", "x.js")

	f.Fuzz(func(t *testing.T, dir, outDir, out string) {
		dst, err := safeOut(dir, outDir, out)
		if err != nil {
			return
		}
		// Accepted: dst must be rooted at the canonical (dir, outDir) join.
		root := filepath.Clean(filepath.Join(dir, outDir))
		rel, relErr := filepath.Rel(root, dst)
		if relErr != nil {
			t.Errorf("safeOut(%q, %q, %q) returned %q which is not Rel-able to root %q: %v",
				dir, outDir, out, dst, root, relErr)
			return
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Errorf("safeOut(%q, %q, %q) accepted but rel=%q escapes root %q",
				dir, outDir, out, rel, root)
		}
	})
}
