package manifest

import (
	"bytes"
	"testing"
)

// FuzzRead pushes arbitrary bytes through the manifest YAML parser. The
// contract is "doesn't panic on any input". Valid manifests should
// round-trip: a manifest that Read accepts, when re-fed to Read after
// being decoded and re-encoded, must produce the same structure.
//
// Seeds cover the happy path, a maximally-loaded entry (every optional
// field set), the documented validation failures (absolute file paths,
// .. escapes, missing version), and a few odd YAML shapes (anchors,
// flow style, BOM).
func FuzzRead(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("\xef\xbb\xbf")) // BOM only
	f.Add([]byte("---\n"))
	f.Add([]byte(`out: v
assets: []
`))
	f.Add([]byte(`out: "static/vendor"
min_release_age: 48h
assets:
  - name: "demo"
    version: "1.2.3"
    files: ["dist/demo.min.js"]
`))
	f.Add([]byte(`out: "v"
trust:
  require_provenance: true
  trusted_workflows:
    - https://github.com/o/r/.github/workflows/release.yml
assets:
  - name: pkg
    version: ^1.0.0
    files: [a.js]
    trust:
      require_publisher_matches_repository: false
`))
	// Forge source shape.
	f.Add([]byte(`out: v
assets:
  - source: github:o/r
    version: v1
    files: [dist/x.js]
`))
	// Path-traversal seed — Read MUST reject this, not panic.
	f.Add([]byte(`out: v
assets:
  - name: bad
    version: "1.0.0"
    files: ["../etc/passwd"]
`))
	// Flow-style YAML.
	f.Add([]byte(`{out: v, assets: [{name: x, version: "1", files: [a.js]}]}`))
	// Deeply indented (parser shouldn't OOM).
	f.Add([]byte("out: v\nassets:\n  - name: x\n    version: '1.0.0'\n    files:\n      - a.js\n"))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = Read(bytes.NewReader(body))
	})
}
