package npm

import (
	"testing"
	"time"
)

// isStickySlowLimit caps a single IsSticky call. Real registry
// versions and manifest constraints resolve in microseconds; anything
// past this is either pathological backtracking inside vers.Satisfies
// or genuine algorithmic complexity worth surfacing as a bug.
const isStickySlowLimit = 100 * time.Millisecond

// FuzzIsSticky pushes arbitrary strings into the lock-is-sticky check.
// IsSticky delegates to vers.Satisfies internally and must:
//   - never panic on any input
//   - return within isStickySlowLimit (catches regex-backtracking and
//     similar algorithmic-complexity issues at the trust boundary
//     where attacker-controlled manifests reach this function)
func FuzzIsSticky(f *testing.F) {
	f.Add("", "")
	f.Add("", "1.0.0")
	f.Add("1.0.0", "")
	f.Add("1.2.3", "^1.0.0")
	f.Add("1.2.3", "latest")
	f.Add("not-a-version", "not-a-constraint")
	f.Add("1.0.0-rc.1", "~1.0.0")
	f.Add("9999999999999.0.0", "x.y.z")
	f.Add("1.0.0", "1.0.0 || 2.0.0")

	f.Fuzz(func(t *testing.T, locked, constraint string) {
		done := make(chan struct{})
		go func() {
			_ = IsSticky(locked, constraint)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(isStickySlowLimit):
			t.Errorf("IsSticky(%q, %q) did not return within %v", locked, constraint, isStickySlowLimit)
		}
	})
}

// FuzzFindSignature fuzzes the npm dist.signatures JSON sniffer. raw is
// a version document body; findSignature should return nil rather than
// panic on any malformed JSON.
func FuzzFindSignature(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"dist":{}}`))
	f.Add([]byte(`{"dist":{"signatures":[]}}`))
	f.Add([]byte(`{"dist":{"signatures":[{"sig":"abc","keyid":"k"}]}}`))
	f.Add([]byte(`{"dist":{"signatures":[{"sig":"","keyid":""}]}}`))
	f.Add([]byte(`{"dist":{"signatures":[{},{"sig":"x","keyid":"y"}]}}`))
	f.Add([]byte(`{"dist":{"signatures":null}}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = findSignature(raw)
	})
}
