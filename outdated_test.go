package pin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/git-pkgs/pin/lock"
)

func writeLockFixture(t *testing.T, dir string, l *lock.Lock) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, DefaultLock))
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Write(f, l, ToolName, "test"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func fakeOutdatedRegistry(t *testing.T, packages map[string]map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for name, doc := range packages {
		mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(doc)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestOutdated(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	old := time.Now().UTC().AddDate(0, 0, -100).Format(time.RFC3339)
	srv := fakeOutdatedRegistry(t, map[string]map[string]any{
		"current": {
			"dist-tags": map[string]string{"latest": "1.0.0"},
			"versions":  map[string]any{"1.0.0": map[string]any{"license": "MIT"}},
			"time":      map[string]string{"1.0.0": old, "modified": old},
		},
		"behind": {
			"dist-tags": map[string]string{"latest": "2.5.0"},
			"versions":  map[string]any{"1.0.0": map[string]any{}, "2.5.0": map[string]any{}},
			"time":      map[string]string{"2.5.0": now, "modified": now},
		},
		"deprecated": {
			"dist-tags": map[string]string{"latest": "1.0.0"},
			"versions":  map[string]any{"1.0.0": map[string]any{"deprecated": "use foo instead"}},
			"time":      map[string]string{"1.0.0": old, "modified": old},
		},
		"yanked": {
			"dist-tags": map[string]string{"latest": "2.0.0"},
			"versions":  map[string]any{"2.0.0": map[string]any{}},
			"time":      map[string]string{"2.0.0": now, "modified": now},
		},
	})

	dir := t.TempDir()
	writeLockFixture(t, dir, &lock.Lock{Assets: []lock.Asset{
		{Name: "current", Version: "1.0.0", PURL: "pkg:npm/current@1.0.0", Path: "x", Out: "current/x"},
		{Name: "behind", Version: "1.0.0", PURL: "pkg:npm/behind@1.0.0", Path: "x", Out: "behind/x"},
		{Name: "deprecated", Version: "1.0.0", PURL: "pkg:npm/deprecated@1.0.0", Path: "x", Out: "deprecated/x"},
		{Name: "yanked", Version: "1.0.0", PURL: "pkg:npm/yanked@1.0.0", Path: "x", Out: "yanked/x"},
	}})

	reports, err := Outdated(context.Background(), OutdatedOptions{Dir: dir, RegistryURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 4 {
		t.Fatalf("reports = %d, want 4", len(reports))
	}

	byName := map[string]OutdatedReport{}
	for _, r := range reports {
		byName[r.Name] = r
	}

	if r := byName["current"]; r.Severity() != "ok" || r.Behind {
		t.Errorf("current: %+v", r)
	}
	if r := byName["behind"]; r.Severity() != "behind" || r.Latest != "2.5.0" {
		t.Errorf("behind: %+v", r)
	}
	if r := byName["behind"]; r.AgeDays != 0 {
		t.Errorf("behind.AgeDays = %d, want 0", r.AgeDays)
	}
	if r := byName["deprecated"]; r.Severity() != "deprecated" || r.Deprecated != "use foo instead" {
		t.Errorf("deprecated: %+v", r)
	}
	if r := byName["yanked"]; r.Severity() != "yanked" || !r.Yanked {
		t.Errorf("yanked: %+v", r)
	}

	if code := OutdatedExitCode(reports); code != ExitYanked {
		t.Errorf("exit code = %d, want %d (yanked dominates)", code, ExitYanked)
	}
}

// TestOutdated_LicenseChange covers the licence-drift signal: a
// package that switched from MIT to GPL-3.0-only between the locked
// version and latest flags LicenseChange=true with the normalised SPDX
// strings on both sides. Same-license-different-string (e.g. "MIT"
// vs "MIT License") does NOT trip the flag because spdx normalisation
// collapses the two.
func TestOutdated_LicenseChange(t *testing.T) {
	old := time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)
	srv := fakeOutdatedRegistry(t, map[string]map[string]any{
		"changed": {
			"dist-tags": map[string]string{"latest": "2.0.0"},
			"versions": map[string]any{
				"1.0.0": map[string]any{"license": "MIT"},
				"2.0.0": map[string]any{"license": "GPL-3.0-only"},
			},
			"time": map[string]string{"1.0.0": old, "2.0.0": old, "modified": old},
		},
		"phrased": {
			"dist-tags": map[string]string{"latest": "2.0.0"},
			"versions": map[string]any{
				"1.0.0": map[string]any{"license": "MIT License"},
				"2.0.0": map[string]any{"license": "MIT"},
			},
			"time": map[string]string{"1.0.0": old, "2.0.0": old, "modified": old},
		},
	})

	dir := t.TempDir()
	writeLockFixture(t, dir, &lock.Lock{Assets: []lock.Asset{
		{Name: "changed", Version: "1.0.0", PURL: "pkg:npm/changed@1.0.0", Path: "x", Out: "changed/x"},
		{Name: "phrased", Version: "1.0.0", PURL: "pkg:npm/phrased@1.0.0", Path: "x", Out: "phrased/x"},
	}})

	reports, err := Outdated(context.Background(), OutdatedOptions{Dir: dir, RegistryURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]OutdatedReport{}
	for _, r := range reports {
		byName[r.Name] = r
	}

	if r := byName["changed"]; !r.LicenseChange {
		t.Errorf("MIT → GPL-3.0-only should flag LicenseChange: %+v", r)
	}
	if r := byName["phrased"]; r.LicenseChange {
		t.Errorf("MIT License vs MIT should NOT flag LicenseChange after spdx normalisation: %+v", r)
	}
}

// TestOutdated_Unmaintained asserts a package whose last-publish date
// exceeds the threshold flags Unmaintained=true regardless of whether
// the locked version is also the latest.
func TestOutdated_Unmaintained(t *testing.T) {
	cold := time.Now().UTC().AddDate(-2, 0, 0).Format(time.RFC3339)
	warm := time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)
	srv := fakeOutdatedRegistry(t, map[string]map[string]any{
		"cold": {
			"dist-tags": map[string]string{"latest": "1.0.0"},
			"versions":  map[string]any{"1.0.0": map[string]any{"license": "MIT"}},
			"time":      map[string]string{"1.0.0": cold, "modified": cold},
		},
		"warm": {
			"dist-tags": map[string]string{"latest": "1.0.0"},
			"versions":  map[string]any{"1.0.0": map[string]any{"license": "MIT"}},
			"time":      map[string]string{"1.0.0": warm, "modified": warm},
		},
	})

	dir := t.TempDir()
	writeLockFixture(t, dir, &lock.Lock{Assets: []lock.Asset{
		{Name: "cold", Version: "1.0.0", PURL: "pkg:npm/cold@1.0.0", Path: "x", Out: "cold/x"},
		{Name: "warm", Version: "1.0.0", PURL: "pkg:npm/warm@1.0.0", Path: "x", Out: "warm/x"},
	}})

	reports, err := Outdated(context.Background(), OutdatedOptions{Dir: dir, RegistryURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]OutdatedReport{}
	for _, r := range reports {
		byName[r.Name] = r
	}
	if !byName["cold"].Unmaintained {
		t.Errorf("two-year-old last-publish should flag Unmaintained: %+v", byName["cold"])
	}
	if byName["warm"].Unmaintained {
		t.Errorf("30-day-old last-publish should NOT flag Unmaintained: %+v", byName["warm"])
	}
}

func TestOutdatedExitCodes(t *testing.T) {
	cases := []struct {
		reports []OutdatedReport
		want    int
	}{
		{[]OutdatedReport{}, 0},
		{[]OutdatedReport{{Behind: false}}, 0},
		{[]OutdatedReport{{Behind: true}}, ExitOutdated},
		{[]OutdatedReport{{Deprecated: "x"}}, ExitOutdated},
		{[]OutdatedReport{{Behind: true}, {Yanked: true}}, ExitYanked},
	}
	for i, tc := range cases {
		if got := OutdatedExitCode(tc.reports); got != tc.want {
			t.Errorf("[%d] = %d, want %d", i, got, tc.want)
		}
	}
}
