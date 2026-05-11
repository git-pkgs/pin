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
