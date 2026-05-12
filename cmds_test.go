package pin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInit(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, ""); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, DefaultManifest))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `out:`) {
		t.Errorf("init template missing out:\n%s", got)
	}
	if err := Init(dir, ""); err == nil {
		t.Fatal("Init should fail when manifest already exists")
	}
}

func TestRemove(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"dist/a.js": "a"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/a.js"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}

	res, err := Remove(context.Background(), []string{"demo"}, SyncOptions{Dir: dir, RegistryURL: srv.URL})
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(res.Removed) != 1 {
		t.Errorf("Removed = %v, want one entry", res.Removed)
	}
	got, _ := os.ReadFile(filepath.Join(dir, DefaultManifest))
	if strings.Contains(string(got), "name: \"demo\"") {
		t.Errorf("manifest still contains demo:\n%s", got)
	}
}

func TestRemove_DryRun(t *testing.T) {
	srv := fakeNPM(t, "demo", "1.0.0", map[string]string{"dist/a.js": "a"})
	dir := t.TempDir()
	writeManifest(t, dir, `out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/a.js"]
`)
	if _, err := Sync(context.Background(), SyncOptions{Dir: dir, RegistryURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	originalManifest, _ := os.ReadFile(filepath.Join(dir, DefaultManifest))

	if _, err := Remove(context.Background(), []string{"demo"}, SyncOptions{Dir: dir, DryRun: true}); err != nil {
		t.Fatalf("Remove --dry-run: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, DefaultManifest))
	if string(originalManifest) != string(after) {
		t.Error("--dry-run modified the manifest")
	}
}

func TestListAndPath(t *testing.T) {
	dir, _ := setupSynced(t)

	entries, err := List(VerifyOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("List = %d, want 2", len(entries))
	}
	for _, e := range entries {
		if e.Name != "demo" || e.Version != "1.0.0" {
			t.Errorf("entry = %+v", e)
		}
		if e.Integrity == "" || e.Size == 0 {
			t.Errorf("entry missing integrity/size: %+v", e)
		}
	}

	paths, err := Path("demo", VerifyOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Errorf("Path returned %d, want 2", len(paths))
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("path %s does not exist", p)
		}
	}

	if _, err := Path("nope", VerifyOptions{Dir: dir}); err == nil {
		t.Fatal("Path on unknown package should error")
	}
}
