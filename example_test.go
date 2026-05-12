package pin_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	pin "github.com/git-pkgs/pin"
	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/pinfs"
)

// ExampleSync resolves a manifest and writes the lockfile + vendored
// files into a project directory. A real consumer would point
// RegistryURL at registry.npmjs.org; this example spins up a tiny
// in-memory registry so it can run hermetically.
func ExampleSync() {
	srv := exampleRegistry("demo", "1.0.0", map[string]string{
		"dist/demo.js": "console.log('demo')",
	})
	defer srv.Close()

	dir, err := os.MkdirTemp("", "pin-example-sync-")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	manifest := `out: "vendor"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/demo.js"]
`
	if err := os.WriteFile(filepath.Join(dir, pin.DefaultManifest), []byte(manifest), 0o644); err != nil {
		panic(err)
	}

	res, err := pin.Sync(context.Background(), pin.SyncOptions{
		Dir:         dir,
		RegistryURL: srv.URL,
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("synced %d asset\n", len(res.Lock.Assets))
	// Output: synced 1 asset
}

// ExampleSync_inMemory pipes pin's outputs into an in-memory writer
// instead of the local filesystem. Useful for build systems that
// assemble artefacts in-process, for tests, or for any consumer that
// wants the resolved bytes without touching disk. The manifest still
// has to live on disk under SyncOptions.Dir; only the writes
// (vendored files + pin.lock) are diverted.
func ExampleSync_inMemory() {
	srv := exampleRegistry("demo", "1.0.0", map[string]string{
		"dist/demo.js": "console.log('demo')",
	})
	defer srv.Close()

	dir, err := os.MkdirTemp("", "pin-example-mem-")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, pin.DefaultManifest), []byte(`out: "v"
assets:
  - name: "demo"
    version: "1.0.0"
    files: ["dist/demo.js"]
`), 0o644); err != nil {
		panic(err)
	}

	mem := pinfs.NewMemory()
	if _, err := pin.Sync(context.Background(), pin.SyncOptions{
		Dir:         dir,
		RegistryURL: srv.URL,
		FS:          mem,
	}); err != nil {
		panic(err)
	}

	js, _ := mem.Get("v/demo/demo.js")
	fmt.Println(string(js))
	_, hasLock := mem.Get("pin.lock")
	fmt.Println("lock in memory:", hasLock)
	// Output:
	// console.log('demo')
	// lock in memory: true
}

// ExampleClient shows the reusable-client path: construct once via New,
// register a custom resolver for a non-built-in purl type, then drive
// multiple operations off the same Client. The package-level pin.Sync
// shim builds a fresh Client per call; long-running consumers prefer
// this style.
func ExampleClient() {
	c := pin.New(pin.ClientOptions{
		RegistryURL: "https://registry.npmjs.org",
	})

	// Plug in a resolver for pkg:ipfs/... entries without forking pin.
	// c.RegisterResolver("ipfs", myIPFSResolver)

	fmt.Println(c.Resolver("npm") != nil)
	fmt.Println(c.Resolver("ipfs") != nil)
	// Output:
	// true
	// false
}

// ExampleInit writes a starter pin.yaml in an empty project. The
// manifest path argument is optional; passing "" picks the default.
func ExampleInit() {
	dir, err := os.MkdirTemp("", "pin-example-init-")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := pin.Init(dir, ""); err != nil {
		panic(err)
	}

	_, err = os.Stat(filepath.Join(dir, pin.DefaultManifest))
	fmt.Println(err == nil)
	// Output: true
}

// ExampleVerifyResult_Summary prints the one-line summary the CLI
// renders at the end of `pin verify`. Library consumers driving a UI
// can reuse the same string.
func ExampleVerifyResult_Summary() {
	r := &pin.VerifyResult{
		OK:      []string{"a", "b", "c"},
		Missing: []string{"d"},
		Drifted: []pin.Drift{{Out: "e"}},
	}
	fmt.Println(r.Summary())
	// Output: 3 ok, 1 missing, 1 drifted
}

// ExampleOutdatedReport_Severity collapses an OutdatedReport into a
// single label. Useful when filtering or grouping reports in a UI.
func ExampleOutdatedReport_Severity() {
	reports := []pin.OutdatedReport{
		{Name: "fine", Behind: false},
		{Name: "stale", Behind: true},
		{Name: "dropped", Yanked: true},
	}
	for _, r := range reports {
		fmt.Printf("%s: %s\n", r.Name, r.Severity())
	}
	// Output:
	// fine: ok
	// stale: behind
	// dropped: yanked
}

// ExampleOutdatedExitCode mirrors what the `pin outdated` CLI returns
// to the shell: 9 if any package is yanked, 7 if any is behind or
// deprecated, 0 otherwise.
func ExampleOutdatedExitCode() {
	reports := []pin.OutdatedReport{
		{Name: "a", Behind: true},
		{Name: "b", Yanked: true},
	}
	fmt.Println(pin.OutdatedExitCode(reports))
	// Output: 9
}

// ExampleEncodeLock serialises a Lock value to the CycloneDX-shaped
// pin.lock bytes. Useful when generating a lockfile programmatically
// without going through Sync.
func ExampleEncodeLock() {
	l := &lock.Lock{
		LockfileVersion: 1,
		OutDir:          "vendor",
		Assets: []lock.Asset{{
			Name:    "demo",
			Version: "1.0.0",
			PURL:    "pkg:npm/demo@1.0.0",
			Out:     "demo/dist/demo.js",
		}},
	}
	b, err := pin.EncodeLock(l)
	if err != nil {
		panic(err)
	}

	var top struct {
		BOMFormat string `json:"bomFormat"`
	}
	_ = json.Unmarshal(b, &top)
	fmt.Println(top.BOMFormat)
	// Output: CycloneDX
}

// exampleRegistry stands up an httptest.Server serving one
// npm-shaped package version: a single .tgz with one file inside and
// the matching version JSON. Kept in this file so the Examples above
// stay self-contained; not part of pin's public API.
func exampleRegistry(name, version string, files map[string]string) *httptest.Server {
	pj, _ := json.Marshal(map[string]any{"name": name, "version": version})
	all := map[string]string{"package.json": string(pj)}
	maps.Copy(all, files)

	var tarBuf bytes.Buffer
	gz := gzip.NewWriter(&tarBuf)
	tw := tar.NewWriter(gz)
	for p, c := range all {
		_ = tw.WriteHeader(&tar.Header{Name: "package/" + p, Mode: 0o644, Size: int64(len(c))})
		_, _ = tw.Write([]byte(c))
	}
	_ = tw.Close()
	_ = gz.Close()
	tarball := tarBuf.Bytes()

	h := sha512.Sum512(tarball)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	mux := http.NewServeMux()
	var url string
	mux.HandleFunc("/"+name+"/"+version, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":    name,
			"version": version,
			"license": "MIT",
			"dist":    map[string]any{"tarball": url + "/tarball.tgz", "integrity": integrity},
		})
	})
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball)
	})
	srv := httptest.NewServer(mux)
	url = srv.URL
	return srv
}
