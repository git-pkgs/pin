package cli

import (
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	pin "github.com/git-pkgs/pin"
	"github.com/git-pkgs/pin/lock"
)

func writeVerifyLock(t *testing.T, dir, outDir string, paths ...string) {
	t.Helper()
	digest := sha512.Sum384([]byte("contents"))
	l := &lock.Lock{OutDir: outDir}
	for _, path := range paths {
		l.Assets = append(l.Assets, lock.Asset{
			Name: "demo", Version: "1.0.0", Path: "x.js", Out: path,
			Integrity: "sha384-" + base64.StdEncoding.EncodeToString(digest[:]),
		})
	}
	encoded, err := pin.EncodeLock(l)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pin.lock"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCLI_VerifyRejectsInvalidPaths(t *testing.T) {
	for _, tc := range []struct {
		name   string
		outDir string
		paths  []string
	}{
		{name: "asset-parent", outDir: "v", paths: []string{"../secret.txt"}},
		{name: "asset-absolute", outDir: "v", paths: []string{"/secret.txt"}},
		{name: "asset-empty", outDir: "v", paths: []string{""}},
		{name: "asset-dot", outDir: "v", paths: []string{"."}},
		{name: "output-parent", outDir: "../outside", paths: []string{"secret.txt"}},
		{name: "output-absolute", outDir: "/outside", paths: []string{"secret.txt"}},
		{name: "empty-assets", outDir: "../outside"},
		{name: "validate-all-first", outDir: "v", paths: []string{"directory", "../secret.txt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "project")
			for _, path := range []string{"project/v/directory", "outside"} {
				if err := os.MkdirAll(filepath.Join(base, path), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for _, path := range []string{"project/secret.txt", "outside/secret.txt"} {
				if err := os.WriteFile(filepath.Join(base, path), []byte("contents"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			writeVerifyLock(t, dir, tc.outDir, tc.paths...)
			out, err := runCmd(t, "verify", "-C", dir, "--json")
			if !errors.Is(err, pin.ErrPathEscape) {
				t.Fatalf("verify error = %v, want ErrPathEscape", err)
			}
			if out != "" {
				t.Errorf("invalid lockfile produced verification output: %s", out)
			}
		})
	}
}

func TestCLI_VerifySymlinkContainment(t *testing.T) {
	for _, tc := range []struct {
		name   string
		link   string
		target string
		out    string
		allow  bool
		empty  bool
	}{
		{name: "file-outside-project", link: "v/link", target: "../../outside/secret.txt", out: "link"},
		{name: "asset-outside-project", link: "v/link", target: "../../outside", out: "link/secret.txt"},
		{name: "asset-outside-output", link: "v/link", target: "../private", out: "link/secret.txt"},
		{name: "output-outside-project", link: "v", target: "../outside", out: "secret.txt"},
		{name: "output-empty-assets", link: "v", target: "../outside", empty: true},
		{name: "internal-output-link", link: "v", target: "private", out: "secret.txt", allow: true},
		{name: "internal-link", link: "v/link", target: "files", out: "link/secret.txt", allow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupVerifySymlink(t, tc.link, tc.target)
			paths := []string{tc.out}
			if tc.empty {
				paths = nil
			}
			writeVerifyLock(t, dir, "v", paths...)
			out, err := runCmd(t, "verify", "-C", dir, "--json")
			if tc.allow {
				if err != nil || !strings.Contains(out, tc.out) {
					t.Fatalf("internal symlink: error = %v, output = %s", err, out)
				}
			} else if err == nil || out != "" {
				t.Fatalf("escaping symlink: error = %v, output = %s", err, out)
			}
		})
	}
}

func setupVerifySymlink(t *testing.T, link, target string) string {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "project")
	for _, path := range []string{"outside", "project/private", "project/v/files"} {
		if link == "v" && path == "project/v/files" {
			continue
		}
		full := filepath.Join(base, path)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, "secret.txt"), []byte("contents"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.FromSlash(target), filepath.Join(dir, link)); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	return dir
}

func TestCLI_VerifyMissingOutputDirectory(t *testing.T) {
	dir := t.TempDir()
	writeVerifyLock(t, dir, "v", "demo/x.js")
	out, err := runCmd(t, "verify", "-C", dir)
	var exit *exitError
	if !errors.As(err, &exit) || exit.ExitCode() != exitVerifyFailed {
		t.Fatalf("verify error = %v, want missing-file exit code", err)
	}
	if !strings.Contains(out, "missing: demo/x.js") {
		t.Errorf("missing asset not reported: %s", out)
	}
}

func TestCLI_VerifyRelativeOutputDirectory(t *testing.T) {
	for _, outDir := range []string{"", ".", "./v/", "nested/vendor"} {
		t.Run(outDir, func(t *testing.T) {
			dir := t.TempDir()
			output := filepath.Join(dir, outDir)
			if err := os.MkdirAll(output, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(output, "x.js"), []byte("contents"), 0o644); err != nil {
				t.Fatal(err)
			}
			writeVerifyLock(t, dir, outDir, "x.js")
			out, err := runCmd(t, "verify", "-C", dir)
			if err != nil || !strings.HasPrefix(out, "1 ok") {
				t.Fatalf("verify error = %v, output = %s", err, out)
			}
		})
	}
}
