package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/git-pkgs/registries/client"
)

// makeTarball builds a gzipped tarball with arbitrary headers. Used
// by the rejection tests to forge tarballs that npm would reject on
// publish but a malicious publisher could still craft.
func makeTarball(t *testing.T, entries []tar.Header, bodies map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		hCopy := h
		if body, ok := bodies[h.Name]; ok {
			hCopy.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&hCopy); err != nil {
			t.Fatal(err)
		}
		if body, ok := bodies[h.Name]; ok {
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestValidateTarballEntries_AcceptsRegularAndDir(t *testing.T) {
	pj := []byte(`{"name":"demo","version":"1.0.0"}`)
	tarball := makeTarball(t, []tar.Header{
		{Name: "package/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "package/package.json", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "package/dist/x.js", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string][]byte{
		"package/package.json": pj,
		"package/dist/x.js":    []byte("x"),
	})
	if err := validateTarballEntries(tarball); err != nil {
		t.Errorf("regular+dir tarball should pass: %v", err)
	}
}

func TestValidateTarballEntries_RejectsSymlink(t *testing.T) {
	tarball := makeTarball(t, []tar.Header{
		{Name: "package/dist/x.js", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o644},
	}, nil)
	err := validateTarballEntries(tarball)
	if !errors.Is(err, ErrUnsafeTarballEntry) {
		t.Errorf("err = %v; want errors.Is(ErrUnsafeTarballEntry)", err)
	}
}

func TestValidateTarballEntries_RejectsHardlink(t *testing.T) {
	tarball := makeTarball(t, []tar.Header{
		{Name: "package/dist/x.js", Typeflag: tar.TypeLink, Linkname: "package/elsewhere", Mode: 0o644},
	}, nil)
	err := validateTarballEntries(tarball)
	if !errors.Is(err, ErrUnsafeTarballEntry) {
		t.Errorf("err = %v; want errors.Is(ErrUnsafeTarballEntry)", err)
	}
}

func TestValidateTarballEntries_RejectsDevice(t *testing.T) {
	cases := []struct {
		name string
		flag byte
	}{
		{"char-device", tar.TypeChar},
		{"block-device", tar.TypeBlock},
		{"fifo", tar.TypeFifo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tarball := makeTarball(t, []tar.Header{
				{Name: "package/dist/x.js", Typeflag: c.flag, Mode: 0o644},
			}, nil)
			err := validateTarballEntries(tarball)
			if !errors.Is(err, ErrUnsafeTarballEntry) {
				t.Errorf("%s: err = %v; want errors.Is(ErrUnsafeTarballEntry)", c.name, err)
			}
		})
	}
}

func TestSource_RejectsSymlinkTarball(t *testing.T) {
	// A registry response carrying a tarball whose package/dist/x.js
	// entry is a symlink to /etc/passwd, signed (via integrity) by
	// the registry. Pin must refuse before any byte hits the
	// consumer's filesystem.
	pj := []byte(`{"name":"demo","version":"1.0.0"}`)
	tarball := makeTarball(t, []tar.Header{
		{Name: "package/package.json", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "package/dist/x.js", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o644},
	}, map[string][]byte{"package/package.json": pj})

	h := sha512.Sum512(tarball)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/demo/1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":    "demo",
			"version": "1.0.0",
			"dist":    map[string]any{"tarball": srvURL + "/tarball.tgz", "integrity": integrity},
		})
	})
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball)
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	defer srv.Close()

	s := New(Options{
		RegistryURL: srv.URL,
		HTTPClient:  client.NewClient(),
	})
	_, err := s.Resolve(context.Background(), npmPURL("demo", "1.0.0"), []string{"dist/x.js"})
	if !errors.Is(err, ErrUnsafeTarballEntry) {
		t.Errorf("Resolve err = %v; want errors.Is(ErrUnsafeTarballEntry)", err)
	}
}
