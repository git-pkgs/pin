package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// ErrUnsafeTarballEntry surfaces non-regular tar entries (symlink,
// hardlink, device, fifo). A symlink entry would extract as a
// zero-byte regular file via the standard tar reader, letting a
// publisher ship "empty bytes with valid integrity" in place of the
// claimed asset.
var ErrUnsafeTarballEntry = errors.New("tarball contains non-regular file entry")

func validateTarballEntries(tarball []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return fmt.Errorf("decompress tarball: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeDir, tar.TypeXGlobalHeader:
			continue
		default:
			return fmt.Errorf("%w: %q (typeflag=%d)", ErrUnsafeTarballEntry, header.Name, header.Typeflag)
		}
	}
}
