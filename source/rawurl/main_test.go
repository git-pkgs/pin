package rawurl

import (
	"os"
	"testing"

	"github.com/git-pkgs/pin/internal/safehttp"
)

func TestMain(m *testing.M) {
	safehttp.EnableLoopbackForTesting()
	os.Exit(m.Run())
}
