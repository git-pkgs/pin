package npm

import (
	"os"
	"testing"

	"github.com/git-pkgs/registries/safehttp"
)

func TestMain(m *testing.M) {
	safehttp.EnableLoopbackForTesting()
	os.Exit(m.Run())
}
