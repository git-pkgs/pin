package cli

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

func TestRoot(t *testing.T) {
	r := Root()
	if r.Use != "pin" {
		t.Errorf("Use = %q", r.Use)
	}
	if r.Version == "" {
		t.Error("Version should be set")
	}
}

func TestSyncInstallAlias(t *testing.T) {
	r := Root()
	var sync *cobra.Command
	for _, c := range r.Commands() {
		if c.Use == "sync" {
			sync = c
			break
		}
	}
	if sync == nil {
		t.Fatal("sync command not registered")
	}
	if !slices.Contains(sync.Aliases, "install") {
		t.Errorf("sync.Aliases = %v; want to contain \"install\"", sync.Aliases)
	}
}
