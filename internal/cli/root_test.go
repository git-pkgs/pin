package cli

import "testing"

func TestRoot(t *testing.T) {
	r := Root()
	if r.Use != "pin" {
		t.Errorf("Use = %q", r.Use)
	}
	if r.Version == "" {
		t.Error("Version should be set")
	}
}
