// A worked example of consuming pin as a Go library rather than via
// the CLI. Constructs a pin.Client once, then runs Sync and Verify
// against a project directory. The client reuses one HTTP connection
// pool across operations — useful for long-lived processes (the Rails
// gem, a CI service, a custom integrator).
//
// Run with: go run ./examples/library-consumer -dir ./examples/server-rendered-go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/git-pkgs/pin"
)

func main() {
	dir := flag.String("dir", ".", "project directory containing pin.yaml")
	flag.Parse()

	// One Client per process. ClientOptions carries the things you'd
	// want to set once: registry URL, signature mode, an optional
	// ProvenanceVerifier (sigstore-go in production). Zero values give
	// the same defaults the CLI uses.
	c := pin.New(pin.ClientOptions{})

	// Sync.
	res, err := c.Sync(context.Background(), pin.SyncOptions{Dir: *dir})
	if err != nil {
		log.Fatalf("sync: %v", err)
	}
	fmt.Printf("synced %d files\n", len(res.Written))

	// Verify the bytes on disk match the lockfile.
	vr, err := c.Verify(pin.VerifyOptions{Dir: *dir})
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Println(vr.Summary())
	if vr.Failed() {
		os.Exit(1)
	}
}
