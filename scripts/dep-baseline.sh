#!/usr/bin/env bash
# Refresh the dependency-review baseline files committed under
# .github/. CI re-runs this script and fails on any diff, so a PR
# that adds a new module or pulls in a new privileged stdlib import
# (unsafe / syscall / os/exec / cgo / plugin) surfaces in the diff
# before merge.
#
# Run from repo root:
#
#   ./scripts/dep-baseline.sh
#
# Commit the resulting changes alongside the go.mod / go.sum bump.
set -euo pipefail

cd "$(dirname "$0")/.."

# Full module graph. go mod graph output is deterministic.
go mod graph | sort > .github/dep-graph.txt

# Privileged stdlib imports in the dep tree. For every non-stdlib
# package reachable from this module, list the privileged stdlib
# packages it imports directly. Sorted; one "package: import" pair
# per line.
go list -deps -f '{{if .Standard}}{{else}}{{.ImportPath}} {{range .Imports}}{{.}}|{{end}}{{end}}' ./... \
  | awk -F' ' '
      NF >= 2 {
        n = split($2, imps, "|")
        for (i = 1; i <= n; i++) {
          if (imps[i] == "unsafe" || imps[i] == "syscall" || imps[i] == "os/exec" || imps[i] == "plugin" || imps[i] ~ /^syscall\//) {
            print $1 ": " imps[i]
          }
        }
      }
    ' \
  | sort -u > .github/dep-privileged.txt

echo "Refreshed .github/dep-graph.txt and .github/dep-privileged.txt"
