# pin

Browser asset vendoring without npm. A single static binary that fetches files from published packages, anchors their integrity to the registry tarball, commits them to your repo, and writes a lockfile that is also a valid CycloneDX SBOM.

If your server-rendered app needs htmx, a CSS kit, and an icon set, the honest dependency count is three. Running `npm install` for them gives you a `node_modules` with hundreds of transitive packages, a lockfile format you don't otherwise use, a Node runtime in CI, and arbitrary code execution on every install via lifecycle hooks. `pin` fetches exactly the files you name, from exactly the versions you pin, hashes them against what npm published, and writes them to disk. Nothing executes. There is no dependency tree because there are no transitive dependencies: the manifest is the bill of materials.

## Install

```
go install github.com/git-pkgs/pin/cmd/pin@latest
```

Or grab a binary from the releases page once tagged.

## Quickstart

Write `pin.yaml`:

```yaml
out: "internal/web/static/vendor"

assets:
  - name: "htmx.org"
    version: "^2.0"
    files: ["dist/htmx.min.js"]

  - name: "@tailwindcss/browser"
    version: "4.1.13"

  - name: "lucide"
    version: "^0.545"
    files: ["dist/umd/lucide.min.js"]
```

Run `pin sync`. You get:

```
internal/web/static/vendor/
  htmx.org/htmx.min.js
  tailwindcss__browser/index.global.js
  lucide/lucide.min.js
pin.lock
```

The version field accepts exact pins (`2.0.6`), semver ranges (`^2.0`, `~0.3.11`), or npm dist-tags (`latest`, `next`). Once a version is locked, it stays locked: `pin sync` re-uses the locked version as long as the manifest constraint still allows it. `pin update` is what bumps things forward.

When `files:` is omitted, `pin` reads the package's `package.json` and picks the entry point from `jsdelivr || unpkg || browser || module || main`.

## Commands

```
pin sync                resolve manifest, fetch assets, write lockfile
pin sync --frozen       fail before any network if manifest and lockfile disagree (CI)
pin sync --dry-run      resolve and report, write nothing
pin update [NAME...]    re-resolve to highest satisfying version, ignoring the lock
pin verify              re-hash files on disk against the lockfile (exit 4 on drift)
pin outdated            compare locked versions against the registry's latest
pin add NAME[@SPEC]     append to the manifest at alphabetic position and sync
```

## Lockfile

`pin.lock` is a valid CycloneDX 1.6 SBOM. Each package becomes a `library` component with the registry tarball hash; each vendored file becomes a nested `file` component with its own SHA-384, the CDN URL, and pin-specific metadata under a `pin:` property namespace. Any CycloneDX consumer (Dependency-Track, GUAC, OSV-scanner, `git-pkgs sbom`) reads it directly. `serialNumber` and `metadata.timestamp` are deliberately omitted so re-runs are byte-stable and parallel branches don't conflict on the file.

## Integrity

On first sync of a package version, `pin` fetches the registry metadata, downloads the published tarball, verifies it against npm's `dist.integrity`, extracts the requested files, and computes a SHA-384 over each one. Subsequent syncs of the same version verify against the recorded hash. The CDN is a transport, not a source of truth.

## What doesn't work

`pin` is for self-contained distributables: UMD bundles, IIFE builds, ESM modules with no bare-specifier imports, CSS files. It does not work for packages that expect a module graph at runtime, and it does not run install scripts. If a package's real payload arrives via a `postinstall` hook (a platform binary downloaded after the tarball lands) `pin` will vendor only the stub. Point `files:` at the package's pre-bundled CDN distribution if it ships one; if it doesn't ship one and depends on a bundler or `postinstall` to assemble itself, it's out of scope.

## As a Go library

The CLI is a thin shim over the importable module:

```go
import "github.com/git-pkgs/pin"

res, err := pin.Sync(ctx, pin.SyncOptions{Dir: "."})
```

`pin.Sync`, `pin.Verify`, `pin.Outdated`, `pin.Add` and the `manifest` / `lock` / `source/npm` sub-packages are all public.

## License

MIT
