# pin

Browser asset vendoring without npm. A single static binary that fetches files from published packages, anchors their integrity to the registry tarball, commits them to your repo, and writes a lockfile that is also a valid CycloneDX SBOM.

If your server-rendered app needs htmx, a CSS kit, and an icon set, the honest dependency count is three. Running `npm install` for them gives you a `node_modules` with hundreds of transitive packages, a lockfile format you don't otherwise use, a Node runtime in CI, and arbitrary code execution on every install via lifecycle hooks. `pin` fetches exactly the files you name, from exactly the versions you pin, hashes them against what npm published, and writes them to disk. Nothing executes. There is no dependency tree because there are no transitive dependencies: the manifest is the bill of materials.

## Install

Homebrew:

```
brew tap git-pkgs/git-pkgs
brew install pin
```

Go:

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

  - name: "highlight.js"
    version: "11.11.1"
    source: "github:highlightjs/cdn-release"
    files:
      - "build/highlight.min.js"
      - "build/styles/github.min.css"
```

Run `pin sync`. You get:

```
internal/web/static/vendor/
  htmx.org/htmx.min.js
  tailwindcss__browser/index.global.js
  lucide/lucide.min.js
  highlightjs__cdn-release/highlight.min.js
  highlightjs__cdn-release/github.min.css
pin.lock
```

The version field accepts exact pins (`2.0.6`), semver ranges (`^2.0`, `~0.3.11`), or npm dist-tags (`latest`, `next`). Once a version is locked, it stays locked: `pin sync` re-uses the locked version as long as the manifest constraint still allows it. `pin update` bumps things forward.

When `files:` is omitted for an npm source, `pin` reads the package's `package.json` and picks the entry point from `jsdelivr || unpkg || browser || module || main`.

## Source kinds

```yaml
- name: "htmx.org"                       # npm (default)
  version: "^2.0"

- name: "highlight.js"                   # GitHub release
  version: "11.11.1"
  source: "github:highlightjs/cdn-release"
  files: ["build/highlight.min.js"]

- name: "my-asset"                       # Raw URL (TOFU)
  version: "1.0.0"
  source: "url:https://example.com/dist/asset.js"
```

`github:` sources resolve the tag to a commit SHA, fetch via jsdelivr's `/gh/` mirror, and record the SHA in the lockfile as the integrity anchor. `url:` sources hash the bytes on first fetch and verify against the recorded hash on every subsequent sync. Both go through the same `source.Resolver` interface, so adding gitlab/codeberg/bitbucket later is a single new file.

## Commands

```
pin sync                       resolve manifest, fetch assets, write lockfile
pin sync --frozen              fail before any network if manifest and lockfile disagree (CI)
pin sync --no-fetch            --frozen plus re-hash on-disk files against the lockfile; no network, no writes
pin sync --concurrency=N       cap parallel resolves (default 8)
pin sync --dry-run [--json]    resolve and report, write nothing
pin update [NAME...]           re-resolve to highest satisfying version, ignoring the lock
pin verify [--strict] [--json] re-hash files on disk against the lockfile (exit 4 on drift)
pin outdated [--json]          compare locked versions against the registry's latest
pin add NAME[@SPEC] [FILE...]  append to the manifest at alphabetic position and sync
pin rm NAME...                 remove entries from the manifest and sync
pin list [--json]              print the lockfile contents
pin path NAME                  print the on-disk paths for a locked package
pin init                       write a starter pin.yaml in the current directory
pin sbom [-f spdx|cyclonedx-xml] [-o FILE]  emit the lockfile as an SBOM
```

`pin sync` prints a one-line stderr nudge when it detects a CI environment (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `CIRCLECI`, `JENKINS_URL`) and `--frozen` is not set.

## Safe defaults

The cooldown window (`min_release_age`) is on by default at 48 hours. Most malicious npm versions are caught within 24 to 48 hours, and the window blocks the majority of fresh-publish supply-chain attacks. Ranges fall back to the next-highest satisfying version outside the window; dist-tags fail with a clear error if `latest` is too fresh; exact pins bypass the window because you named the version explicitly. Opt out with `min_release_age: 0` at the manifest top level or per entry.

`--frozen` is the single CI safety flag: it bails before any network if the manifest and lockfile disagree. `--no-fetch` adds a re-hash of every vendored file against the lockfile's recorded integrity on top of `--frozen` — designed for CI jobs that vendored at image-build time and want to assert nothing was tampered with after `git checkout`, with no network and no writes.

`pin sync` rewrites the lockfile only when the manifest changed; identical bytes skip the write. The tool runs no code from a fetched package: no install scripts, no hooks, no plugin loaders. Stages 5 and 6 of [The Stages of Package Installation](https://nesbitt.io/2026/04/27/the-stages-of-package-installation.html) are absent by design.

## Provenance and trusted publishing

For npm and GitHub forge sources, when the publisher used trusted publishing, `pin sync` records the SLSA Provenance v1 attestation in the lockfile: `builder_id` (the CI workflow URI), `source_repository`, `source_revision`, `signer_identity` (the OIDC SAN), and the bundle URL.

Three opt-in flags layer the trust assertion:

```
pin sync --strict-provenance
   fail if any entry resolves to a version with no attestation.

pin sync --require-publisher-matches-repository
   fail if an attestation's source repository differs from the package's declared
   repository.url. This is the load-bearing check against leaked-token attacks:
   an attacker with a stolen publish token can produce a syntactically valid
   bundle from their own CI, but the source_repository field will not match.

pin sync --verify-provenance
   cryptographically verify the sigstore bundle against the live Sigstore TUF
   trust root: Fulcio cert chain, Rekor inclusion proof, DSSE signature,
   subject digest matches the fetched artifact. Composes with the other two.
   Trust root is cached at $XDG_CACHE_HOME/pin/sigstore-tuf/ after first use.

pin sync --signature-mode {warn|enforce|off}
   verify npm dist.signatures (ECDSA P-256 over {name}@{version}:{integrity},
   keys fetched from /-/npm/v1/keys). warn (default) fails on bad sigs but
   tolerates absent ones; enforce additionally fails on absent.
```

The flags are per-invocation. The persistent form is a manifest `trust:` block, top-level or per-entry:

```yaml
trust:
  require_provenance: true
  require_publisher_matches_repository: true
  trusted_workflows:
    - https://github.com/builder-org/builder/.github/workflows/release.yml

assets:
  - name: monorepo-pkg
    version: ^1.0.0
    trust:
      require_publisher_matches_repository: false   # entry-level override
```

`trusted_workflows` is the escape hatch for monorepo packages whose legitimate build workflow lives on a different repo than the package's declared `repository.url`. CLI flags always win over manifest entries: `--strict-provenance` forces the check even on an entry that opted out.

`pin outdated` flags a `provenance-downgrade` severity (above deprecated, below yanked) when the locked version had an attestation and the latest doesn't. That's the signal that trusted publishing was switched off by the maintainer or by whoever now controls the publish token.

## Lockfile

`pin.lock` is a valid CycloneDX 1.6 SBOM. Each package becomes a `library` component with the registry tarball hash; each vendored file becomes a nested `file` component with its own SHA-384, the CDN URL, and pin-specific metadata under a `pin:` property namespace. Any CycloneDX consumer (Dependency-Track, GUAC, OSV-scanner, `git-pkgs sbom`) reads it directly. `serialNumber` and `metadata.timestamp` are deliberately omitted so re-runs are byte-stable and parallel branches don't conflict on the file.

Schema is documented normatively in [docs/SPEC.md](docs/SPEC.md). Defences are in [docs/SECURITY.md](docs/SECURITY.md); the structured adversary-by-asset model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Integrity

On first sync of an npm package version, `pin` fetches the registry metadata, downloads the published tarball, verifies it against npm's `dist.integrity`, extracts the requested files, and computes a SHA-384 over each one. Subsequent syncs of the same version verify against the recorded hash. The CDN is a transport, not a source of truth.

For `github:` sources, the commit SHA is the anchor and is recorded as a `SHA-1` hash on the library component plus a `vcs_revision` qualifier on the purl. For `url:` sources, the per-file SHA-384 is the anchor (Trust-On-First-Use).

## Format sniffing

For each vendored script, `pin` detects the module format (`esm`, `umd`, `iife`, `cjs`, `amd`, `system`, or `unknown`) by scanning the bytes with a comment- and string-aware regex pass. The result lands in the lockfile's `pin:format` property so importmap consumers can filter to ESM entries. Override per-entry with `format:` in the manifest.

## What doesn't work

`pin` is for self-contained distributables: UMD bundles, IIFE builds, ESM modules with no bare-specifier imports, CSS files. It does not work for packages that expect a module graph at runtime, and it does not run install scripts. If a package's real payload arrives via a `postinstall` hook (a platform binary downloaded after the tarball lands) `pin` will vendor only the stub. Point `files:` at the package's pre-bundled CDN distribution if it ships one; if it doesn't ship one and depends on a bundler or `postinstall` to assemble itself, it's out of scope.

## As a Go library

The CLI is a thin shim over the importable module:

```go
import "github.com/git-pkgs/pin"

res, err := pin.Sync(ctx, pin.SyncOptions{Dir: "."})
```

`pin.Sync`, `pin.Update` (via `SyncOptions.UpdateAll`), `pin.Verify`, `pin.Outdated`, `pin.Add`, `pin.Remove`, `pin.List`, `pin.Path`, `pin.Init`, `pin.SBOM`, plus the `manifest`, `lock`, `integrity`, `cdn`, `sniff`, `source` (with `source/npm`, `source/forge`, `source/rawurl`), and `assets` sub-packages are all public.

The `assets` package is the runtime helper a Go web app uses to consume `pin`'s output: parse the lockfile, serve the vendored files via `fs.FS`, and emit HTML tags with `integrity` and `crossorigin` attributes from a template.

## License

MIT
