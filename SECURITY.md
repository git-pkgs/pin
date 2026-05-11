# Security model

This document lists the threats `pin` is designed to defend against,
where each defence lives in the code, and the threats that are
out of scope. The structured adversary-by-asset threat model lives in
[THREAT_MODEL.md](THREAT_MODEL.md). Lockfile schema is in `SPEC.md`.

## Threat model in one paragraph

A package author, a registry, a CDN, and the network path between them
are all potentially adversarial. The lockfile is the user's contract
with the version they once approved. `pin` exists to make that contract
verifiable: every fetched byte is anchored to a registry-published hash
or a Trust-On-First-Use hash; no code from a fetched package ever runs;
the manifest contains the full bill of materials with no transitive
resolution. The threat model is small because the feature set is small.

## Defences

### Path traversal

A malicious manifest entry could in principle smuggle `..` into the
output path. Three layers stop it:

1. `manifest.validateFilePath` rejects `files:` entries that are absolute,
   that begin with `..`, or that `path.Clean` to `..`.
2. `Entry.Slug` replaces `/` with `__` in package names and forge owners,
   so slugs cannot contain path separators.
3. `safeOut` (`sync.go`) recomputes the joined destination path, takes
   its `filepath.Rel` against the project's `out` root, and refuses to
   write if the relative path begins with `..`. Defence in depth on the
   last step before bytes hit the disk.

### Tarball decompression

- The compressed tarball is capped at `npm.DefaultMaxTarballBytes` (100 MiB)
  via `Source.fetchTarball`. Larger fetches abort before extraction.
- `github.com/git-pkgs/archives` enforces its own per-entry and per-archive
  caps during extraction, and rejects symlink and hardlink entries.
- The `package/` prefix stripping is `OpenBytesWithPrefix`, which strips
  exactly one path component; entries outside `package/` in the tarball
  are not exposed.

### Integrity bypass

There is no code path that writes a file before computing and
recording its SHA-384. For npm sources, the tarball's outer hash is
verified against the registry's `dist.integrity` before extraction;
files extracted from a tarball whose outer hash didn't match never
reach disk. For forge sources, the commit SHA is the anchor; the
per-file hash is recorded on first fetch and verified on every
subsequent fetch. For url sources, the per-file hash is recorded on
first fetch (TOFU) and verified thereafter.

### Lockfile parsing

- `lock.Read` caps input at `MaxLockfileBytes` (16 MiB) via
  `io.LimitReader`, so a malicious or truncated lockfile cannot trigger
  arbitrary memory growth.
- `lock.Read` requires `bomFormat: "CycloneDX"` and refuses any
  `pin:lockfile_version` it does not understand.
- JSON parsing uses the standard library decoder; no extension or
  alias mechanism that could blow up.

### Manifest parsing

- `manifest.Read` parses with `yaml.v3`, which does not follow YAML
  anchors / aliases unbounded (no billion-laughs).
- Unknown fields at the asset-entry level are rejected so a typo
  doesn't silently disable a validation rule. Unknown top-level keys
  are tolerated for forward compatibility with future versions of the
  spec.

### Network

- HTTP fetches go through `github.com/git-pkgs/registries/client`,
  which sets a 30-second timeout, retries on 429 and 5xx with
  exponential backoff and jitter, and (via `registries/fetch`)
  caches DNS for 5 minutes and implements a per-host circuit breaker.
- TLS verification is on by default; there is no flag to disable it.
- HTTP redirects are followed by the standard library client, capped
  at 10 redirects by default.

### Code execution

`pin` never runs code from a fetched package. There are no install
scripts, no lifecycle hooks, no plugin loaders. The tool operates only
in stages 1–4 of the package-installation model (fetch metadata,
resolve, download, unpack); stages 5 (build) and 6 (post-install) are
absent by design. This eliminates an entire class of supply-chain
attacks that target stages 5–6, including the post-install download
leak where a package's real payload arrives via a `postinstall` hook.

### Reproducibility

- The release binary is built with `-trimpath` and `CGO_ENABLED=0`,
  with `mod_timestamp` set to the commit timestamp.
- Goreleaser signs the checksum file with cosign keyless on every
  release; consumers verify with `cosign verify-blob` or
  `gh attestation verify`.
- The released archives include syft-generated SBOMs.

## Defences planned but not yet shipped

- **npm signature verification** (M2 deferred). npm publishes Ed25519
  signatures over `{name}@{version}:{integrity}` for many recent
  versions; `pin` does not yet verify these. The tarball hash is still
  anchored against `dist.integrity`, so a registry-side attacker can't
  substitute bytes without invalidating the lockfile, but the registry
  itself could substitute the metadata. Signature verification closes
  that hole.
- **Provenance attestations** (v0.2). npm publishes `dist.attestations`
  for packages built in CI; `pin` will record the attestation
  pointers in the lockfile and add a `--strict-provenance` flag that
  fails when a pinned version has no attestation. See SPEC.md
  "Reserved fields".
- **Cooldown** (v0.2). Most malicious npm versions are caught within
  24–48 hours. A default-on `min_release_age` window blocks the
  majority of fresh-publish supply-chain attacks at the cost of a
  bounded lag on bleeding-edge releases.

## Out of scope

- **Sandboxing.** `pin` writes files to disk that the consuming web
  server later serves to browsers. The defences above ensure the
  bytes match what was published; they do not ensure the bytes are
  free of bugs or backdoors that the publisher introduced. A vendored
  htmx with a backdoor in v2.0.6 will still backdoor your users.
- **Private registries.** v0.1 does not support authenticated
  registries. Use the `pkg:npm/foo?repository_url=...` purl qualifier
  pattern when v0.2 lands.
- **DNS rebinding** between metadata fetch and tarball fetch. The HTTP
  client reuses connections within a session, which mitigates this in
  practice, but the explicit defence (pinning to a resolved IP
  across a single resolve) is out of scope.
- **Resource exhaustion via huge file counts.** A manifest with
  ten thousand entries will issue ten thousand resolves. The shape
  is unusual enough that we don't defend against it.

## Reporting

Please email security issues privately to the maintainer rather than
opening a public issue. A public GitHub issue with `[SECURITY]` in
the title is also acceptable for non-critical findings.
