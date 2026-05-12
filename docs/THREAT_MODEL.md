# Threat model

Companion to [`../SECURITY.md`](../SECURITY.md). `SECURITY.md` documents the defences `pin` ships; this file documents the adversaries those defences exist to stop, the assets they want, and how each plausible attack maps onto a defence. Informed by [Package Manager Threat Models](https://nesbitt.io/2026/05/05/package-manager-threat-models.html) and [Package Manager CWEs](https://nesbitt.io/2026/05/04/package-manager-cwes.html).

## Trust boundaries

The boundaries that matter, from least to most trusted:

1. **The public internet.** Untrusted. Any byte arriving over HTTPS could be substituted.
2. **CDNs (jsdelivr, unpkg).** Untrusted as a source of truth. Useful as a transport. Bytes are verified against the registry tarball before they land.
3. **The npm registry.** Partially trusted. We trust it for the *integrity claim* (`dist.integrity`) but verify the tarball against it. We trust it less for *provenance* — anyone who controls a publish token can put bytes there.
4. **Sigstore TUF root.** Trusted as the verification anchor for provenance. Refreshed on a cadence.
5. **The user's `pin.yaml`.** Trusted as a statement of intent. The user is responsible for choosing which packages to depend on.
6. **The user's `pin.lock`.** Trusted as the record of what was actually fetched and verified. Committed to the user's repository; tampering with it is a separate problem (handled by version control, code review, branch protection).
7. **The `pin` binary itself.** Trusted at the point of execution. The release pipeline produces a cosign-signed binary; users verify out-of-band.

## Adversaries

The kinds of actor whose actions we want to detect, prevent, or limit damage from. The same person can play multiple roles.

| Actor | Capability |
|---|---|
| **Network attacker** | Active MITM on HTTPS connections to the registry or CDN. |
| **Compromised CDN** | Controls the bytes returned for a given CDN URL but not the registry. |
| **Compromised registry** | Controls everything at `registry.npmjs.org`: tarballs, metadata, integrity fields, signatures, dist-tags. |
| **Malicious package author** | Has legitimate publishing rights for a package the user opted into. Can ship arbitrary code in their published tarballs. |
| **Leaked-token attacker** | Has obtained a publish token (npm API token, OIDC abuse, supply-chain compromise of CI). Can publish new versions of a package they don't own. |
| **Typosquatter** | Publishes a similarly-named package and hopes the user adds it by mistake. |
| **Insider with repo write** | Can edit `pin.yaml`, `pin.lock`, or the vendored files in the consumer's repository. |

## Threats and mitigations

Each row is one plausible attack. "Mitigation" is what `pin` does today; "Residual" is what's left unaddressed.

### Integrity and substitution

| Threat | Mitigation | Residual |
|---|---|---|
| Network attacker substitutes tarball bytes in flight | TLS + `dist.integrity` verification before extraction | TLS-pinning not enforced; relies on the system trust store |
| CDN serves different bytes than the npm tarball | `pin` fetches from the npm tarball directly, not the CDN, for the byte-of-record. CDN URL is recorded as metadata only. | None for the v0.1 fetch path |
| Registry rewrites `dist.integrity` for an already-published version | First sync records `dist.integrity` in the lockfile; subsequent syncs verify against the recorded value. A drifted integrity field surfaces as a mismatch. | First sync of a freshly compromised version trusts the registry. Mitigated by cooldown (M2) and `--verify-provenance` (M19) |
| Local vendored file modified post-sync | `pin verify` re-hashes against the lockfile, exit 4 on drift | None |
| Lockfile JSON resource exhaustion (DoS) | `lock.Read` caps input at 16 MiB via `io.LimitReader` | None |
| Tarball decompression bomb | 100 MiB compressed cap in `npm.fetchTarball`; `archives` enforces per-entry and total uncompressed caps | None |
| Symlink / hardlink escape from tarball | `archives` rejects both | Not asserted by a pin-side fixture (M23 follow-up) |
| Path traversal via manifest `files:` | `manifest.validateFilePath` rejects absolute paths and `..`; `Entry.Slug` sanitises forge owner/repo and `@scope/pkg` to `__` | Defence in depth: `safeOut` recomputes the joined path with `filepath.Rel` against the out root before any byte hits the disk |
| SSRF: registry redirects to internal services, or a `url:` manifest names `http://localhost`, RFC1918, CGNAT, or link-local | `internal/safehttp` validates every resolved IP before dial and rejects all of those ranges. DNS is resolved once and the connection dials the IP directly, so a rebind between resolve and connect cannot escape the gate. | None |
| Exfiltration via redirect to `file://` / `gopher://` / `data://` | `internal/safehttp` `CheckRedirect` rejects non-`http(s)` schemes; redirect chain capped at 10 with each hop revalidated against the dial gate | None |

### Trust and provenance

| Threat | Mitigation | Residual |
|---|---|---|
| Leaked-token attacker publishes a forged version with valid sigstore bundle from their own CI | `--require-publisher-matches-repository` rejects when the attestation's `builder_id` repo differs from the package's `repository.url` | Requires the user to opt in to the flag (default off in v0.2) |
| Maintainer disables trusted publishing on a previously-attested package | `outdated` reports `provenance-downgrade` severity (above deprecated, below yanked) | Surfaces in `outdated`, not at sync time. Promote to a `sync` error in v0.3? |
| Compromised registry serves a forged sigstore bundle | `--verify-provenance` validates the bundle against Sigstore's TUF trust root (Fulcio cert chain, Rekor inclusion proof, DSSE signature, subject digest matches the fetched tarball) | Requires the user to opt in (default off). Local TUF root cache is a follow-up so verification isn't a per-sync network call. |
| Compromised registry rotates Ed25519 signing keys to one it controls | `--verify-provenance` covers the sigstore path. `dist.signatures` (the older Ed25519 signal) is not yet verified by `pin` — M2 follow-up. | Pending until npm Ed25519 verification ships |
| Typosquat: user adds `lodahs` thinking it's `lodash` | None at `pin add` time (the user typed the name). The lockfile's purl is the record. | Out of scope for v0.1. A "did you mean" preflight would need a popularity / similarity service. |

### Fresh-publish supply chain

| Threat | Mitigation | Residual |
|---|---|---|
| Malicious version published, retracted within 24-48h | `min_release_age` defaults to 48h. Ranges and dist-tags skip versions inside the window; exact pins bypass (the user named the version). See [Package managers need to cool down](https://nesbitt.io/2026/03/04/package-managers-need-to-cool-down.html). | Exact pins are an opt-in to the fresh-publish risk |
| Dist-tag (`latest`) moves to a freshly-published malicious version under a stable manifest range | `IsSticky` returns false for dist-tags, so they always re-resolve. Cooldown catches the new version if it's within the window. | After the window expires, the dist-tag is followed without further checks |

### Install-time execution (the npm threat model)

| Threat | Mitigation | Residual |
|---|---|---|
| Lifecycle scripts (`preinstall`, `install`, `postinstall`) run arbitrary code | Not invoked. `pin` operates only in stages 1-4 of [The Stages of Package Installation](https://nesbitt.io/2026/04/27/the-stages-of-package-installation.html). | If a package relies on `postinstall` to download its real payload, `pin` vendors only the stub. Documented in README "What doesn't work". |
| Native build (`gyp`, Cargo, etc.) runs during install | Not invoked. | Same as above. |
| `npx`-style "run latest unpinned code" | `pin` has no equivalent. The only resolved-version path is `sync`, which always pins. | None |

### CI and developer workflow

| Threat | Mitigation | Residual |
|---|---|---|
| CI silently re-resolves a stale lockfile | `--frozen` fails fast before any network when manifest and lockfile disagree. `pin sync` prints a stderr nudge when it detects a CI environment without `--frozen`. | User has to actually set `--frozen` (the nudge is just discoverable). |
| Developer's `pin sync` rewrites the lockfile without their intent | `sync` only rewrites when the manifest changed (lock-is-sticky). Idempotent runs skip the write entirely. | None |
| Insider with repo write swaps the lockfile to point at a different version | Caught by `pin verify` against the on-disk bytes — if the swap is just a version bump, the recomputed SHA-384 will differ. | Detecting that the swap *happened* is git history's job, not `pin`'s. |

### Tool itself

| Threat | Mitigation | Residual |
|---|---|---|
| Compromised `pin` binary | goreleaser signs releases with cosign keyless. Users verify with `gh attestation verify` or `cosign verify-blob`. Reproducible builds (`-trimpath`, `CGO_ENABLED=0`, mod_timestamp from commit). | Users have to actually verify. |
| Vulnerability in a `pin` dependency | `govulncheck` runs in CI. Dependency graph is small (registries, archives, vers, purl, sbom, spdx, sigstore-go, cobra, yaml.v3). | Patch cadence depends on the maintainer noticing. capcheck baseline (planned, M23 follow-up) would flag new privileged-operation acquisitions in deps. |
| Telemetry / phone-home | None. `pin` makes no network calls except those required to fetch resolution metadata, tarballs, and (on opt-in) provenance bundles. | None |

## Out of scope

- **Sandboxing the vendored files.** `pin` ensures the bytes match what was published; it does not ensure the bytes are free of bugs or backdoors the publisher introduced. A vendored htmx with a backdoor in v2.0.6 will still backdoor your users.
- **Authenticated registries.** v0.1 does not support `~/.npmrc`-shaped auth. Public registries only.
- **Resource exhaustion via huge manifest entry counts.** A manifest with ten thousand entries will issue ten thousand resolves. Unusual enough that we don't defend.

## Mapping to CWE classes

Selected entries from the [package-manager CWE catalogue](https://nesbitt.io/2026/05/04/package-manager-cwes.html), with the corresponding `pin` defence:

- **CWE-345 Insufficient Verification of Data Authenticity** — `dist.integrity` verification on every fetch.
- **CWE-494 Download of Code Without Integrity Check** — Same; no code path writes a file before its hash is computed and compared.
- **CWE-22 Path Traversal** — `validateFilePath` + slug sanitisation + `safeOut`.
- **CWE-409 Resource Exhaustion via Decompression** — 100 MiB tarball cap; `archives` enforces uncompressed caps.
- **CWE-829 Inclusion of Functionality from Untrusted Control Sphere** — No lifecycle scripts, no plugin loading, no dynamic registration.
- **CWE-77 Command Injection (during install)** — Not applicable; `pin` does not invoke commands during sync.
- **CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes** — Manifest is strict at the entry level (unknown fields rejected) and tolerant only at the top level for forward-compat.

## Reporting

Email security issues privately to the maintainer rather than opening a public issue. `[SECURITY]` in a GitHub issue title is also acceptable for non-critical findings.
