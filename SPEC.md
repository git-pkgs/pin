# pin.lock specification

`pin.lock` is a [CycloneDX 1.6][cdx] JSON SBOM with a small set of pin-specific
properties under the `pin:` namespace. This document is normative for the
schema. The pin CLI is one implementation; another tool that produces or
consumes `pin.lock` should be able to do so by reading this spec without
reading any code.

[cdx]: https://cyclonedx.org/specification/overview/

Schema version: **1**.

## Top-level

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": { ... },
  "components": [ ... ]
}
```

`bomFormat`, `specVersion`, and `version` are required and fixed for
schema version 1 of `pin.lock`. `serialNumber` and `metadata.timestamp`
MUST NOT appear: their omission is what makes the file byte-stable across
re-runs and conflict-free across parallel branches.

## metadata

```json
{
  "metadata": {
    "tools": {
      "components": [
        {"type": "application", "name": "pin", "version": "X.Y.Z"}
      ]
    },
    "properties": [
      {"name": "pin:lockfile_version", "value": "1"},
      {"name": "pin:out_dir", "value": "internal/web/static/vendor"}
    ]
  }
}
```

- `tools.components[]` carries the writer's name and version. A reader
  uses this for diagnostics only; it does not affect parsing.
- `properties[]` carries pin-namespaced top-level metadata:
  - `pin:lockfile_version` — integer string. A reader MUST refuse a
    value it does not understand. The current value is `"1"`.
  - `pin:out_dir` — the manifest's `out:` directory, the root that
    every `pin:out` path is relative to.

A reader MUST tolerate additional `properties[]` entries it does not
recognise: forward-compatibility for v0.2 fields depends on this.

## components

Top-level `components[]` is an array of `type: library` entries, one per
distinct package, sorted alphabetically by `bom-ref`. Within each
library, the nested `components[]` is an array of `type: file` entries,
one per vendored file, sorted alphabetically by `bom-ref`. The sort
order is stable and a writer MUST produce it; a reader MAY rely on it.

### library component

```json
{
  "type": "library",
  "bom-ref": "pkg:npm/htmx.org@2.0.6",
  "name": "htmx.org",
  "version": "2.0.6",
  "purl": "pkg:npm/htmx.org@2.0.6",
  "licenses": [{"license": {"id": "0BSD"}}],
  "hashes": [{"alg": "SHA-512", "content": "<hex>"}],
  "externalReferences": [{"type": "vcs", "url": "https://github.com/bigskysoftware/htmx"}],
  "components": [ ... ]
}
```

- `bom-ref` equals `purl`. Both fields exist for CycloneDX consumers
  that key by either.
- `hashes[0]` is the package-level integrity anchor. Encoding depends
  on the source kind, summarised below:

  | Source            | purl prefix     | `hashes[0].alg`          | `hashes[0].content`                            |
  |-------------------|-----------------|--------------------------|------------------------------------------------|
  | npm               | `pkg:npm/`      | `SHA-512` (or the algorithm in `dist.integrity`) | hex of the registry tarball                     |
  | github            | `pkg:github/`   | `SHA-1`                  | hex of the resolved commit SHA                  |
  | url (TOFU)        | `pkg:generic/`  | `SHA-384`                | hex of the single fetched file                  |

  When `hashes[]` is absent, the source did not provide a package-level
  anchor (legitimate for very old packages without `dist.integrity`).

- `externalReferences[type=vcs]` is the source repository URL when known.
- `licenses[]` carries the SPDX-normalised declared license when known.

For `github:` sources, the purl carries a `vcs_revision` qualifier with
the same hex SHA that appears in `hashes[0]`:

```
pkg:github/highlightjs/cdn-release@11.11.1?vcs_revision=91724c0adaf7bea7...
```

Consumers MAY use either the qualifier or `hashes[0]` to recover the
commit SHA; writers MUST write both.

### file component

```json
{
  "type": "file",
  "bom-ref": "pkg:npm/htmx.org@2.0.6#dist/htmx.min.js",
  "name": "dist/htmx.min.js",
  "hashes": [{"alg": "SHA-384", "content": "<hex>"}],
  "externalReferences": [
    {"type": "distribution", "url": "https://cdn.jsdelivr.net/npm/htmx.org@2.0.6/dist/htmx.min.js"}
  ],
  "properties": [
    {"name": "pin:out", "value": "htmx.org/htmx.min.js"},
    {"name": "pin:type", "value": "script"},
    {"name": "pin:format", "value": "iife"},
    {"name": "pin:size", "value": "51007"}
  ]
}
```

- `bom-ref` is the package's purl with a `#<path>` subpath fragment
  identifying the file inside the package.
- `name` is the file's path inside the package (the source-of-record path,
  not the on-disk output path).
- `hashes[0]` is the Subresource Integrity hash of the file's bytes,
  encoded as hex per CycloneDX convention. SHA-384 is the default
  algorithm chosen because it's what browsers accept in
  `<script integrity>` attributes and what jsdelivr publishes natively.
  Convert hex to base64 to produce an `sha384-...` SRI string.
- `externalReferences[type=distribution]` is the CDN URL where the file
  can be fetched. Recording it as transport metadata; integrity is
  anchored to the package, not the CDN.
- `properties[]` carries pin-namespaced per-file metadata:
  - `pin:out` (required) — output path relative to `pin:out_dir` from
    metadata. Writers MUST produce this; readers MUST treat its absence
    as a parse error.
  - `pin:type` (required) — one of `script | style | font | image |
    wasm | map | other`. Classification is by file extension.
  - `pin:format` (optional) — for `pin:type: script` only. One of
    `esm | umd | iife | cjs | amd | system | unknown`. Best-effort
    sniffing; manifest overrides are surfaced here.
  - `pin:size` (optional) — file size in bytes, as a decimal string.

A reader MUST tolerate additional properties it does not recognise.

## pin: property namespace

The `pin:` namespace is reserved for this specification. Tools producing
`pin.lock` for non-pin purposes MUST NOT introduce properties with this
prefix. The full set at schema version 1 is:

| Property             | Location                       | Type           |
|----------------------|--------------------------------|----------------|
| `pin:lockfile_version` | `metadata.properties[]`      | int as string  |
| `pin:out_dir`        | `metadata.properties[]`        | path string    |
| `pin:out`            | `<file>.properties[]`          | path string    |
| `pin:type`           | `<file>.properties[]`          | enum           |
| `pin:format`         | `<file>.properties[]`          | enum or absent |
| `pin:size`           | `<file>.properties[]`          | int as string  |

Adding a new `pin:` property is an additive change at the same schema
version. Removing or repurposing one is a schema-version bump.

## Formatting

A writer MUST produce JSON with:

- Two-space indentation.
- LF line endings.
- A trailing newline.
- No trailing whitespace.
- Keys sorted alphabetically within every object.

A writer SHOULD skip writing the file when the new bytes would be
identical to the existing file on disk, so the file's mtime stays
stable.

## Reserved fields

The following fields are reserved for future schema versions and MUST NOT
appear at schema version 1. A v1 writer MUST NOT emit them; a v1 reader
encountering them in a higher-version lockfile follows the forward-compat
rules below.

- On `library` components: an `attestation` object carrying SLSA
  Provenance / sigstore bundle pointers (`predicate_type`, `builder_id`,
  `source_repository`, `source_revision`, `signer_identity`,
  `transparency_log`). Reserved for the provenance verification work; see
  [Could lockfiles just be SBOMs?][cl] for the motivation.

[cl]: https://nesbitt.io/2025/12/23/could-lockfiles-just-be-sboms.html

## Forward compatibility

A reader processing a lockfile whose `pin:lockfile_version` it does not
recognise MUST refuse to parse it. Tools that need to operate on the
file regardless (CycloneDX consumers that read it as a generic SBOM)
ignore the `pin:` namespace and rely only on the CycloneDX fields.

Within a single schema version, additive changes are allowed:

- New `pin:` properties on existing entry shapes.
- New `externalReferences[]` types.
- New `hashes[]` algorithms.

Readers MUST tolerate unknown additive content. Writers SHOULD NOT
emit additive content unless documented in this spec.

## Verification model

The CycloneDX hash entries are the contract. To verify that a vendored
file matches the lockfile, a consumer:

1. Reads `metadata.properties[name=pin:out_dir]` and `<file>.properties
   [name=pin:out]` to compute the on-disk path.
2. Reads `<file>.hashes[]`, decodes the content from hex, and compares
   to the hash of the file's bytes using the same algorithm.
3. Optionally, reads the parent `library.hashes[]` to verify the
   provenance of the package as a whole (for npm sources, this is the
   tarball hash anchoring back to the registry).

The hashes are the only required input. The `purl`, `externalReferences`,
and `pin:` properties are informational from the verifier's perspective.
