# ADR-0001 — Official language kits and the catalog home

- **Status:** Accepted
- **Date:** 2026-06-13
- **Boundary:** OSS-only
- **Scope:** The official language-kit catalog (TypeScript, TS/Next.js, Go, Rust,
  Java, Python, Ruby), where it lives, its keyless Sigstore signing, and the
  `demand.env` follow-up it depends on.

## Context

The kit machinery — manifest schema + parser, declarative detection, the
`foundation → framework → project` composition algorithm, the toolchain
provisioner, and the Sigstore trust gate — is built and shipped in the execution
layer. What was missing was the **content**: only a single TypeScript/Next.js
kit existed, and it was duplicated with drift between the OSS catalog and a
manifest string embedded in the closed platform.

Two cross-cutting facts shape this decision:

1. **The default trust mode is `signed-by-allowlist`, and the vendor trust root
   ships compiled-in.** A security change flipped the compiled-in default from
   `permissive`. The daemon does NOT ship an empty allowlist: at startup it seeds
   `trust.issuerSet` with the official kit-signing identity (the
   `defaultVendorIssuerSet()` default). The signing CI and the embedded
   public-good Sigstore trust root have both landed, so every official kit
   manifest ships a real sibling `.sigstore` bundle and passes the legacy
   manifest `signed-by-allowlist` gate without `--allow-unsigned`. That does not
   bind referenced payload or establish complete-package installation.
2. **Kits are execution-layer content.** A kit is a declarative detection +
   toolchain + commands + skills contract with no server side and no platform
   dependency. Per the OSS line ("client/execution + contracts are OSS;
   intelligence is platform-only"), the default kits are OSS-owned.

## Decision

1. **One OSS monorepo for official kits: `donmai-kits`.** A dedicated,
   brand-neutral OSS repo (rather than extending the deprecating TS libraries
   monorepo) holds the catalog. Kits are language-agnostic TOML + content data
   files consumed by the Go execution layer via the daemon scan path / git
   install — not TS library code — so a dedicated content repo is the clean home.

2. **Author seven foundation/framework kits** — manifests-only, zero machinery
   changes (the parser, detection, composition, and provisioner already execute
   any conforming manifest):

   | Kit | Order | Toolchain |
   |---|---|---|
   | `default/typescript` | foundation | node 22 |
   | `default/ts-nextjs` | framework | node 22 (pnpm) |
   | `default/go` | foundation | go 1.23 |
   | `default/rust` | foundation | rust stable |
   | `default/java` | foundation | temurin 17 |
   | `default/python` | foundation | python 3.12 + uv |
   | `default/ruby` | foundation | ruby 3.3 (rbenv) |

3. **Split the TypeScript kit** into a base `default/typescript` foundation kit
   (any TS/Node project; `tsconfig.json` + `package.json`) and the
   `default/ts-nextjs` framework kit (Next.js; `next.config.*` +
   `package.json#dependencies.next`). A Next.js repo selects one foundation + one
   framework and composes them — exactly the composition model the layer is
   built around, and it demonstrates the foundation/framework split with a real
   pair. The platform should consume this OSS catalog rather than embedding its
   own TS kit string (resolving the prior drift).

4. **Signing CI + vendor trust root — LANDED.** Keyless Sigstore signing runs in
   `.github/workflows/sign.yml` on push to `main` (and on tags / manual dispatch):
   GitHub Actions OIDC → Fulcio short-lived cert, logged in the public-good Rekor
   transparency log, emitting a protobuf-format sibling `kit.toml.sigstore` bundle
   per kit (`cosign sign-blob --new-bundle-format`). The daemon's compiled-in
   `defaultVendorIssuerSet()` pins that workflow's exact Fulcio SAN
   (`…/sign.yml@refs/heads/main`) + OIDC issuer, and the embedded public-good
   Sigstore trust root verifies the chain offline. The result is
   `legacy-manifest-verified` integrity for official manifest bytes under the
   default `signed-by-allowlist` gate without `--allow-unsigned`.
   (The "vendor trust root" here is the embedded public-good root narrowed by the
   pinned vendor signer identity — a self-hosted Fulcio is not used, because a
   GitHub-OIDC-issued cert can only validate against the public-good root.)

   **2026-07-10 package addendum.** The accepted full-package contract now lives
   in
   [`donmai-architecture/ADR-2026-07-10-deterministic-kit-packages-and-command-composition.md`](https://github.com/RenseiAI/donmai-architecture/blob/main/ADR-2026-07-10-deterministic-kit-packages-and-command-composition.md).
   The publisher generates a canonical descriptor covering every payload path,
   digest, size, and portable mode, then keyless-signs that descriptor. The
   legacy manifest bundle is inventoried and is preserved when unchanged so the
   same kit id/version cannot acquire a new package digest from a signature
   refresh. Package-aware consumer installation and signed catalog snapshots
   remain separate follow-ups. Until those expansion prerequisites are
   accepted, the publisher is fail-closed to the current seven directory/kit-id
   pairs; an ordinary kit contribution cannot add, delete, rename, or substitute
   one of them.

5. **Wire `demand.env` end-to-end (follow-up, cross-repo).** Populate the
   composed demand's `env` map (currently always nil from the composer) so
   PATH-mutating installers (Rust/Python/Ruby) propagate their tool directory to
   every command. Until then, the affected kits source their env files inside
   the install scripts and hooks. **Not implemented in this scaffold.**

## Consequences

- OSS users get language coverage out of the box; the platform consumes the
  catalog rather than authoring kits.
- The signing CI verifies stable legacy bundles, generates deterministic
  complete-file descriptors, signs them, and publishes the package set
  atomically.
- The legacy manifest trust gate remains usable today. Package signature
  publication does not claim that the current installer verifies or activates
  complete packages.

## Open questions

- **O2 — Pre-baked sandbox images** per language to de-flake cold cloud
  provisioning before real-mode smokes.
- **O3 — `demand.env` schema.** Whether kits declare PATH augmentation via a new
  manifest block or the composer derives it from the install scripts.
