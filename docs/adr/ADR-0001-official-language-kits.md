# ADR-0001 — Official language kits and the catalog home

- **Status:** Proposed
- **Date:** 2026-06-13
- **Boundary:** OSS-only
- **Scope:** The official language-kit catalog (TypeScript, Go, Rust, Java,
  Python, Ruby), where it lives, and the signing / `demand.env` follow-ups it
  depends on.

## Context

The kit machinery — manifest schema + parser, declarative detection, the
`foundation → framework → project` composition algorithm, the toolchain
provisioner, and the Sigstore trust gate — is built and shipped in the execution
layer. What was missing was the **content**: only a single TypeScript/Next.js
kit existed, and it was duplicated with drift between the OSS catalog and a
manifest string embedded in the closed platform.

Two cross-cutting facts shape this decision:

1. **The default trust mode is now `signed-by-allowlist`.** A security change
   flipped the compiled-in default from `permissive`. Under the new default with
   an empty issuer allowlist, the gate **fails closed** — no kit installs until
   an operator populates the allowlist or opts back to `permissive`. No vendor
   trust root or signing CI exists yet, so every official kit is unsigned today.
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

2. **Author six foundation/framework kits** — manifests-only, zero machinery
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

4. **Stand up signing CI + a vendor trust root (follow-up, step 3.6).** Keyless
   Sigstore signing of each `kit.toml` → sibling `.sigstore` bundle on tagged
   releases, under a published OIDC signer identity; add that signer to the
   default `trust.issuerSet` shipped with the binary; replace the embedded
   public-good trust root with the vendor root. This makes official kits install
   under `signed-by-allowlist` without `--allow-unsigned` — the gating
   dependency the trust-default change created. **Not implemented in this scaffold.**

5. **Wire `demand.env` end-to-end (follow-up, cross-repo).** Populate the
   composed demand's `env` map (currently always nil from the composer) so
   PATH-mutating installers (Rust/Python/Ruby) propagate their tool directory to
   every command. Until then, the affected kits source their env files inside
   the install scripts and hooks. **Not implemented in this scaffold.**

## Consequences

- OSS users get language coverage out of the box; the platform consumes the
  catalog rather than authoring kits.
- A single CI can sign the whole catalog in one pass, and a single parity
  fixture can guard composer drift across the layer.
- The trust gate becomes usable for official kits once the signer + trust root
  land — realizing the security change's intent rather than working around it.
- These kits are **unsigned until 3.6 lands**; installing them requires
  `--allow-unsigned` (audit-logged) or a `permissive` trust mode.

## Open questions

- **O1 — Signing CI ownership + trust-root publication timeline.** Until it
  exists, official kits ship unsigned. Owner-gated.
- **O2 — Pre-baked sandbox images** per language to de-flake cold cloud
  provisioning before real-mode smokes.
- **O3 — `demand.env` schema.** Whether kits declare PATH augmentation via a new
  manifest block or the composer derives it from the install scripts.
