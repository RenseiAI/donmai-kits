# donmai-kits — official kit catalog for the donmai execution layer (OSS-public)

Declarative TOML manifests (`kit.toml`, `api = "rensei.dev/v1"`) that teach an
agent session to detect a project, install its base toolchain, and run
build/test/validate — no code runs to load a kit. Layout:
`kits/<lang>/{kit.toml, bin/, partials/, skills/<id>/SKILL.md}`. The manifest
contract is `../donmai-architecture/005-kit-manifest-spec.md`; the consumer is
the OSS execution-layer daemon's kit registry.

## Operating context

- `README.md` (catalog, manifest anatomy, install paths) and `CONTRIBUTING.md`
  (authoring steps, gotchas, signing model) are canonical for authoring detail
  — this file routes to them; it does not restate them.
- Governing corpus: `../donmai-architecture/` (public); `005-kit-manifest-spec.md`
  is the contract, `001-layered-execution-model.md` first. The corpus wins over
  code. Missing? `gh repo clone RenseiAI/donmai-architecture
  ../donmai-architecture` (from a worktree, siblings sit at `../../<repo>`).
- `scripts/validate_kits.py` mirrors the daemon parser: permissive on unknown
  fields (forward-compatible), strict on known shapes, and every referenced
  skill/prompt-fragment/hook script must resolve on disk.
- Package integrity is governed by
  `../donmai-architecture/ADR-2026-07-10-deterministic-kit-packages-and-command-composition.md`.
  `kit.toml.sigstore` is an explicit legacy manifest-only compatibility
  artifact; `kit.package.json` plus its detached bundle is the complete-package
  trust subject. `.github/workflows/sign.yml` is authoritative on ordering.

## Before you start — read in this order

| The moment you... | Read |
|---|---|
| start ANY task in this repo | this file, top to bottom (it is short) |
| author or edit any `kits/<lang>/kit.toml` or its `bin/`/`partials/`/`skills/` files | `CONTRIBUTING.md` top to bottom, then copy `kits/go/kit.toml` as the template |
| change what a manifest field MEANS (schema semantics, not a value) | `../donmai-architecture/005-kit-manifest-spec.md` + open an ADR — the validator and daemon parser move in lock-step |
| touch signing, trust modes, or any `.sigstore` file | `.github/workflows/sign.yml` (header comments) + `CONTRIBUTING.md` § "Signing model" + `docs/adr/ADR-0001-official-language-kits.md` |
| are about to write "done"/"fixed" or open a PR | Gates below + `../donmai-architecture/agents/PROTOCOL.md` §V |
| hit a failing validator or CI check you did not predict | `../donmai-architecture/agents/PROTOCOL.md` §D |

When a row matches, read that doc before your next edit and follow it literally.

## Gates — "done" means these passed

```bash
python3 scripts/validate_kits.py    # schema validation — pure stdlib, Python 3.11+
python3 -m unittest discover -s tests -v  # validator + Agent Skills conformance
python3 scripts/package_kits.py check     # inventory/publication state; Python 3.12/3.13
```

During the one-time package-v1 activation PR only, the last command is
`python3 scripts/package_kits.py check --allow-legacy-only`; the main signing
workflow atomically replaces that state with descriptors, package bundles, and
`.kit-package-v1-active`. After activation, legacy-only/mixed states fail.

Then run the Boundary grep below — CI's `oss-clean` job fails the build on any
hit. CI (`.github/workflows/validate.yml`) runs both on every push and PR;
`sign.yml` re-runs the validator before signing anything. Run the gates after
your last edit and quote each result line in your report.

## Iron rules

- `[provide.toolchain_install].linux` is load-bearing — cloud sandboxes are
  Linux; `.macos`/`.windows` are local-dev parity only.
- Raw tarball installs branch on `$(uname -m)` — a hardcoded amd64 URL breaks
  arm64 images (package managers like apt/brew pick the arch themselves).
- PATH-mutating installers (rustup, uv, rbenv) source their env file in the
  install script AND in `post_acquire` (`demand.env` is not wired end-to-end
  yet, so the next command otherwise misses the tool).
- Detection matches EXACT filenames via `os.Stat` — globs like `*.gemspec`
  never match; detect on a concrete file (`Gemfile`, `go.mod`, `tsconfig.json`).
- One foundation kit per repo: two `order = "foundation"` kits matching the
  same repo is a hard error (`ErrKitFoundationConflict`) — foundations detect
  on disjoint files; frameworks compose on top.
- Every catalog kit declares the required surface: `[provide.commands]`,
  per-OS `[provide.toolchain_install]` (`.linux` minimum), a `post_acquire`
  hook, `[provide.tool_permissions]`, ≥1 skill, ≥1 prompt fragment, and
  `[provide.workarea_config]` (`clean_dirs` + `preserve_dirs`).
- Every referenced `SKILL.md` starts with Agent Skills YAML frontmatter. Its
  required `name` matches both the skill directory and manifest `id`, and its
  non-empty `description` explains what the skill does and when to use it.
- `post_acquire` fetches framework dependencies only — never the base
  toolchain (that is `toolchain_install`'s job; order is install →
  post_acquire).
- Kit identity stays brand-neutral: `author = "donmai"`,
  `authorIdentity = "did:web:donmai.dev"`, `homepage = "https://donmai.dev"`.
- Package publication is frozen to the seven directory/kit-id pairs encoded in
  `scripts/package_kits.py`. Do not add, delete, rename, or substitute a kit id
  until an explicit architecture change lifts the catalog-expansion hold and
  updates the allowlist in the same reviewed change.
- `api = "rensei.dev/v1"` is the manifest protocol wire constant the daemon
  parser keys on — preserved verbatim in every manifest; never rename it.
- After every manifest edit, re-run `python3 scripts/validate_kits.py` before
  claiming anything works (the manifest IS the product here).

## Signing & trust (current reality)

- Keyless Sigstore: on relevant pushes to `main`, `.github/workflows/sign.yml`
  preserves and verifies unchanged legacy `kit.toml.sigstore` bundles, signs a
  changed manifest only after CI proves its kit version changed, generates the
  canonical full-file `kit.package.json`, then signs/verifies that descriptor.
- Ordering is load-bearing: `kit.toml.sigstore` is inventoried by the package,
  so refreshing it at an unchanged kit version would create package-digest
  equivocation. The workflow never refreshes unchanged legacy signatures.
- The descriptor inventories exact normalized paths, SHA-256 digests, sizes,
  and portable `0644`/`0755` modes. Its own detached
  `kit.package.json.sigstore` is excluded, preventing self-reference.
- The seven descriptors, their package bundles, any changed legacy bundles,
  and `.kit-package-v1-active` are committed together only after strict local
  validation and `cosign verify-blob` against the official identity.
- The allowlisted signer identity is that workflow's own OIDC SAN pinned to
  `sign.yml@refs/heads/main`; the daemon's default `trust.issuerSet` trusts
  exactly that identity/issuer pair.
- The current daemon consumes only the explicit `legacy-manifest-verified`
  path. Complete-package consumer installation and signed catalog snapshots
  remain separate, pending segments; do not describe them as shipped.
- Trust modes (daemon-wide): `permissive` (verify + warn, never block),
  `signed-by-allowlist` (the DEFAULT — rejects unsigned and
  signed-but-unverified kits), `attested` (allowlist today; SLSA future).
- The cliff: default mode + an empty issuer allowlist fails CLOSED — no kit
  installs; only the audit-logged `--allow-unsigned` override or `permissive`
  mode bypasses it.

## Boundary — this repo is public (OSS-clean)

Run this before pushing; it mirrors CI's `oss-clean` job:

```bash
grep -rnE 'REN-[0-9]|REN2-[0-9]|SUP-[0-9]|rensei-(architecture|ops|tui|platform)|RenseiAI[/]rensei|rensei[.]ai' \
  --include='*.toml' --include='*.md' --include='*.yaml' --include='*.yml' \
  --include='*.sh' --include='*.cmd' --include='*.json' \
  --include='*.py' \
  --exclude-dir='.git' --exclude='validate.yml' --exclude='CONTRIBUTING.md' .
```

Zero hits = clean (grep exits 1). The authoritative pattern lives in
`.github/workflows/validate.yml`; the copy above is regex-equivalent but
rewritten with grouping/character classes so this file — which the CI job DOES
scan (only `validate.yml` and `CONTRIBUTING.md` are excluded) — cannot match
itself. Keep it that way: never paste the workflow's literal pattern into any
scanned file.

- Nothing private lands here: no internal tracker IDs, no closed-source repo
  names, no internal SHAs or hostnames, no product brand domains.
- The two intentional look-alikes that STAY: `api = "rensei.dev/v1"` (wire
  constant, see Iron rules) and `[requires]` version keys as shipped in
  existing manifests — match the existing kits exactly.

## Gotchas

- Cold provisions reinstall the toolchain every time (apt/curl) — slow and
  flaky for real-mode cloud smokes; pre-baked images are future work, not
  something to hack around in a kit.
- Build-tool wrapper assumptions (`./mvnw`, lockfiles): a repo without the
  wrapper still gets the toolchain but needs a local `.kit.toml` override.
- The validator ignores unknown fields by design — a typo'd optional field
  passes silently; diff against `kits/go/kit.toml` to catch it.

## Hard stops

- NEVER fabricate/hand-place a `.sigstore` bundle or edit `kit.package.json`
  -> instead: change payload + bump `kit.version`, then let `sign.yml` generate
  and sign the package on `main`.
- NEVER expand or shrink the authorized seven-kit set as an ordinary kit PR ->
  instead: land the prerequisite package/consumer/catalog gates and explicit
  architecture authorization first.
- NEVER rename or "de-brand" `api = "rensei.dev/v1"` -> instead: leave it; it
  is a protocol identifier, not a product name.
- NEVER commit content that hits the Boundary grep -> instead: rewrite it
  brand-neutrally first.
- NEVER weaken `validate_kits.py`, the `oss-clean` job, or `sign.yml` to get
  green -> instead: quote the failure and propose the change.
- NEVER put brand-specific identity in a kit manifest -> instead:
  `author = "donmai"` / `did:web:donmai.dev` / `homepage donmai.dev`.
