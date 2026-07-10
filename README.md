# donmai-kits

The official **kit catalog** for the donmai agent execution layer.

A *kit* is the packaging + detection + composition unit that teaches an agent
session how to work in a given language or framework: how to detect the project,
which base toolchain to install, the build/test/validate commands, plus optional
skills, prompt fragments, and tool permissions. Kits are declarative TOML
manifests — no code runs to load them — so the catalog stays small, auditable,
and language-agnostic.

This repository is **OSS and brand-neutral**. It contributes the default
language kits that ship with the open execution layer; the hosted registry,
per-tenant policy, and publication UI are a separate, closed concern.

## What a kit is

A kit manifest (`kit.toml`, `api = "rensei.dev/v1"`) declares:

| Section | Purpose |
|---|---|
| `[kit]` | identity — `id`, `version`, `name`, `description`, `license`, `priority`, … |
| `[supports]` | `os` (`linux` / `macos` / `windows`) and `arch` (`x86_64` / `arm64`) |
| `[requires]` | host version range + capabilities |
| `[detect]` | declarative `files` (any-exists), `files_all` (all-exist), `not_files`, `[detect.toolchain]` pin, optional `[[detect.content_matches]]` |
| `[provide.commands]` | `build` / `test` / `validate` (+ `[provide.commands_override.<os>]`) |
| `[provide.toolchain_install.<os>]` | per-OS base-toolchain install scripts (the kit↔sandbox seam) |
| `[provide.hooks]` | `post_acquire` (fetch deps) / `pre_release` (teardown), with `[provide.hooks.os.<os>]` overrides |
| `[provide.tool_permissions]` | shell verbs the kit allows (`cargo *`, `go *`, …) |
| `[provide.prompt_fragments]` / `[provide.skills]` | conventions partials + SKILL.md references |
| `[provide.workarea_config]` | `clean_dirs` / `preserve_dirs` |
| `[composition]` | `order` (`foundation` → `framework` → `project`), `composes_with`, `conflicts_with` |

The base-toolchain install scripts are the load-bearing kit↔sandbox boundary: a
kit declares *what toolchain it needs* (`{ node = "22" }`, `{ go = "1.23" }`),
the scheduler unions demand across the selected kits, and the
workarea/sandbox provider installs it. The kit never knows the sandbox; the
sandbox never knows the kit.

## The catalog

| Kit (`id`) | Order | Detects | Toolchain | build / test / validate |
|---|---|---|---|---|
| `default/typescript` | foundation | `tsconfig.json` + `package.json` | node 22 | `npm run build` / `npm test` / `npm run typecheck` |
| `default/ts-nextjs` | framework | `next.config.*` + `package.json#deps.next` | node 22 (pnpm) | `pnpm build` / `pnpm test` / `pnpm typecheck` |
| `default/go` | foundation | `go.mod` | go 1.23 | `go build ./...` / `go test ./...` / `go vet ./...` |
| `default/rust` | foundation | `Cargo.toml` | rust stable | `cargo build` / `cargo test` / `cargo clippy -D warnings && cargo fmt --check` |
| `default/java` | foundation | `pom.xml` / `build.gradle(.kts)` | temurin 17 | `./mvnw package` / `./mvnw test` / `./mvnw compile` |
| `default/python` | foundation | `pyproject.toml` / `requirements.txt` / `setup.py` | python 3.12 + uv | `python -m build` / `pytest` / `ruff check && mypy` |
| `default/ruby` | foundation | `Gemfile` / `.ruby-version` | ruby 3.3 (rbenv) | `rake build` / `rspec` / `rubocop` |

The TypeScript support is split into two kits: a base **`default/typescript`**
foundation kit (any TS/Node project) and a **`default/ts-nextjs`** framework kit
that composes on top for Next.js projects. A Next.js repo selects both — one
foundation + one framework — and they compose `foundation → framework`.

### Layout

```
kits/
  <lang>/
    kit.toml                       # the manifest (the contract)
    kit.toml.sigstore              # legacy manifest-only compatibility bundle
    kit.package.json               # canonical signed full-file inventory
    kit.package.json.sigstore      # detached package-descriptor bundle
    bin/setup.sh, bin/setup.cmd    # post_acquire hook scripts (posix + windows)
    partials/<name>.yaml           # prompt fragments
    skills/<id>/SKILL.md           # skill definitions
scripts/
  validate_kits.py                 # schema validator (stdlib, runs in CI)
  package_kits.py                  # deterministic package generator/validator
.github/workflows/validate.yml     # validates every kit.toml + OSS-clean grep
docs/adr/                          # architecture decision records
```

## Installing a kit

Kits are discovered by the execution-layer daemon's local registry. The daemon
scans a kits directory (default `~/.donmai/kits/*.kit.toml`) and exposes the
catalog through its local control API and CLI:

```bash
donmai kit list                       # list installed kits
donmai kit show default/go            # inspect one kit
donmai kit install --source <git-url> # install from a git source (signature-gated)
donmai kit enable default/python
```

That command surface is the explicit legacy compatibility path today: it
installs/verifies the manifest, not the complete package. Do not copy a
descriptor without its inventoried payload and detached package bundle. The
package-aware atomic installer remains a separate consumer migration.

To use a kit from this catalog directly, copy its `kit.toml` (renamed to
`<id>.kit.toml`, slashes → `__`) and its referenced files into the scan path, or
point a local `.kit.toml` manifest at it from inside a project workarea.

## Validating

```bash
python3 scripts/validate_kits.py        # validates every kits/*/kit.toml
python3 scripts/package_kits.py check   # validates every published package
```

The validator (pure stdlib, Python 3.11+) checks each manifest against the
manifest schema: the `api` constant, required identity fields, OS/arch enums,
composition `order` enum, command keys, catalog-wide kit/skill identity
uniqueness, path containment, and that every referenced skill / prompt-fragment
/ hook script resolves on disk. Referenced `SKILL.md` files must carry valid
Agent Skills `name` + `description` YAML frontmatter. The package publisher is
also pure stdlib but requires Python 3.12 or 3.13: those runtimes implement the
pinned Unicode 15.1-compatible normalization/case-fold profile, whose semantic
mapping fingerprint the gate verifies. Publisher validation also requires
POSIX descriptor-relative `O_NOFOLLOW` traversal; an unsupported host fails
closed instead of falling back to raceable pathname reads. Run the conformance
tests after validation:

```bash
python3 -m unittest discover -s tests -v
```

CI also runs the full unittest suite, adversarial package path/link/collision/
extra/missing/mode/race cases, version-bump enforcement, and generated-file
drift checks on every push and PR. Publication is frozen to the current seven
directory/kit-id pairs until the architecture expansion hold is explicitly
lifted; additions, deletions, renames, and id substitutions fail before
signing. During the one-time package activation, the package check uses the
explicit `--allow-legacy-only` bootstrap state; once the main signer commits
`.kit-package-v1-active`, legacy-only or mixed states fail.

## Signing & trust

Historic kit installs are manifest-signature-gated. The current execution
layer verifies a sibling `<manifest>.sigstore` bundle against a trust root and
issuer allowlist. That establishes `legacy-manifest-verified`, not complete
package integrity.

**Complete-package publishing is main-only and keyless.** On relevant merges,
[`.github/workflows/sign.yml`](./.github/workflows/sign.yml) verifies and
preserves unchanged legacy bundles, signs only changed/version-bumped
manifests, generates each RFC-8785-canonical `kit.package.json`, and keyless
signs the descriptor with cosign (GitHub Actions OIDC → Fulcio → Rekor,
bundle v0.3). No long-lived keys exist. The allowlisted signer identity is the
workflow's own OIDC subject:

```
SAN    = https://github.com/RenseiAI/donmai-kits/.github/workflows/sign.yml@refs/heads/main
issuer = https://token.actions.githubusercontent.com
```

The package descriptor inventories every payload file — including the stable
legacy manifest bundle — by normalized path, SHA-256, byte size, and portable
mode. The descriptor excludes itself and its detached signature to avoid a
cycle. The workflow signs in that exact order, verifies both bundle classes,
then atomically commits all seven package publications plus the activation
marker.

That identity pair is baked into the daemon's default `trust.issuerSet` for
the legacy manifest gate. The current daemon installer has not yet implemented
complete-package verification/atomic activation, so it must continue to report
the weaker legacy trust state. A signed catalog snapshot/TUF publisher and the
package-aware consumer migration are separate follow-ups; this repository does
not claim them here.

Trust modes (daemon-wide):

- `permissive` — verify + warn, never block.
- `signed-by-allowlist` — **the default.** Rejects unsigned and
  signed-but-unverified kits; only an allowlisted signer's verified kit installs.
- `attested` — allowlist today; SLSA attestation is future work.

The cliff: under the default `signed-by-allowlist` mode with an **empty**
issuer allowlist, the gate fails **closed** — no kit installs. The audit-logged
`donmai kit install --allow-unsigned` override (or flipping to `permissive`)
is the only bypass.

`.sigstore` bundles and `kit.package.json` are never hand-placed or edited — CI
emits them. Change package payload only with a `kit.version` bump; the main
workflow then updates the legacy bundle when needed, regenerates the descriptor,
and signs it. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) § "Signing model" and
[`docs/adr/ADR-0001-official-language-kits.md`](./docs/adr/ADR-0001-official-language-kits.md).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for how to author a kit, the
authoring gotchas (arch pinning, PATH-mutating installers, build-tool wrappers),
and the OSS-clean rules.

## License

[MIT](./LICENSE).
