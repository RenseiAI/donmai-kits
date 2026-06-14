#!/usr/bin/env python3
"""validate_kits.py — validate every kit.toml in this catalog against the kit
manifest schema.

The schema this enforces is the one the OSS execution-layer daemon actually
parses (the `kitManifestTOML` struct in the daemon's kit registry) plus the
constraints documented in the kit-manifest spec (`005-kit-manifest-spec.md` in
the architecture corpus). We deliberately keep this validator structural and
permissive in the same way the daemon decoder is permissive: unknown fields are
ignored (forward-compatible), but the fields we DO know about must have the
right shape, and on-disk file references (skills, prompt fragments, hooks) must
resolve.

Pure stdlib — uses `tomllib` (Python 3.11+). No third-party dependencies, so CI
needs nothing but a Python runtime.

Exit codes:
    0  every kit.toml parses and conforms
    1  one or more kits failed validation
    2  no kit.toml files found (mis-invocation / empty catalog)
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

# The protocol/api version string the manifest must declare. This is the wire
# contract constant carried by every manifest (`api = "rensei.dev/v1"`); it is a
# protocol identifier, not a product name. Bump in lock-step with the daemon
# parser if the manifest schema version ever moves.
EXPECTED_API = "rensei.dev/v1"

VALID_OS = {"linux", "macos", "windows"}
VALID_ARCH = {"x86_64", "arm64"}
VALID_ORDER = {"foundation", "framework", "project"}
# build / test / validate are the canonical command keys (005 § Contributions).
VALID_COMMAND_KEYS = {"build", "test", "validate"}


class KitError(Exception):
    """A single validation failure, scoped to one kit directory."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise KitError(msg)


def _is_str_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _is_str_map(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    )


def validate_kit(kit_toml: Path) -> list[str]:
    """Validate one kit.toml. Returns a list of human-readable error strings
    (empty when the kit conforms)."""
    errors: list[str] = []
    kit_dir = kit_toml.parent

    def err(msg: str) -> None:
        errors.append(msg)

    try:
        with kit_toml.open("rb") as fh:
            manifest = tomllib.load(fh)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        return [f"failed to parse TOML: {exc}"]

    # --- api ----------------------------------------------------------------
    api = manifest.get("api")
    if api != EXPECTED_API:
        err(f'api: expected "{EXPECTED_API}", got {api!r}')

    # --- [kit] --------------------------------------------------------------
    kit = manifest.get("kit")
    if not isinstance(kit, dict):
        err("[kit]: section is required")
        kit = {}

    for field in ("id", "version", "name"):
        val = kit.get(field)
        if not isinstance(val, str) or not val.strip():
            err(f"[kit].{field}: required non-empty string")

    for field in (
        "description",
        "author",
        "authorIdentity",
        "license",
        "homepage",
        "repository",
    ):
        if field in kit and not isinstance(kit[field], str):
            err(f"[kit].{field}: must be a string")

    if "priority" in kit and not isinstance(kit["priority"], int):
        err("[kit].priority: must be an integer")

    # --- [supports] ---------------------------------------------------------
    supports = manifest.get("supports", {})
    if supports:
        if not isinstance(supports, dict):
            err("[supports]: must be a table")
        else:
            os_list = supports.get("os", [])
            arch_list = supports.get("arch", [])
            if not _is_str_list(os_list):
                err("[supports].os: must be a list of strings")
            else:
                bad = set(os_list) - VALID_OS
                if bad:
                    err(f"[supports].os: unknown OS values {sorted(bad)}; allowed {sorted(VALID_OS)}")
            if not _is_str_list(arch_list):
                err("[supports].arch: must be a list of strings")
            else:
                bad = set(arch_list) - VALID_ARCH
                if bad:
                    err(f"[supports].arch: unknown arch values {sorted(bad)}; allowed {sorted(VALID_ARCH)}")

    # --- [requires] ---------------------------------------------------------
    requires = manifest.get("requires", {})
    if requires:
        if not isinstance(requires, dict):
            err("[requires]: must be a table")
        else:
            if "rensei" in requires and not isinstance(requires["rensei"], str):
                err("[requires].rensei: must be a string version range")
            if "capabilities" in requires and not _is_str_list(requires["capabilities"]):
                err("[requires].capabilities: must be a list of strings")

    # --- [detect] -----------------------------------------------------------
    detect = manifest.get("detect", {})
    if detect:
        if not isinstance(detect, dict):
            err("[detect]: must be a table")
        else:
            for key in ("files", "files_all", "not_files"):
                if key in detect and not _is_str_list(detect[key]):
                    err(f"[detect].{key}: must be a list of strings")
            if "exec" in detect and not isinstance(detect["exec"], str):
                err("[detect].exec: must be a string")
            tc = detect.get("toolchain", {})
            if tc and not _is_str_map(tc):
                err("[detect.toolchain]: must be a map of string->string (e.g. node = \"22\")")
            cm = detect.get("content_matches", [])
            if cm:
                if not isinstance(cm, list):
                    err("[[detect.content_matches]]: must be an array of tables")
                else:
                    for i, entry in enumerate(cm):
                        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
                            err(f"[[detect.content_matches]][{i}]: requires a string `file`")
            # A kit with NO detection at all never matches a repo. Warn loudly
            # by failing — every catalog kit must be detectable.
            has_detection = any(
                detect.get(k) for k in ("files", "files_all", "exec", "content_matches")
            )
            if not has_detection:
                err("[detect]: kit declares no detection rule (files / files_all / exec / content_matches)")

    # --- [provide.*] --------------------------------------------------------
    provide = manifest.get("provide", {})
    if provide and not isinstance(provide, dict):
        err("[provide]: must be a table")
        provide = {}

    commands = provide.get("commands", {})
    if commands:
        if not _is_str_map(commands):
            err("[provide.commands]: must be a map of string->string")
        else:
            unknown = set(commands) - VALID_COMMAND_KEYS
            if unknown:
                err(f"[provide.commands]: unknown command keys {sorted(unknown)}; allowed {sorted(VALID_COMMAND_KEYS)}")

    overrides = provide.get("commands_override", {})
    if overrides:
        if not isinstance(overrides, dict):
            err("[provide.commands_override]: must be an OS-keyed table")
        else:
            for os_key, os_cmds in overrides.items():
                if os_key not in VALID_OS:
                    err(f"[provide.commands_override.{os_key}]: unknown OS key; allowed {sorted(VALID_OS)}")
                if not _is_str_map(os_cmds):
                    err(f"[provide.commands_override.{os_key}]: must be a map of string->string")

    toolchain_install = provide.get("toolchain_install", {})
    if toolchain_install:
        if not isinstance(toolchain_install, dict):
            err("[provide.toolchain_install]: must be an OS-keyed table")
        else:
            for os_key, scripts in toolchain_install.items():
                if os_key not in VALID_OS:
                    err(f"[provide.toolchain_install.{os_key}]: unknown OS key; allowed {sorted(VALID_OS)}")
                if not _is_str_map(scripts):
                    err(f"[provide.toolchain_install.{os_key}]: must be a map of key->shell-command")

    # tool_permissions — array of { shell = "..." }
    for i, tp in enumerate(provide.get("tool_permissions", []) or []):
        if not isinstance(tp, dict) or not isinstance(tp.get("shell"), str):
            err(f"[[provide.tool_permissions]][{i}]: requires a string `shell`")

    # prompt_fragments — array of { partial, when[], file }; file must exist
    for i, pf in enumerate(provide.get("prompt_fragments", []) or []):
        if not isinstance(pf, dict):
            err(f"[[provide.prompt_fragments]][{i}]: must be a table")
            continue
        if not isinstance(pf.get("partial"), str):
            err(f"[[provide.prompt_fragments]][{i}]: requires a string `partial`")
        if "when" in pf and not _is_str_list(pf["when"]):
            err(f"[[provide.prompt_fragments]][{i}].when: must be a list of strings")
        file_ref = pf.get("file")
        if not isinstance(file_ref, str):
            err(f"[[provide.prompt_fragments]][{i}]: requires a string `file`")
        elif not (kit_dir / file_ref).is_file():
            err(f"[[provide.prompt_fragments]][{i}]: file {file_ref!r} does not exist on disk")

    # skills — array of { file (, id) }; file must exist
    for i, sk in enumerate(provide.get("skills", []) or []):
        if not isinstance(sk, dict):
            err(f"[[provide.skills]][{i}]: must be a table")
            continue
        file_ref = sk.get("file")
        if not isinstance(file_ref, str):
            err(f"[[provide.skills]][{i}]: requires a string `file`")
        elif not (kit_dir / file_ref).is_file():
            err(f"[[provide.skills]][{i}]: SKILL file {file_ref!r} does not exist on disk")

    # hooks — generic + OS-keyed; referenced scripts must exist on disk when
    # they look like a path (contain a slash or a known script extension).
    hooks = provide.get("hooks", {})
    if hooks:
        if not isinstance(hooks, dict):
            err("[provide.hooks]: must be a table")
        else:
            _check_hook_files(hooks, kit_dir, err)
            os_hooks = hooks.get("os", {})
            if os_hooks:
                if not isinstance(os_hooks, dict):
                    err("[provide.hooks.os]: must be an OS-keyed table")
                else:
                    for os_key, entry in os_hooks.items():
                        if os_key not in VALID_OS:
                            err(f"[provide.hooks.os.{os_key}]: unknown OS key; allowed {sorted(VALID_OS)}")
                        if isinstance(entry, dict):
                            _check_hook_files(entry, kit_dir, err, scope=f"os.{os_key}")

    # workarea_config — clean_dirs / preserve_dirs string lists
    wac = provide.get("workarea_config", {})
    if wac:
        if not isinstance(wac, dict):
            err("[provide.workarea_config]: must be a table")
        else:
            for key in ("clean_dirs", "preserve_dirs"):
                if key in wac and not _is_str_list(wac[key]):
                    err(f"[provide.workarea_config].{key}: must be a list of strings")

    # --- [composition] ------------------------------------------------------
    comp = manifest.get("composition", {})
    if comp:
        if not isinstance(comp, dict):
            err("[composition]: must be a table")
        else:
            order = comp.get("order")
            if order is not None and order not in VALID_ORDER:
                err(f"[composition].order: {order!r} invalid; allowed {sorted(VALID_ORDER)}")
            for key in ("conflicts_with", "composes_with", "provides", "depends_on"):
                if key in comp and not _is_str_list(comp[key]):
                    err(f"[composition].{key}: must be a list of strings")

    return errors


def _check_hook_files(hooks: dict, kit_dir: Path, err, scope: str = "") -> None:
    """A hook value that references a script file (windows backslash, posix
    slash, or a .sh/.cmd extension) must resolve on disk. Inline shell
    one-liners (no path separator, no script extension) are accepted as-is."""
    prefix = f"[provide.hooks{('.' + scope) if scope else ''}]"
    for hook_key in ("post_acquire", "pre_release"):
        val = hooks.get(hook_key)
        if val is None:
            continue
        if not isinstance(val, str):
            err(f"{prefix}.{hook_key}: must be a string")
            continue
        looks_like_path = (
            "/" in val
            or "\\" in val
            or val.endswith(".sh")
            or val.endswith(".cmd")
        )
        if looks_like_path:
            # Normalise windows-style separators for the on-disk check.
            rel = val.replace("\\", "/")
            if not (kit_dir / rel).is_file():
                err(f"{prefix}.{hook_key}: script {val!r} does not exist on disk")


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    kits_dir = root / "kits"
    search_root = kits_dir if kits_dir.is_dir() else root

    kit_tomls = sorted(search_root.rglob("kit.toml"))
    if not kit_tomls:
        print(f"validate_kits: no kit.toml found under {search_root}", file=sys.stderr)
        return 2

    total = 0
    failed = 0
    for kit_toml in kit_tomls:
        total += 1
        rel = kit_toml.relative_to(root)
        errors = validate_kit(kit_toml)
        if errors:
            failed += 1
            print(f"FAIL  {rel}")
            for e in errors:
                print(f"        - {e}")
        else:
            print(f"OK    {rel}")

    print()
    print(f"validate_kits: {total - failed}/{total} kits passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
