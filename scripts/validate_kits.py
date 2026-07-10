#!/usr/bin/env python3
"""validate_kits.py — validate every kit.toml in this catalog against the kit
manifest schema.

The schema this enforces is the one the OSS execution-layer daemon actually
parses (the `kitManifestTOML` struct in the daemon's kit registry) plus the
constraints documented in the kit-manifest spec (`005-kit-manifest-spec.md` in
the architecture corpus). We deliberately keep manifest validation structural
and permissive in the same way the daemon decoder is permissive: unknown fields
are ignored (forward-compatible), but the fields we DO know about must have the
right shape, and on-disk file references (skills, prompt fragments, hooks) must
resolve. Referenced SKILL.md files are additionally validated against the
required Agent Skills frontmatter contract (name + description).

Pure stdlib — uses `tomllib` (Python 3.11+). No third-party dependencies, so CI
needs nothing but a Python runtime.

Exit codes:
    0  every kit.toml parses and conforms
    1  one or more kits failed validation
    2  no kit.toml files found (mis-invocation / empty catalog)
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path, PureWindowsPath

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
SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
YAML_NON_STRING_PLAIN_RE = re.compile(
    r"^(?:null|true|false|yes|no|on|off|~|"
    r"[-+]?(?:0x[0-9a-f_]+|0o[0-7_]+|0b[01_]+|"
    r"(?:\d[\d_]*)(?:\.[\d_]*)?(?:e[-+]?\d[\d_]*)?|"
    r"\.\d[\d_]*(?:e[-+]?\d[\d_]*)?|\.inf|\.nan)|"
    r"[-+]?\d+(?::[0-5]?\d)+(?:\.\d+)?|"
    r"\d{4}-\d{1,2}-\d{1,2}(?:[tT ][0-9:.+\-zZ ]*)?)$",
    re.IGNORECASE,
)


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


def _parse_yaml_string(value: str) -> tuple[str | None, str | None]:
    """Parse the strict YAML-string subset accepted for required metadata.

    Supporting the full YAML grammar would require a non-stdlib dependency.
    The hermetic gate instead accepts plain strings, JSON-compatible YAML
    double-quoted strings, and YAML single-quoted strings. It rejects values
    that YAML would type as a collection, number, boolean, null, tag, alias, or
    malformed quoted scalar. Block strings are handled by the caller.
    """
    value = value.strip()
    if not value:
        return None, "must be a non-empty YAML string"

    if value.startswith('"'):
        if len(value) < 2 or not value.endswith('"'):
            return None, "has an unterminated double-quoted string"
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None, "contains an invalid double-quoted string"
        if not isinstance(parsed, str):
            return None, "must be a YAML string"
        return parsed, None

    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            return None, "has an unterminated single-quoted string"
        inner = value[1:-1]
        if "'" in inner.replace("''", ""):
            return None, "contains an invalid single-quoted string"
        return inner.replace("''", "'"), None

    if value.startswith(("- ", "? ", ": ")) or value[0] in "[],{}#&*!|>'%@`":
        return None, "must be a scalar YAML string, not a collection, tag, alias, or directive"
    if value[0] in {'"', "'"} or value[-1] in {'"', "'"}:
        return None, "contains an unmatched quote"
    if ": " in value or value.endswith(":") or " #" in value:
        return None, "plain YAML strings containing colon/comment syntax must be quoted"
    if YAML_NON_STRING_PLAIN_RE.fullmatch(value):
        return None, "must be quoted because YAML would not parse it as a string"
    return value, None


def _skill_frontmatter_fields(frontmatter: list[str]) -> tuple[dict[str, str], list[str]]:
    """Extract required top-level Agent Skills scalar fields.

    This is not a general YAML parser. It recognizes only the top-level `name`
    and `description` scalars the official specification requires, while
    allowing arbitrary optional YAML fields to pass through for forward
    compatibility. A malformed or unsupported required scalar fails closed.
    """
    fields: dict[str, str] = {}
    errors: list[str] = []
    i = 0
    while i < len(frontmatter):
        raw = frontmatter[i]
        i += 1
        if not raw or raw[0].isspace() or raw.lstrip().startswith("#"):
            continue
        if ":" not in raw:
            continue
        key, raw_value = raw.split(":", 1)
        key = key.strip()
        if key not in {"name", "description"}:
            continue
        if key in fields:
            errors.append(f"frontmatter.{key}: duplicate field")
            continue
        value = raw_value.strip()
        if value in {"|", ">", "|-", ">-", "|+", ">+"}:
            if key == "name":
                errors.append("frontmatter.name: block strings are not supported")
                continue
            block: list[str] = []
            while i < len(frontmatter):
                candidate = frontmatter[i]
                if candidate and not candidate[0].isspace():
                    break
                block.append(candidate.strip())
                i += 1
            value = " ".join(part for part in block if part)
            if not value:
                errors.append(f"frontmatter.{key}: block string must be non-empty")
                continue
            fields[key] = value
            continue

        parsed, parse_error = _parse_yaml_string(value)
        if parse_error:
            errors.append(f"frontmatter.{key}: {parse_error}")
            continue
        if parsed is not None:
            fields[key] = parsed
    return fields, errors


def validate_skill(skill_path: Path, expected_id: str | None = None) -> tuple[list[str], str | None]:
    """Validate one SKILL.md against agentskills.io's required v1 surface.

    Returns (errors, parsed_name). The body is otherwise intentionally
    unrestricted, matching the upstream specification.
    """
    if skill_path.name != "SKILL.md":
        return [f"skill entrypoint must be named `SKILL.md`, got {skill_path.name!r}"], None

    try:
        content = skill_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"failed to read: {exc}"], None

    lines = content.splitlines()
    if not lines or lines[0] != "---":
        return ["must start with YAML frontmatter delimiter `---`"], None

    try:
        close_idx = next(i for i in range(1, len(lines)) if lines[i] == "---")
    except StopIteration:
        return ["frontmatter is missing its closing `---` delimiter"], None

    fields, errors = _skill_frontmatter_fields(lines[1:close_idx])
    name = fields.get("name", "")
    description = fields.get("description", "")

    if not name:
        errors.append("frontmatter.name: required non-empty string")
    else:
        if len(name) > 64:
            errors.append("frontmatter.name: must be at most 64 characters")
        if not SKILL_NAME_RE.fullmatch(name):
            errors.append("frontmatter.name: use lowercase letters, numbers, and single hyphens only")
        if name != skill_path.parent.name:
            errors.append(
                f"frontmatter.name: {name!r} must match parent directory {skill_path.parent.name!r}"
            )
        if expected_id and name != expected_id:
            errors.append(f"frontmatter.name: {name!r} must match manifest skill id {expected_id!r}")

    if not description:
        errors.append("frontmatter.description: required non-empty string")
    elif len(description) > 1024:
        errors.append("frontmatter.description: must be at most 1024 characters")

    if not any(line.strip() for line in lines[close_idx + 1 :]):
        errors.append("body: must contain Markdown instructions after frontmatter")

    return errors, name or None


def _contained_file(kit_dir: Path, file_ref: str) -> Path | None:
    """Resolve a referenced asset without allowing traversal outside its kit."""
    windows_ref = PureWindowsPath(file_ref)
    if windows_ref.drive or windows_ref.is_absolute():
        return None
    try:
        candidate = (kit_dir / file_ref.replace("\\", "/")).resolve()
        candidate.relative_to(kit_dir.resolve())
    except (OSError, ValueError):
        return None
    return candidate if candidate.is_file() else None


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
        elif _contained_file(kit_dir, file_ref) is None:
            err(
                f"[[provide.prompt_fragments]][{i}]: file {file_ref!r} must exist inside the kit directory"
            )

    # skills — array of { file (, id) }; file must exist
    for i, sk in enumerate(provide.get("skills", []) or []):
        if not isinstance(sk, dict):
            err(f"[[provide.skills]][{i}]: must be a table")
            continue
        file_ref = sk.get("file")
        skill_id = sk.get("id")
        if skill_id is not None and (not isinstance(skill_id, str) or not skill_id.strip()):
            err(f"[[provide.skills]][{i}].id: must be a non-empty string when present")
            skill_id = None
        if not isinstance(file_ref, str):
            err(f"[[provide.skills]][{i}]: requires a string `file`")
        else:
            skill_path = _contained_file(kit_dir, file_ref)
            if skill_path is None:
                err(
                    f"[[provide.skills]][{i}]: SKILL file {file_ref!r} must exist inside the kit directory"
                )
            else:
                skill_errors, _ = validate_skill(
                    skill_path,
                    expected_id=skill_id if isinstance(skill_id, str) else None,
                )
                for skill_error in skill_errors:
                    err(f"[[provide.skills]][{i}] {file_ref}: {skill_error}")

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
            if _contained_file(kit_dir, val) is None:
                err(f"{prefix}.{hook_key}: script {val!r} must exist inside the kit directory")


def validate_catalog(root: Path, kit_tomls: list[Path] | None = None) -> dict[Path, list[str]]:
    """Validate per-kit structure plus catalog-wide identity uniqueness."""
    if kit_tomls is None:
        kits_dir = root / "kits"
        search_root = kits_dir if kits_dir.is_dir() else root
        kit_tomls = sorted(search_root.rglob("kit.toml"))

    errors_by_path = {kit_toml: validate_kit(kit_toml) for kit_toml in kit_tomls}
    kit_id_owners: dict[str, list[Path]] = {}
    skill_name_owners: dict[str, list[Path]] = {}

    for kit_toml in kit_tomls:
        try:
            with kit_toml.open("rb") as fh:
                manifest = tomllib.load(fh)
        except (tomllib.TOMLDecodeError, OSError):
            # The per-kit parser already reports the useful error.
            continue

        kit_section = manifest.get("kit", {})
        kit_id = kit_section.get("id") if isinstance(kit_section, dict) else None
        if isinstance(kit_id, str) and kit_id:
            kit_id_owners.setdefault(kit_id, []).append(kit_toml)

        provide = manifest.get("provide", {})
        skills = provide.get("skills", []) if isinstance(provide, dict) else []
        for skill in skills or []:
            if not isinstance(skill, dict) or not isinstance(skill.get("file"), str):
                continue
            skill_path = _contained_file(kit_toml.parent, skill["file"])
            if skill_path is None:
                continue
            _, parsed_name = validate_skill(skill_path)
            if parsed_name:
                skill_name_owners.setdefault(parsed_name, []).append(kit_toml)

    for kit_id, owners in kit_id_owners.items():
        if len(owners) > 1:
            owner_list = ", ".join(str(path.relative_to(root)) for path in owners)
            for owner in owners:
                errors_by_path[owner].append(f"catalog: duplicate kit id {kit_id!r} in {owner_list}")

    for skill_name, owners in skill_name_owners.items():
        if len(owners) > 1:
            owner_list = ", ".join(str(path.relative_to(root)) for path in owners)
            for owner in owners:
                errors_by_path[owner].append(
                    f"catalog: duplicate Agent Skill name {skill_name!r} in {owner_list}"
                )

    return errors_by_path


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    kits_dir = root / "kits"
    search_root = kits_dir if kits_dir.is_dir() else root

    kit_tomls = sorted(search_root.rglob("kit.toml"))
    if not kit_tomls:
        print(f"validate_kits: no kit.toml found under {search_root}", file=sys.stderr)
        return 2

    errors_by_path = validate_catalog(root, kit_tomls)
    failed = 0
    for kit_toml in kit_tomls:
        rel = kit_toml.relative_to(root)
        errors = errors_by_path[kit_toml]
        if errors:
            failed += 1
            print(f"FAIL  {rel}")
            for e in errors:
                print(f"        - {e}")
        else:
            print(f"OK    {rel}")

    print()
    print(f"validate_kits: {len(kit_tomls) - failed}/{len(kit_tomls)} kits passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
