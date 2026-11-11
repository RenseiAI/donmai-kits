from __future__ import annotations

import tempfile
import tomllib
import unittest
from pathlib import Path

from scripts.validate_kits import parse_version_range, validate_kit


ROOT = Path(__file__).resolve().parents[1]

PNPM_ENTRY = """
[[provide.dependency_store]]
manager   = "pnpm"
ecosystem = "node"
lockfiles = ["pnpm-lock.yaml"]
version   = "pnpm --version"
versions  = "{versions}"

[provide.dependency_store.store]
env         = ["NPM_CONFIG_STORE_DIR"]
sharing     = "content-addressed"
integrity   = "on-use"
content     = ["{layout}/files"]
bookkeeping = ["{layout}/projects"]

[provide.dependency_store.no_code]
env = {{ npm_config_ignore_scripts = "true", npm_config_ignore_pnpmfile = "true" }}

[provide.dependency_store.credentials]
config_env = "NPM_CONFIG_USERCONFIG"

[provide.dependency_store.commands]
fetch   = "pnpm fetch"
install = "{install}"
online  = "pnpm install --prefer-offline --frozen-lockfile"
"""


def pnpm_entry(versions: str, layout: str, install: str = "pnpm install --offline --frozen-lockfile") -> str:
    return PNPM_ENTRY.format(versions=versions, layout=layout, install=install)


def manifest(api: str, body: str = "", hooks: str = "") -> str:
    return (
        f'api = "{api}"\n[kit]\nid = "default/probe"\nversion = "1.0.0"\nname = "Probe"\n'
        '[detect]\nfiles = ["package.json"]\n[provide.commands]\nbuild = "true"\n'
        + body
        + hooks
    )


def validate(text: str, files: dict[str, str] | None = None) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        kit_dir = Path(tmp)
        (kit_dir / "kit.toml").write_text(text, encoding="utf-8")
        for name, content in (files or {}).items():
            path = kit_dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return validate_kit(kit_dir / "kit.toml")


TWO_PNPM = pnpm_entry(">=9 <10", "v3") + pnpm_entry(">=10 <11", "v10")


class DependencyStoreValidationTests(unittest.TestCase):
    def test_pnpm_9_and_10_entries_validate(self) -> None:
        self.assertEqual([], validate(manifest("donmai.dev/v2", TWO_PNPM)))

    def test_overlapping_or_missing_ranges_are_refused(self) -> None:
        overlap = pnpm_entry(">=9 <10", "v3") + pnpm_entry(">=9.5 <11", "v10")
        self.assertTrue(any("overlapping" in e for e in validate(manifest("donmai.dev/v2", overlap))))
        unranged = pnpm_entry(">=9 <10", "v3") + pnpm_entry(">=10 <11", "v10").replace(
            'versions  = ">=10 <11"\n', ""
        )
        self.assertTrue(any("overlapping or missing" in e for e in validate(manifest("donmai.dev/v2", unranged))))

    def test_v1_manifest_cannot_declare_a_store(self) -> None:
        errors = validate(manifest("rensei.dev/v1", TWO_PNPM))
        self.assertTrue(any("requires api" in e for e in errors), errors)

    def test_no_code_is_required(self) -> None:
        text = TWO_PNPM.replace(
            '[provide.dependency_store.no_code]\nenv = { npm_config_ignore_scripts = "true", npm_config_ignore_pnpmfile = "true" }\n',
            "",
        )
        self.assertTrue(any("no_code" in e for e in validate(manifest("donmai.dev/v2", text))))

    def test_pnpm_no_code_must_switch_off_scripts_and_pnpmfile(self) -> None:
        text = TWO_PNPM.replace('npm_config_ignore_pnpmfile = "true"', 'npm_config_ignore_pnpmfile = "false"')
        self.assertTrue(any("ignore_pnpmfile" in e for e in validate(manifest("donmai.dev/v2", text))))

    def test_store_commands_must_be_frozen_and_offline(self) -> None:
        loose = pnpm_entry(">=9 <10", "v3", install="pnpm install --offline")
        self.assertTrue(any("frozen" in e for e in validate(manifest("donmai.dev/v2", loose))))
        online = pnpm_entry(">=9 <10", "v3", install="pnpm install --frozen-lockfile")
        self.assertTrue(any("offline" in e for e in validate(manifest("donmai.dev/v2", online))))

    def test_forbidden_env_names_are_refused(self) -> None:
        text = TWO_PNPM.replace('config_env = "NPM_CONFIG_USERCONFIG"', 'config_env = "NODE_OPTIONS"', 1)
        self.assertTrue(any("credentials.config_env" in e for e in validate(manifest("donmai.dev/v2", text))))


class HookInstallTests(unittest.TestCase):
    def hook_errors(self, script: str, body: str = "") -> list[str]:
        hooks = '[provide.hooks]\npost_acquire = "bin/setup.sh"\n'
        return validate(manifest("rensei.dev/v1", body, hooks), {"bin/setup.sh": script})

    def test_non_frozen_pnpm_install_in_a_hook_is_refused(self) -> None:
        for command in (
            "pnpm install --prefer-offline",
            "pnpm i",
            "yarn install",
            "yarn",
            "npm install",
            "bun install",
        ):
            with self.subTest(command=command):
                errors = self.hook_errors(f"#!/bin/sh\n{command}\n")
                self.assertTrue(any("non-frozen" in e for e in errors), errors)

    def test_inline_hook_text_is_checked_too(self) -> None:
        errors = validate(manifest("rensei.dev/v1", "", '[provide.hooks]\npost_acquire = "pnpm install"\n'))
        self.assertTrue(any("non-frozen" in e for e in errors), errors)

    def test_frozen_install_is_allowed_unless_the_kit_declares_the_manager(self) -> None:
        self.assertEqual([], self.hook_errors("#!/bin/sh\nnpm ci\n"))
        errors = validate(
            manifest("donmai.dev/v2", TWO_PNPM, '[provide.hooks]\npost_acquire = "bin/setup.sh"\n'),
            {"bin/setup.sh": "#!/bin/sh\npnpm install --frozen-lockfile\n"},
        )
        self.assertTrue(any("declares a pnpm dependency_store" in e for e in errors), errors)

    def test_comments_and_non_install_commands_pass(self) -> None:
        script = "#!/bin/sh\n# pnpm install\ncommand -v pnpm\ncommand -v yarn &>/dev/null\nwhere yarn\npnpm run build\n"
        self.assertEqual([], self.hook_errors(script))


class VersionRangeTests(unittest.TestCase):
    def test_grammar(self) -> None:
        self.assertEqual([((9, 0, 0), (10, 0, 0))], parse_version_range(">=9 <10"))
        self.assertEqual([((9, 0, 0), (10, 0, 0))], parse_version_range("9.x"))
        self.assertEqual(2, len(parse_version_range(">=8 <9 || >=10 <11")))
        for bad in ("latest", ">=10 <9", ">=10.0.0-rc.1", ""):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_version_range(bad)


class TypeScriptKitTests(unittest.TestCase):
    def kit(self, name: str) -> dict:
        return tomllib.loads((ROOT / "kits" / name / "kit.toml").read_text(encoding="utf-8"))

    def test_typescript_declares_one_pnpm_entry_per_store_layout(self) -> None:
        manifest_ = self.kit("typescript")
        self.assertEqual("donmai.dev/v2", manifest_["api"])
        entries = manifest_["provide"]["dependency_store"]
        self.assertEqual(
            [("pnpm", ">=9 <10", ["v3/files"]), ("pnpm", ">=10 <11", ["v10/files", "v10/index"])],
            [(e["manager"], e["versions"], e["store"]["content"]) for e in entries],
        )
        for entry in entries:
            self.assertEqual("pnpm fetch", entry["commands"]["fetch"])
            self.assertEqual("pnpm install --offline --frozen-lockfile", entry["commands"]["install"])
            self.assertEqual("NPM_CONFIG_USERCONFIG", entry["credentials"]["config_env"])

    def test_typescript_kits_run_no_install_in_a_hook(self) -> None:
        for name in ("typescript", "ts-nextjs"):
            with self.subTest(kit=name):
                manifest_ = self.kit(name)
                self.assertNotIn("hooks", manifest_["provide"])
                self.assertFalse((ROOT / "kits" / name / "bin").exists())

    def test_nextjs_declares_no_store_and_follows_the_revision(self) -> None:
        manifest_ = self.kit("ts-nextjs")
        self.assertEqual("donmai.dev/v2", manifest_["api"])
        self.assertNotIn("dependency_store", manifest_["provide"])


if __name__ == "__main__":
    unittest.main()
