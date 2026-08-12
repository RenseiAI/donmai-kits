from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.validate_kits import validate_catalog, validate_kit, validate_skill


ROOT = Path(__file__).resolve().parents[1]


class SkillConformanceTests(unittest.TestCase):
    def test_current_catalog_is_conformant(self) -> None:
        errors_by_path = validate_catalog(ROOT)
        failures = {
            str(path.relative_to(ROOT)): errors
            for path, errors in errors_by_path.items()
            if errors
        }
        self.assertEqual({}, failures)

    def test_every_current_skill_has_spec_metadata(self) -> None:
        skill_paths = sorted((ROOT / "kits").glob("*/skills/*/SKILL.md"))
        self.assertGreater(len(skill_paths), 0)
        for skill_path in skill_paths:
            with self.subTest(skill=str(skill_path.relative_to(ROOT))):
                errors, name = validate_skill(skill_path)
                self.assertEqual([], errors)
                self.assertEqual(skill_path.parent.name, name)

    def test_missing_frontmatter_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "missing-frontmatter"
            skill_dir.mkdir()
            skill_path = skill_dir / "SKILL.md"
            skill_path.write_text("# Instructions\n", encoding="utf-8")

            errors, name = validate_skill(skill_path)

        self.assertIsNone(name)
        self.assertIn("must start with YAML frontmatter", errors[0])

    def test_skill_entrypoint_must_be_named_skill_md(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "wrong-entrypoint"
            skill_dir.mkdir()
            skill_path = skill_dir / "README.md"
            skill_path.write_text(
                "---\n"
                "name: wrong-entrypoint\n"
                "description: Use when testing skill entrypoint names.\n"
                "---\n\n"
                "# Instructions\n",
                encoding="utf-8",
            )

            errors, name = validate_skill(skill_path)

        self.assertIsNone(name)
        self.assertIn("must be named `SKILL.md`", errors[0])

    def test_frontmatter_delimiters_must_be_exact_lines(self) -> None:
        cases = {
            "indented-open": (
                "  ---\n"
                "name: indented-open\n"
                "description: Use when testing an indented opening delimiter.\n"
                "---\n\n"
                "# Instructions\n"
            ),
            "indented-close": (
                "---\n"
                "name: indented-close\n"
                "description: Use when testing an indented closing delimiter.\n"
                "  ---\n\n"
                "# Instructions\n"
            ),
        }
        for skill_name, content in cases.items():
            with self.subTest(case=skill_name), tempfile.TemporaryDirectory() as tmp:
                skill_dir = Path(tmp) / skill_name
                skill_dir.mkdir()
                skill_path = skill_dir / "SKILL.md"
                skill_path.write_text(content, encoding="utf-8")

                errors, name = validate_skill(skill_path)

                self.assertIsNone(name)
                self.assertGreater(len(errors), 0)

    def test_name_must_match_parent_and_manifest_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "expected-name"
            skill_dir.mkdir()
            skill_path = skill_dir / "SKILL.md"
            skill_path.write_text(
                "---\n"
                "name: wrong-name\n"
                "description: Use when testing validator identity checks.\n"
                "---\n\n"
                "# Instructions\n",
                encoding="utf-8",
            )

            errors, _ = validate_skill(skill_path, expected_id="expected-name")

        self.assertTrue(any("must match parent directory" in error for error in errors))
        self.assertTrue(any("must match manifest skill id" in error for error in errors))

    def test_description_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "missing-description"
            skill_dir.mkdir()
            skill_path = skill_dir / "SKILL.md"
            skill_path.write_text(
                "---\n"
                "name: missing-description\n"
                "---\n\n"
                "# Instructions\n",
                encoding="utf-8",
            )

            errors, _ = validate_skill(skill_path)

        self.assertTrue(any("frontmatter.description" in error for error in errors))

    def test_required_metadata_rejects_unsupported_or_malformed_yaml_values(self) -> None:
        cases = {
            "sequence-description": ((
                "name: demo\n"
                "description: [not, a, string]\n"
            ), "not a collection"),
            "mapping-description": ((
                "name: demo\n"
                "description: {value: not-a-string}\n"
            ), "not a collection"),
            "invalid-unquoted-colon": ((
                "name: demo\n"
                "description: Use when: builds fail\n"
            ), "colon/comment syntax must be quoted"),
            "numeric-name": ((
                "name: 123\n"
                "description: Use when testing numeric YAML scalars.\n"
            ), "frontmatter.name: must be quoted"),
            "hex-description": ((
                "name: demo\n"
                "description: 0xFF\n"
            ), "frontmatter.description: must be quoted"),
            "octal-description": ((
                "name: demo\n"
                "description: 0o77\n"
            ), "frontmatter.description: must be quoted"),
            "trailing-dot-number": ((
                "name: demo\n"
                "description: 12.\n"
            ), "frontmatter.description: must be quoted"),
            "date-name": ((
                "name: 2026-07-10\n"
                "description: Use when testing YAML date scalars.\n"
            ), "frontmatter.name: must be quoted"),
            "timestamp-description": ((
                "name: demo\n"
                "description: 2026-07-10T12:34:56Z\n"
            ), "frontmatter.description: must be quoted"),
            "unterminated-quote": ((
                "name: demo\n"
                'description: "Use when a quote never closes.\n'
            ), "unterminated double-quoted string"),
        }
        for case_name, (frontmatter, expected_error) in cases.items():
            with self.subTest(case=case_name), tempfile.TemporaryDirectory() as tmp:
                skill_dir = Path(tmp) / "demo"
                skill_dir.mkdir()
                skill_path = skill_dir / "SKILL.md"
                skill_path.write_text(
                    f"---\n{frontmatter}---\n\n# Instructions\n",
                    encoding="utf-8",
                )

                errors, _ = validate_skill(skill_path)

                self.assertTrue(any(expected_error in error for error in errors), errors)

    def test_quoted_description_may_contain_colon_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "quoted-description"
            skill_dir.mkdir()
            skill_path = skill_dir / "SKILL.md"
            skill_path.write_text(
                "---\n"
                "name: quoted-description\n"
                'description: "Use when: a diagnostic contains a colon."\n'
                "---\n\n"
                "# Instructions\n",
                encoding="utf-8",
            )

            errors, name = validate_skill(skill_path)

        self.assertEqual([], errors)
        self.assertEqual("quoted-description", name)

    def test_non_utf8_skill_returns_validation_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "non-utf8"
            skill_dir.mkdir()
            skill_path = skill_dir / "SKILL.md"
            skill_path.write_bytes(b"\xff\xfe\x00")

            errors, name = validate_skill(skill_path)

        self.assertIsNone(name)
        self.assertEqual(1, len(errors))
        self.assertIn("failed to read", errors[0])

    def test_duplicate_skill_names_fail_catalog_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for kit_suffix in ("one", "two"):
                kit_dir = root / "kits" / kit_suffix
                skill_dir = kit_dir / "skills" / "shared-debugging"
                skill_dir.mkdir(parents=True)
                (skill_dir / "SKILL.md").write_text(
                    "---\n"
                    "name: shared-debugging\n"
                    "description: Use when testing duplicate catalog skill names.\n"
                    "---\n\n"
                    "# Instructions\n",
                    encoding="utf-8",
                )
                (kit_dir / "kit.toml").write_text(
                    "api = \"rensei.dev/v1\"\n"
                    "[kit]\n"
                    f"id = \"default/{kit_suffix}\"\n"
                    "version = \"1.0.0\"\n"
                    f"name = \"{kit_suffix}\"\n"
                    "[[provide.skills]]\n"
                    "file = \"skills/shared-debugging/SKILL.md\"\n"
                    "id = \"shared-debugging\"\n",
                    encoding="utf-8",
                )

            errors_by_path = validate_catalog(root)

        duplicate_errors = [
            error
            for errors in errors_by_path.values()
            for error in errors
            if "duplicate Agent Skill name" in error
        ]
        self.assertEqual(2, len(duplicate_errors))

    def test_duplicate_kit_ids_fail_catalog_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for kit_suffix in ("one", "two"):
                kit_dir = root / "kits" / kit_suffix
                kit_dir.mkdir(parents=True)
                (kit_dir / "kit.toml").write_text(
                    "api = \"rensei.dev/v1\"\n"
                    "[kit]\n"
                    "id = \"default/duplicate\"\n"
                    "version = \"1.0.0\"\n"
                    f"name = \"{kit_suffix}\"\n",
                    encoding="utf-8",
                )

            errors_by_path = validate_catalog(root)

        duplicate_errors = [
            error
            for errors in errors_by_path.values()
            for error in errors
            if "duplicate kit id" in error
        ]
        self.assertEqual(2, len(duplicate_errors))

    def test_skill_reference_cannot_escape_kit_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = root / "kit"
            kit_dir.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "SKILL.md").write_text(
                "---\n"
                "name: outside\n"
                "description: Use when testing path containment.\n"
                "---\n\n"
                "# Instructions\n",
                encoding="utf-8",
            )
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                "api = \"rensei.dev/v1\"\n"
                "[kit]\n"
                "id = \"default/escape\"\n"
                "version = \"1.0.0\"\n"
                "name = \"escape\"\n"
                "[[provide.skills]]\n"
                "file = \"../outside/SKILL.md\"\n",
                encoding="utf-8",
            )

            errors = validate_kit(manifest)

        self.assertTrue(any("must exist inside the kit directory" in error for error in errors))

    def test_windows_drive_qualified_hook_cannot_pass_as_posix_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kit_dir = Path(tmp) / "kit"
            crafted_hook = kit_dir / "C:" / "outside" / "hook.cmd"
            crafted_hook.parent.mkdir(parents=True)
            crafted_hook.write_text("@echo off\n", encoding="utf-8")
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                "api = \"rensei.dev/v1\"\n"
                "[kit]\n"
                "id = \"default/windows-escape\"\n"
                "version = \"1.0.0\"\n"
                "name = \"windows-escape\"\n"
                "[provide.hooks.os.windows]\n"
                "post_acquire = \"C:\\\\outside\\\\hook.cmd\"\n",
                encoding="utf-8",
            )

            errors = validate_kit(manifest)

        self.assertTrue(any("must exist inside the kit directory" in error for error in errors))

    def test_lane_declares_a_macos_only_placement_demand(self) -> None:
        # Regression pin for the swift kit's [[provide.lanes]] pilot: a lane
        # narrower than the kit's own [supports].os must validate cleanly.
        with tempfile.TemporaryDirectory() as tmp:
            kit_dir = Path(tmp) / "kit"
            kit_dir.mkdir()
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                "api = \"rensei.dev/v1\"\n"
                "[kit]\n"
                "id = \"default/lane-demo\"\n"
                "version = \"1.0.0\"\n"
                "name = \"lane-demo\"\n"
                "[supports]\n"
                "os = [\"linux\", \"macos\"]\n"
                "[[provide.lanes]]\n"
                "name = \"ios-app-build\"\n"
                "os = [\"macos\"]\n",
                encoding="utf-8",
            )

            errors = validate_kit(manifest)

        self.assertEqual([], errors)

    def test_lane_missing_name_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kit_dir = Path(tmp) / "kit"
            kit_dir.mkdir()
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                "api = \"rensei.dev/v1\"\n"
                "[kit]\n"
                "id = \"default/lane-demo\"\n"
                "version = \"1.0.0\"\n"
                "name = \"lane-demo\"\n"
                "[[provide.lanes]]\n"
                "os = [\"macos\"]\n",
                encoding="utf-8",
            )

            errors = validate_kit(manifest)

        self.assertTrue(any("[[provide.lanes]][0].name: required" in error for error in errors))

    def test_lane_unknown_os_value_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kit_dir = Path(tmp) / "kit"
            kit_dir.mkdir()
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                "api = \"rensei.dev/v1\"\n"
                "[kit]\n"
                "id = \"default/lane-demo\"\n"
                "version = \"1.0.0\"\n"
                "name = \"lane-demo\"\n"
                "[[provide.lanes]]\n"
                "name = \"bogus-lane\"\n"
                "os = [\"beos\"]\n",
                encoding="utf-8",
            )

            errors = validate_kit(manifest)

        self.assertTrue(any("unknown OS values" in error for error in errors))

    def test_lane_widening_beyond_kit_supports_fails(self) -> None:
        # A lane must narrow the kit's own [supports].os, never widen it —
        # declaring windows on a linux/macos-only kit is an authoring bug.
        with tempfile.TemporaryDirectory() as tmp:
            kit_dir = Path(tmp) / "kit"
            kit_dir.mkdir()
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                "api = \"rensei.dev/v1\"\n"
                "[kit]\n"
                "id = \"default/lane-demo\"\n"
                "version = \"1.0.0\"\n"
                "name = \"lane-demo\"\n"
                "[supports]\n"
                "os = [\"linux\", \"macos\"]\n"
                "[[provide.lanes]]\n"
                "name = \"windows-only-lane\"\n"
                "os = [\"windows\"]\n",
                encoding="utf-8",
            )

            errors = validate_kit(manifest)

        self.assertTrue(any("must narrow, never widen" in error for error in errors))

    def test_lane_arch_widening_beyond_kit_supports_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kit_dir = Path(tmp) / "kit"
            kit_dir.mkdir()
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                "api = \"rensei.dev/v1\"\n"
                "[kit]\n"
                "id = \"default/lane-demo\"\n"
                "version = \"1.0.0\"\n"
                "name = \"lane-demo\"\n"
                "[supports]\n"
                "arch = [\"arm64\"]\n"
                "[[provide.lanes]]\n"
                "name = \"x86-only-lane\"\n"
                "arch = [\"x86_64\"]\n",
                encoding="utf-8",
            )

            errors = validate_kit(manifest)

        self.assertTrue(any("must narrow, never widen" in error for error in errors))

    def test_lane_entry_must_be_a_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kit_dir = Path(tmp) / "kit"
            kit_dir.mkdir()
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                "api = \"rensei.dev/v1\"\n"
                "[kit]\n"
                "id = \"default/lane-demo\"\n"
                "version = \"1.0.0\"\n"
                "name = \"lane-demo\"\n"
                "[provide]\n"
                "lanes = [\"not-a-table\"]\n",
                encoding="utf-8",
            )

            errors = validate_kit(manifest)

        self.assertTrue(any("[[provide.lanes]][0]: must be a table" in error for error in errors))

    def test_malformed_kit_section_is_reported_without_catalog_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = root / "kits" / "bad"
            kit_dir.mkdir(parents=True)
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                "api = \"rensei.dev/v1\"\n"
                "kit = \"not-a-table\"\n",
                encoding="utf-8",
            )

            errors_by_path = validate_catalog(root)

        self.assertIn(manifest, errors_by_path)
        self.assertTrue(any("[kit]: section is required" in error for error in errors_by_path[manifest]))


if __name__ == "__main__":
    unittest.main()
