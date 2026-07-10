from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import unicodedata
from pathlib import Path

from scripts.package_kits import (
    DESCRIPTOR_NAME,
    DESCRIPTOR_SIGNATURE_NAME,
    PACKAGE_MARKER,
    PACKAGE_MARKER_BYTES,
    PackageError,
    build_descriptor,
    canonical_json_bytes,
    check_catalog,
    check_version_bumps,
    ci_check,
    ensure_unique_portable_paths,
    generate_catalog,
    portable_collision_key,
    validate_descriptor,
    validate_portable_path,
    verify_unicode_profile,
)


ROOT = Path(__file__).resolve().parents[1]


def _fixture_bundle(subject: bytes) -> bytes:
    value = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {
                "rawBytes": base64.b64encode(b"fixture-certificate").decode()
            },
            "tlogEntries": [{"fixture": True}],
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(hashlib.sha256(subject).digest()).decode(),
            },
            "signature": base64.b64encode(b"fixture-signature").decode(),
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _write_kit(root: Path, name: str = "demo") -> Path:
    kit_dir = root / "kits" / name
    (kit_dir / "bin").mkdir(parents=True)
    (kit_dir / "data").mkdir()
    manifest = kit_dir / "kit.toml"
    manifest.write_text(
        'api = "rensei.dev/v1"\n'
        "[kit]\n"
        f'id = "default/{name}"\n'
        'version = "1.0.0"\n'
        f'name = "{name}"\n'
        'authorIdentity = "did:web:donmai.dev"\n',
        encoding="utf-8",
    )
    setup = kit_dir / "bin" / "setup.sh"
    setup.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    setup.chmod(0o755)
    (kit_dir / "data" / "notes.txt").write_text("fixture\n", encoding="utf-8")
    (kit_dir / "kit.toml.sigstore").write_bytes(_fixture_bundle(manifest.read_bytes()))
    return kit_dir


def _publish(root: Path, kit_dir: Path) -> None:
    generate_catalog(root)
    descriptor = (kit_dir / DESCRIPTOR_NAME).read_bytes()
    (kit_dir / DESCRIPTOR_SIGNATURE_NAME).write_bytes(_fixture_bundle(descriptor))
    (root / PACKAGE_MARKER).write_bytes(PACKAGE_MARKER_BYTES)


def _rewrite_descriptor(kit_dir: Path, mutate) -> None:
    path = kit_dir / DESCRIPTOR_NAME
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_bytes(canonical_json_bytes(value))


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def _commit_fixture(root: Path) -> str:
    _git(root, "init", "--quiet")
    _git(root, "config", "user.name", "Package Fixture")
    _git(root, "config", "user.email", "fixture@example.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", "fixture")
    return _git(root, "rev-parse", "HEAD")


def _commit_changes(root: Path, message: str = "candidate") -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", message)


class CurrentCatalogPackageTests(unittest.TestCase):
    def test_canonical_json_rejects_non_interoperable_numbers(self) -> None:
        for value in (1.5, 1 << 53):
            with self.subTest(value=value):
                with self.assertRaises(PackageError):
                    canonical_json_bytes({"value": value})

    def test_current_catalog_renders_seven_package_candidates(self) -> None:
        generated = [
            (
                manifest.parent.name,
                hashlib.sha256(
                    build_descriptor(
                        ROOT,
                        manifest.parent,
                        require_legacy_subject_match=False,
                    )[1]
                ).hexdigest(),
            )
            for manifest in sorted((ROOT / "kits").glob("*/kit.toml"))
        ]

        self.assertEqual(7, len(generated))
        self.assertEqual(
            ["go", "java", "python", "ruby", "rust", "ts-nextjs", "typescript"],
            [name for name, _ in generated],
        )
        self.assertTrue(all(len(digest) == 64 for _, digest in generated))

    def test_current_descriptor_inventory_is_complete_and_sorted(self) -> None:
        for manifest in sorted((ROOT / "kits").glob("*/kit.toml")):
            with self.subTest(kit=manifest.parent.name):
                descriptor, raw = build_descriptor(
                    ROOT,
                    manifest.parent,
                    require_legacy_subject_match=False,
                )
                paths = [entry["path"] for entry in descriptor["entries"]]
                self.assertIn("kit.toml", paths)
                self.assertIn("kit.toml.sigstore", paths)
                self.assertNotIn(DESCRIPTOR_NAME, paths)
                self.assertNotIn(DESCRIPTOR_SIGNATURE_NAME, paths)
                self.assertEqual(
                    paths, sorted(paths, key=lambda path: path.encode("utf-8"))
                )
                self.assertEqual(raw, canonical_json_bytes(descriptor))

    def test_current_generation_is_byte_reproducible(self) -> None:
        first = {
            manifest.parent.name: build_descriptor(
                ROOT,
                manifest.parent,
                require_legacy_subject_match=False,
            )[1]
            for manifest in sorted((ROOT / "kits").glob("*/kit.toml"))
        }
        second = {
            manifest.parent.name: build_descriptor(
                ROOT,
                manifest.parent,
                require_legacy_subject_match=False,
            )[1]
            for manifest in sorted((ROOT / "kits").glob("*/kit.toml"))
        }
        self.assertEqual(first, second)

    def test_legacy_bundle_is_identity_bearing_but_package_bundle_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _, original = build_descriptor(root, kit_dir)

            legacy_path = kit_dir / "kit.toml.sigstore"
            legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
            legacy["verificationMaterial"]["tlogEntries"][0]["refresh"] = True
            legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
            _, refreshed_legacy = build_descriptor(root, kit_dir)
            self.assertNotEqual(original, refreshed_legacy)

            generate_catalog(root)
            package_signature = kit_dir / DESCRIPTOR_SIGNATURE_NAME
            package_signature.write_bytes(_fixture_bundle(b"detached metadata"))
            _, with_package_signature = build_descriptor(root, kit_dir)
            package_signature.write_bytes(
                _fixture_bundle(b"different detached metadata")
            )
            _, with_refreshed_package_signature = build_descriptor(root, kit_dir)
            self.assertEqual(with_package_signature, with_refreshed_package_signature)


class PortablePathTests(unittest.TestCase):
    def test_unicode_profile_is_pinned(self) -> None:
        verify_unicode_profile()
        self.assertIn(unicodedata.unidata_version, {"15.0.0", "15.1.0"})
        self.assertEqual(
            portable_collision_key("Straße/É"),
            portable_collision_key("STRASSE/E\u0301"),
        )

    def test_adversarial_paths_fail_closed(self) -> None:
        cases = {
            "absolute": "/etc/passwd",
            "dot-dot": "../outside",
            "empty-segment": "a//b",
            "backslash": "a\\b",
            "drive": "C:/outside",
            "ads": "notes.txt:secret",
            "forbidden": "bad?.txt",
            "control": "bad\u001f.txt",
            "trailing-dot": "name.",
            "trailing-space": "name ",
            "device": "CON.txt",
            "device-superscript": "COM¹.log",
            "version-control": ".git/config",
            "temporary": ".tmp-payload",
            "installer-marker": ".kit-installing",
            "reserved-metadata": "nested/kit.package.json",
        }
        for case, path in cases.items():
            with self.subTest(case=case):
                with self.assertRaises(PackageError):
                    validate_portable_path(path)

    def test_non_nfc_path_fails(self) -> None:
        decomposed = "data/e\u0301.txt"
        self.assertNotEqual(decomposed, unicodedata.normalize("NFC", decomposed))
        with self.assertRaisesRegex(PackageError, "not UTF-8 NFC"):
            validate_portable_path(decomposed)

    def test_casefold_collision_fails_inventory(self) -> None:
        # This is a pure lexical test so it also runs on case-insensitive APFS,
        # where the host may collapse the two fixture names before validation.
        with self.assertRaisesRegex(PackageError, "portable path collision"):
            ensure_unique_portable_paths(["Straße", "STRASSE"])


class SpecialFileTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            os.symlink("data/notes.txt", kit_dir / "alias.txt")
            with self.assertRaisesRegex(PackageError, "symlink"):
                build_descriptor(root, kit_dir)

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_hard_link_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            os.link(kit_dir / "data" / "notes.txt", kit_dir / "hardlink.txt")
            with self.assertRaisesRegex(PackageError, "hard-linked"):
                build_descriptor(root, kit_dir)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs unavailable")
    def test_fifo_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            os.mkfifo(kit_dir / "payload.fifo")
            with self.assertRaisesRegex(PackageError, "not a regular file"):
                build_descriptor(root, kit_dir)


class DescriptorValidationTests(unittest.TestCase):
    def test_published_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)

            state, generated = check_catalog(root)

        self.assertEqual("published", state)
        self.assertEqual(1, len(generated))

    def test_legacy_only_requires_explicit_bootstrap_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_kit(root)
            with self.assertRaisesRegex(PackageError, "legacy-only package state"):
                check_catalog(root)
            state, _ = check_catalog(root, allow_legacy_only=True)
        self.assertEqual("legacy-only", state)

    def test_mixed_descriptor_without_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_kit(root)
            generate_catalog(root)
            with self.assertRaisesRegex(PackageError, "mixed package migration state"):
                check_catalog(root, allow_legacy_only=True)

    def test_active_state_missing_signature_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_kit(root)
            generate_catalog(root)
            (root / PACKAGE_MARKER).write_bytes(PACKAGE_MARKER_BYTES)
            with self.assertRaisesRegex(PackageError, "missing, extra, or misplaced"):
                check_catalog(root)

    def test_invalid_activation_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            (root / PACKAGE_MARKER).write_text("legacy", encoding="utf-8")
            with self.assertRaisesRegex(PackageError, "marker bytes are invalid"):
                check_catalog(root)

    def test_extra_payload_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            (kit_dir / "extra.txt").write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(PackageError, "missing payload entries"):
                validate_descriptor(root, kit_dir)

    def test_missing_payload_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            (kit_dir / "data" / "notes.txt").unlink()
            with self.assertRaisesRegex(PackageError, "extra payload entries"):
                validate_descriptor(root, kit_dir)

    def test_payload_digest_tamper_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            (kit_dir / "data" / "notes.txt").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(PackageError, "digest/size/mode"):
                validate_descriptor(root, kit_dir)

    def test_payload_mode_tamper_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            (kit_dir / "bin" / "setup.sh").chmod(0o644)
            with self.assertRaisesRegex(PackageError, "digest/size/mode"):
                validate_descriptor(root, kit_dir)

    def test_descriptor_missing_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            _rewrite_descriptor(kit_dir, lambda value: value["entries"].pop())
            with self.assertRaisesRegex(PackageError, "missing payload entries"):
                validate_descriptor(root, kit_dir)

    def test_descriptor_extra_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)

            def add_extra(value):
                value["entries"].append(
                    {"path": "ghost.txt", "sha256": "0" * 64, "size": 0, "mode": "0644"}
                )
                value["entries"].sort(key=lambda entry: entry["path"].encode("utf-8"))

            _rewrite_descriptor(kit_dir, add_extra)
            with self.assertRaisesRegex(PackageError, "extra payload entries"):
                validate_descriptor(root, kit_dir)

    def test_descriptor_identity_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            _rewrite_descriptor(
                kit_dir, lambda value: value["kit"].update(version="9.9.9")
            )
            with self.assertRaisesRegex(PackageError, "identity/version"):
                validate_descriptor(root, kit_dir)

    def test_noncanonical_descriptor_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            path = kit_dir / DESCRIPTOR_NAME
            value = json.loads(path.read_text(encoding="utf-8"))
            path.write_text(json.dumps(value, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(
                PackageError, "not exact RFC 8785 canonical JSON"
            ):
                validate_descriptor(root, kit_dir)

    def test_descriptor_traversal_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            _rewrite_descriptor(
                kit_dir,
                lambda value: value["entries"][0].update(path="../outside"),
            )
            with self.assertRaisesRegex(PackageError, "dot-dot"):
                validate_descriptor(root, kit_dir)

    def test_package_signature_subject_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            (kit_dir / DESCRIPTOR_SIGNATURE_NAME).write_bytes(_fixture_bundle(b"wrong"))
            with self.assertRaisesRegex(PackageError, "subject digest does not match"):
                check_catalog(root)


class CandidateStateTests(unittest.TestCase):
    def test_payload_change_requires_version_bump(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            base = _commit_fixture(root)
            (kit_dir / "data" / "notes.txt").write_text("changed\n", encoding="utf-8")
            _commit_changes(root)

            with self.assertRaisesRegex(PackageError, "without changing kit.version"):
                ci_check(root, base)

    def test_versioned_payload_change_is_a_signing_pending_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            base = _commit_fixture(root)
            manifest = kit_dir / "kit.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    'version = "1.0.0"',
                    'version = "1.0.1"',
                ),
                encoding="utf-8",
            )
            (kit_dir / "data" / "notes.txt").write_text("changed\n", encoding="utf-8")
            _commit_changes(root)

            state, generated = ci_check(root, base)

            (kit_dir / "kit.toml.sigstore").write_bytes(
                _fixture_bundle(manifest.read_bytes())
            )
            generate_catalog(root)
            descriptor = (kit_dir / DESCRIPTOR_NAME).read_bytes()
            (kit_dir / DESCRIPTOR_SIGNATURE_NAME).write_bytes(
                _fixture_bundle(descriptor)
            )
            published_state, _ = check_catalog(root)

        self.assertEqual("signing-pending", state)
        self.assertEqual(1, len(generated))
        self.assertEqual("published", published_state)

    def test_human_generated_artifact_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            base = _commit_fixture(root)
            (kit_dir / DESCRIPTOR_NAME).write_bytes(b"{}")
            _commit_changes(root)

            with self.assertRaisesRegex(PackageError, "CI-generated"):
                ci_check(root, base)

    def test_activation_marker_downgrade_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            base = _commit_fixture(root)
            (root / PACKAGE_MARKER).unlink()
            _commit_changes(root)

            with self.assertRaisesRegex(PackageError, "activation is monotonic"):
                ci_check(root, base)

    def test_historical_version_reuse_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _commit_fixture(root)
            manifest = kit_dir / "kit.toml"
            for version in ("1.0.1", "1.0.2"):
                content = manifest.read_text(encoding="utf-8")
                content = content.replace(
                    next(
                        line
                        for line in content.splitlines()
                        if line.startswith("version = ")
                    ),
                    f'version = "{version}"',
                )
                manifest.write_text(content, encoding="utf-8")
                _commit_changes(root, version)
            base = _git(root, "rev-parse", "HEAD")
            content = manifest.read_text(encoding="utf-8").replace(
                'version = "1.0.2"',
                'version = "1.0.1"',
            )
            manifest.write_text(content, encoding="utf-8")
            _commit_changes(root, "reuse")

            with self.assertRaisesRegex(PackageError, "reuses historical publication"):
                check_version_bumps(root, base, ["kits/demo/kit.toml"])

    def test_historical_identity_reuse_after_directory_move_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            base = _commit_fixture(root)
            moved = root / "kits" / "renamed"
            kit_dir.rename(moved)
            _commit_changes(root, "move")

            with self.assertRaisesRegex(PackageError, "reuses historical publication"):
                check_version_bumps(
                    root,
                    base,
                    ["kits/demo/kit.toml", "kits/renamed/kit.toml"],
                )


if __name__ == "__main__":
    unittest.main()
