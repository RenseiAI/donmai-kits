from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import unicodedata
from pathlib import Path
from unittest.mock import patch

from scripts.package_kits import (
    CATALOG_CANDIDATE_SCHEMA,
    DESCRIPTOR_NAME,
    DESCRIPTOR_SIGNATURE_NAME,
    EXPECTED_KIT_IDENTITIES,
    EXPECTED_MANIFEST_API,
    EXPECTED_PACKAGE_SIGNER_POLICY,
    PACKAGE_SCHEMA,
    PACKAGE_MARKER,
    PACKAGE_MARKER_BYTES,
    PackageError,
    _record_catalog_identity,
    build_catalog_snapshot_candidate,
    build_descriptor,
    canonical_json_bytes,
    check_catalog,
    check_publication_worktree,
    check_version_bumps,
    ci_check,
    discover_kit_dirs,
    ensure_unique_portable_paths,
    first_publication_pending,
    generate_catalog,
    portable_collision_key,
    validate_descriptor,
    validate_portable_path,
    validate_sigstore_bundle,
    verify_unicode_profile,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_KIT_IDENTITIES = {"demo": "default/demo"}


def _live_catalog_signing_pending_kit() -> str | None:
    """Name of an already-published kit in the live ROOT catalog whose
    kit.toml.sigstore no longer matches its current kit.toml bytes, or None
    when the catalog is fully self-consistent.

    A kit-maintenance PR that changes an already-published kit's payload
    necessarily produces this state until the main-only signer (sign.yml)
    re-signs it post-merge. CI's actual PR-time gate
    (`package_kits.py ci-check --base-ref`) already classifies this
    correctly as "signing-pending" via a git diff against the PR base --
    see `check_signing_candidate`. The catalog-*snapshot-candidate* tests
    below are deliberately stricter than that: `build_catalog_snapshot_
    candidate` requires state == "published" by design, because a
    trustable catalog snapshot must never be built while any kit is
    unsigned. They therefore cannot pass during this legitimate transient
    window and skip rather than fail. An illegitimate mismatch (payload
    changed without a kit.version bump) is caught separately and
    unconditionally by `check_version_bumps` (part of `ci-check`), so this
    helper -- used only to skip the snapshot-candidate tests below -- never
    substitutes for that guarantee.
    """
    try:
        kit_dirs = discover_kit_dirs(ROOT)
    except PackageError:
        return None
    pending = first_publication_pending(ROOT, kit_dirs)
    for kit_dir in kit_dirs:
        if kit_dir.name in pending:
            continue
        legacy = kit_dir / "kit.toml.sigstore"
        if not legacy.is_file():
            continue
        manifest_bytes = (kit_dir / "kit.toml").read_bytes()
        try:
            validate_sigstore_bundle(ROOT, legacy, manifest_bytes)
        except PackageError:
            return kit_dir.name
    return None


_LIVE_SIGNING_PENDING_KIT = _live_catalog_signing_pending_kit()


def _published_kit_names(root: Path) -> list[str]:
    """Kit names that have a committed legacy signature (already published).

    A first-publication-pending kit (authorized, never signed) has no
    `kit.toml.sigstore` on disk yet, so it is deliberately excluded here: it
    carries no descriptor to inventory and never appears in a catalog snapshot
    until it graduates.
    """
    return sorted(
        kit_dir.name
        for kit_dir in (root / "kits").iterdir()
        if (kit_dir / "kit.toml").is_file()
        and (kit_dir / "kit.toml.sigstore").is_file()
    )


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
    _generate_catalog(root)
    descriptor = (kit_dir / DESCRIPTOR_NAME).read_bytes()
    (kit_dir / DESCRIPTOR_SIGNATURE_NAME).write_bytes(_fixture_bundle(descriptor))
    (root / PACKAGE_MARKER).write_bytes(PACKAGE_MARKER_BYTES)


def _write_pending_kit(root: Path, name: str) -> Path:
    """Write a first-publication-pending kit: kit.toml + payload, no sigstore.

    Unlike `_write_kit`, this writes no `kit.toml.sigstore` — the kit is
    authorized but never signed, exactly the on-disk shape the main-only signer
    graduates on merge.
    """
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
    (kit_dir / "data" / "notes.txt").write_text("pending\n", encoding="utf-8")
    return kit_dir


def _publish_single(root: Path, kit_dir: Path) -> None:
    """Publish one already-legacy-signed kit: mint its descriptor + signature.

    Unlike `_publish`, this touches only `kit_dir` (it does not run
    `generate_catalog`, which would require every discovered kit to already
    carry a legacy signature) — so a sibling kit can stay
    first-publication-pending.
    """
    _, descriptor = build_descriptor(root, kit_dir)
    (kit_dir / DESCRIPTOR_NAME).write_bytes(descriptor)
    (kit_dir / DESCRIPTOR_SIGNATURE_NAME).write_bytes(_fixture_bundle(descriptor))


def _generate_catalog(root: Path):
    return generate_catalog(root, expected_identities=FIXTURE_KIT_IDENTITIES)


def _check_catalog(root: Path, *, allow_legacy_only: bool = False):
    return check_catalog(
        root,
        allow_legacy_only=allow_legacy_only,
        expected_identities=FIXTURE_KIT_IDENTITIES,
    )


def _ci_check(root: Path, base_ref: str):
    return ci_check(
        root,
        base_ref,
        expected_identities=FIXTURE_KIT_IDENTITIES,
    )


def _publication_check(root: Path):
    return check_publication_worktree(
        root,
        expected_identities=FIXTURE_KIT_IDENTITIES,
    )


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
    def test_official_catalog_is_exactly_the_authorized_eight(self) -> None:
        kit_dirs = discover_kit_dirs(ROOT)
        # Data-driven off EXPECTED_KIT_IDENTITIES: the on-disk directories must
        # be exactly the authorized set (eight after the swift expansion).
        self.assertEqual(
            sorted(EXPECTED_KIT_IDENTITIES), [path.name for path in kit_dirs]
        )
        self.assertEqual(8, len(kit_dirs))
        self.assertIn("swift", [path.name for path in kit_dirs])

    def test_official_catalog_add_delete_and_id_substitution_fail(self) -> None:
        def copied_catalog() -> tuple[tempfile.TemporaryDirectory, Path]:
            temporary = tempfile.TemporaryDirectory()
            root = Path(temporary.name)
            shutil.copytree(ROOT / "kits", root / "kits")
            return temporary, root

        temporary, root = copied_catalog()
        with temporary:
            shutil.copytree(root / "kits" / "go", root / "kits" / "extra")
            with self.assertRaisesRegex(PackageError, "authorized kit set"):
                discover_kit_dirs(root)

        temporary, root = copied_catalog()
        with temporary:
            shutil.rmtree(root / "kits" / "java")
            with self.assertRaisesRegex(PackageError, "authorized kit set"):
                discover_kit_dirs(root)

        temporary, root = copied_catalog()
        with temporary:
            manifest = root / "kits" / "go" / "kit.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    'id = "default/go"', 'id = "default/substitute"'
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PackageError, "authorized kit.id"):
                discover_kit_dirs(root)

    def test_canonical_json_rejects_non_interoperable_numbers(self) -> None:
        for value in (1.5, 1 << 53):
            with self.subTest(value=value):
                with self.assertRaises(PackageError):
                    canonical_json_bytes({"value": value})

    def test_current_catalog_renders_published_package_candidates(self) -> None:
        published = _published_kit_names(ROOT)
        generated = [
            (
                name,
                hashlib.sha256(
                    build_descriptor(
                        ROOT,
                        ROOT / "kits" / name,
                        require_legacy_subject_match=False,
                    )[1]
                ).hexdigest(),
            )
            for name in published
        ]

        # Data-driven off the published subset (kits with a committed legacy
        # signature). A first-publication-pending kit has no descriptor to
        # render, so it is excluded until it graduates.
        self.assertEqual(published, [name for name, _ in generated])
        self.assertTrue(published)
        self.assertTrue(
            set(published).issubset(set(EXPECTED_KIT_IDENTITIES))
        )
        self.assertTrue(all(len(digest) == 64 for _, digest in generated))

    def test_current_descriptor_inventory_is_complete_and_sorted(self) -> None:
        for name in _published_kit_names(ROOT):
            with self.subTest(kit=name):
                descriptor, raw = build_descriptor(
                    ROOT,
                    ROOT / "kits" / name,
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
            name: build_descriptor(
                ROOT,
                ROOT / "kits" / name,
                require_legacy_subject_match=False,
            )[1]
            for name in _published_kit_names(ROOT)
        }
        second = {
            name: build_descriptor(
                ROOT,
                ROOT / "kits" / name,
                require_legacy_subject_match=False,
            )[1]
            for name in _published_kit_names(ROOT)
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

            _generate_catalog(root)
            package_signature = kit_dir / DESCRIPTOR_SIGNATURE_NAME
            package_signature.write_bytes(_fixture_bundle(b"detached metadata"))
            _, with_package_signature = build_descriptor(root, kit_dir)
            package_signature.write_bytes(
                _fixture_bundle(b"different detached metadata")
            )
            _, with_refreshed_package_signature = build_descriptor(root, kit_dir)
            self.assertEqual(with_package_signature, with_refreshed_package_signature)


class CatalogCandidateTests(unittest.TestCase):
    REVISION = "1" * 40

    def _skip_if_live_catalog_signing_pending(self) -> None:
        if _LIVE_SIGNING_PENDING_KIT is not None:
            self.skipTest(
                f"live catalog has a signing-pending kit ({_LIVE_SIGNING_PENDING_KIT!r}); "
                "a catalog snapshot candidate requires every published kit "
                "already signed -- ci-check (the actual PR-time gate) already "
                "classifies this state correctly via a git diff"
            )

    def _build(self, **overrides):
        self._skip_if_live_catalog_signing_pending()
        arguments = {"source_revision": self.REVISION, "sequence": 1}
        arguments.update(overrides)
        return build_catalog_snapshot_candidate(ROOT, **arguments)

    def _copy_published_catalog(self, destination: Path) -> None:
        self._skip_if_live_catalog_signing_pending()
        shutil.copytree(ROOT / "kits", destination / "kits")
        shutil.copyfile(ROOT / PACKAGE_MARKER, destination / PACKAGE_MARKER)

    def test_two_builds_are_byte_and_digest_identical(self) -> None:
        first = self._build()
        second = self._build()
        self.assertEqual(first, second)
        self.assertEqual(hashlib.sha256(first[0]).hexdigest(), first[1])

    def test_discovery_order_does_not_affect_candidate(self) -> None:
        locators = [
            f"kits/{name}/{DESCRIPTOR_NAME}" for name in _published_kit_names(ROOT)
        ]
        forward = self._build(descriptor_locators=locators)
        reverse = self._build(descriptor_locators=reversed(locators))
        self.assertEqual(forward, reverse)

    def test_rows_agree_with_published_descriptors(self) -> None:
        raw, _ = self._build()
        candidate = json.loads(raw)
        signing_workflow = (ROOT / ".github" / "workflows" / "sign.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f'EXPECTED_SAN: "{EXPECTED_PACKAGE_SIGNER_POLICY["identity"]}"',
            signing_workflow,
        )
        self.assertIn(
            f'EXPECTED_ISSUER: "{EXPECTED_PACKAGE_SIGNER_POLICY["issuer"]}"',
            signing_workflow,
        )
        self.assertEqual(CATALOG_CANDIDATE_SCHEMA, candidate["schema"])
        self.assertEqual("unsigned-candidate", candidate["state"])
        self.assertEqual(self.REVISION, candidate["sourceRevision"])
        self.assertEqual(1, candidate["sequence"])

        # The snapshot covers exactly the published subset; a
        # first-publication-pending kit contributes no signed descriptor row.
        published = _published_kit_names(ROOT)
        self.assertEqual(len(published), len(candidate["packages"]))
        expected_ids = sorted(EXPECTED_KIT_IDENTITIES[name] for name in published)
        self.assertEqual(
            expected_ids, [row["kit"]["id"] for row in candidate["packages"]]
        )
        for row in candidate["packages"]:
            descriptor_path = ROOT / row["descriptor"]
            descriptor = json.loads(descriptor_path.read_bytes())
            manifest = (descriptor_path.parent / descriptor["manifest"]).read_text(
                encoding="utf-8"
            )
            self.assertEqual(descriptor["kit"], row["kit"])
            self.assertEqual(
                hashlib.sha256(descriptor_path.read_bytes()).hexdigest(),
                row["packageDigest"],
            )
            self.assertEqual(EXPECTED_PACKAGE_SIGNER_POLICY, row["packageSignerPolicy"])
            self.assertEqual(
                {
                    "kitPackageSchema": PACKAGE_SCHEMA,
                    "kitManifestApi": EXPECTED_MANIFEST_API,
                },
                row["compatibility"],
            )
            self.assertIn(f'api = "{EXPECTED_MANIFEST_API}"', manifest)

    def test_malformed_revision_sequence_and_locator_fail_closed(self) -> None:
        cases = (
            {"source_revision": "short"},
            {"source_revision": "A" * 40},
            {"source_revision": "1" * 39},
            {"sequence": 0},
            {"sequence": -1},
            {"sequence": True},
            {"sequence": 1 << 53},
            {"descriptor_locators": ["../kit.package.json"] * 7},
            {"descriptor_locators": ["kits/go/other.json"] * 7},
            {"descriptor_locators": [f"kits/go/{DESCRIPTOR_NAME}"] * 7},
            {"descriptor_locators": []},
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(PackageError):
                self._build(**arguments)

    def test_duplicate_and_equivocating_identities_fail_closed(self) -> None:
        identity = ("default/shared", "1.0.0")
        identities: dict[tuple[str, str], str] = {}
        _record_catalog_identity(identities, identity, "a" * 64)
        with self.assertRaisesRegex(PackageError, "duplicate package identity"):
            _record_catalog_identity(identities, identity, "a" * 64)

        identities = {}
        _record_catalog_identity(identities, identity, "a" * 64)
        with self.assertRaisesRegex(PackageError, "equivocation"):
            _record_catalog_identity(identities, identity, "b" * 64)

    def test_unsupported_package_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._copy_published_catalog(root)
            descriptor_path = root / "kits" / "go" / DESCRIPTOR_NAME
            descriptor = json.loads(descriptor_path.read_bytes())
            descriptor["schema"] = "donmai.dev/kit-package/v999"
            descriptor_path.write_bytes(canonical_json_bytes(descriptor))
            (descriptor_path.parent / DESCRIPTOR_SIGNATURE_NAME).write_bytes(
                _fixture_bundle(descriptor_path.read_bytes())
            )
            with self.assertRaisesRegex(PackageError, "unsupported schema"):
                build_catalog_snapshot_candidate(
                    root, source_revision=self.REVISION, sequence=1
                )

    def test_unsupported_manifest_api_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._copy_published_catalog(root)
            manifest = root / "kits" / "go" / "kit.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    'api = "rensei.dev/v1"', 'api = "rensei.dev/v999"'
                ),
                encoding="utf-8",
            )
            (manifest.parent / "kit.toml.sigstore").write_bytes(
                _fixture_bundle(manifest.read_bytes())
            )
            descriptor, descriptor_bytes = build_descriptor(root, manifest.parent)
            self.assertEqual("donmai.dev/kit-package/v1", descriptor["schema"])
            (manifest.parent / DESCRIPTOR_NAME).write_bytes(descriptor_bytes)
            (manifest.parent / DESCRIPTOR_SIGNATURE_NAME).write_bytes(
                _fixture_bundle(descriptor_bytes)
            )
            with self.assertRaisesRegex(PackageError, "manifest api"):
                build_catalog_snapshot_candidate(
                    root, source_revision=self.REVISION, sequence=1
                )

    def test_digest_is_sensitive_to_revision_and_sequence(self) -> None:
        baseline = self._build()
        self.assertNotEqual(baseline[1], self._build(source_revision="2" * 40)[1])
        self.assertNotEqual(baseline[1], self._build(sequence=2)[1])


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
            "activation-marker": PACKAGE_MARKER,
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


@unittest.skipUnless(
    hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"),
    "secure dirfd traversal unavailable",
)
class SwapRaceTests(unittest.TestCase):
    def _racing_open(self, target: str, swap):
        real_open = os.open
        fired = False

        def racing_open(path, flags, *args, dir_fd=None, **kwargs):
            nonlocal fired
            if not fired and dir_fd is not None and path == target:
                fired = True
                swap()
            return real_open(path, flags, *args, dir_fd=dir_fd, **kwargs)

        return patch(
            "scripts.package_kits.os.open", side_effect=racing_open
        ), lambda: fired

    def test_payload_inode_swap_between_stat_and_open_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            victim = kit_dir / "data" / "notes.txt"
            original = root / "original-notes.txt"

            def swap() -> None:
                os.replace(victim, original)
                victim.write_text("replacement\n", encoding="utf-8")

            race, fired = self._racing_open("notes.txt", swap)
            with race, self.assertRaisesRegex(PackageError, "changed identity"):
                build_descriptor(root, kit_dir)
            self.assertTrue(fired())

    def test_already_read_payload_swap_before_traversal_completion_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            victim = kit_dir / "bin" / "setup.sh"
            original = root / "original-setup.sh"

            def swap() -> None:
                os.replace(victim, original)
                victim.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
                victim.chmod(0o755)

            # `bin/setup.sh` sorts before `data/`; replace the already-read
            # inode only when the walker later opens that sibling directory.
            race, fired = self._racing_open("data", swap)
            with race, self.assertRaisesRegex(PackageError, "after initial inventory"):
                build_descriptor(root, kit_dir)
            self.assertTrue(fired())

    def test_payload_directory_symlink_swap_between_stat_and_open_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            victim = kit_dir / "data"
            original = root / "original-data"

            def swap() -> None:
                os.replace(victim, original)
                os.symlink(original, victim)

            race, fired = self._racing_open("data", swap)
            with race, self.assertRaisesRegex(PackageError, "securely open directory"):
                build_descriptor(root, kit_dir)
            self.assertTrue(fired())

    def test_descriptor_symlink_swap_between_stat_and_open_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            victim = kit_dir / DESCRIPTOR_NAME
            original = root / "original-descriptor.json"

            def swap() -> None:
                os.replace(victim, original)
                os.symlink(original, victim)

            race, fired = self._racing_open(DESCRIPTOR_NAME, swap)
            with race, self.assertRaisesRegex(PackageError, "securely open regular"):
                validate_descriptor(root, kit_dir)
            self.assertTrue(fired())

    def test_bundle_inode_swap_between_stat_and_open_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            victim = kit_dir / "kit.toml.sigstore"
            original = root / "original-bundle.sigstore"

            def swap() -> None:
                os.replace(victim, original)
                victim.write_bytes(_fixture_bundle(b"replacement"))

            race, fired = self._racing_open("kit.toml.sigstore", swap)
            with race, self.assertRaisesRegex(PackageError, "changed identity"):
                build_descriptor(root, kit_dir)
            self.assertTrue(fired())


class DescriptorValidationTests(unittest.TestCase):
    def test_published_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)

            state, generated = _check_catalog(root)

        self.assertEqual("published", state)
        self.assertEqual(1, len(generated))

    def test_legacy_only_requires_explicit_bootstrap_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_kit(root)
            with self.assertRaisesRegex(PackageError, "legacy-only package state"):
                _check_catalog(root)
            state, _ = _check_catalog(root, allow_legacy_only=True)
        self.assertEqual("legacy-only", state)

    def test_mixed_descriptor_without_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_kit(root)
            _generate_catalog(root)
            with self.assertRaisesRegex(PackageError, "mixed package migration state"):
                _check_catalog(root, allow_legacy_only=True)

    def test_active_state_missing_signature_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_kit(root)
            _generate_catalog(root)
            (root / PACKAGE_MARKER).write_bytes(PACKAGE_MARKER_BYTES)
            with self.assertRaisesRegex(PackageError, "missing, extra, or misplaced"):
                _check_catalog(root)

    def test_invalid_activation_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            (root / PACKAGE_MARKER).write_text("legacy", encoding="utf-8")
            with self.assertRaisesRegex(PackageError, "marker bytes are invalid"):
                _check_catalog(root)

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
                _check_catalog(root)


class CandidateStateTests(unittest.TestCase):
    def test_version_gate_uses_committed_head_not_a_pathname_swap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            base = _commit_fixture(root)
            (kit_dir / "data" / "notes.txt").write_text("changed\n", encoding="utf-8")
            _commit_changes(root)
            manifest = kit_dir / "kit.toml"
            real_read_bytes = Path.read_bytes
            bumped = manifest.read_bytes().replace(b"1.0.0", b"1.0.1")

            def swapped_read(path: Path) -> bytes:
                if path == manifest:
                    return bumped
                return real_read_bytes(path)

            with (
                patch.object(Path, "read_bytes", swapped_read),
                self.assertRaisesRegex(PackageError, "without changing kit.version"),
            ):
                _ci_check(root, base)
            self.assertIn('version = "1.0.0"', manifest.read_text(encoding="utf-8"))

    def test_bootstrap_publication_shape_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _commit_fixture(root)
            _publish(root, kit_dir)

            state, paths = _publication_check(root)

        self.assertEqual("bootstrap-publication", state)
        self.assertEqual(
            {
                PACKAGE_MARKER,
                f"kits/demo/{DESCRIPTOR_NAME}",
                f"kits/demo/{DESCRIPTOR_SIGNATURE_NAME}",
            },
            set(paths),
        )

    def test_bootstrap_rejects_a_refreshed_legacy_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _commit_fixture(root)
            legacy = kit_dir / "kit.toml.sigstore"
            bundle = json.loads(legacy.read_text(encoding="utf-8"))
            bundle["verificationMaterial"]["tlogEntries"][0]["refresh"] = True
            legacy.write_text(json.dumps(bundle), encoding="utf-8")
            _publish(root, kit_dir)

            with self.assertRaisesRegex(PackageError, "bootstrap must publish exactly"):
                _publication_check(root)

    def test_publication_shape_rejects_an_unrelated_root_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _commit_fixture(root)
            _publish(root, kit_dir)
            (root / "unrelated.txt").write_text("not signer output\n", encoding="utf-8")

            with self.assertRaisesRegex(PackageError, "unauthorized worktree"):
                _publication_check(root)

    def test_payload_change_requires_version_bump(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            base = _commit_fixture(root)
            (kit_dir / "data" / "notes.txt").write_text("changed\n", encoding="utf-8")
            _commit_changes(root)

            with self.assertRaisesRegex(PackageError, "without changing kit.version"):
                _ci_check(root, base)

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

            state, generated = _ci_check(root, base)

            (kit_dir / "kit.toml.sigstore").write_bytes(
                _fixture_bundle(manifest.read_bytes())
            )
            _generate_catalog(root)
            descriptor = (kit_dir / DESCRIPTOR_NAME).read_bytes()
            (kit_dir / DESCRIPTOR_SIGNATURE_NAME).write_bytes(
                _fixture_bundle(descriptor)
            )
            published_state, _ = _check_catalog(root)

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

            with (
                patch.dict(os.environ, {"GITHUB_ACTOR": "github-actions[bot]"}),
                self.assertRaisesRegex(PackageError, "main signing workflow"),
            ):
                _ci_check(root, base)

    def test_activation_marker_downgrade_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kit_dir = _write_kit(root)
            _publish(root, kit_dir)
            base = _commit_fixture(root)
            (root / PACKAGE_MARKER).unlink()
            _commit_changes(root)

            with self.assertRaisesRegex(PackageError, "activation is monotonic"):
                _ci_check(root, base)

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


class FirstPublicationTests(unittest.TestCase):
    """The first-publication-pending state: a new authorized kit graduates
    through an explicit signer path, never silently, and never opens a
    demotion hole for an already-published kit."""

    TWO = {"demo": "default/demo", "beta": "default/beta"}

    def test_new_kit_is_first_publication_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # demo is fully published; the marker is active.
            demo = _write_kit(root, "demo")
            _publish_single(root, demo)
            (root / PACKAGE_MARKER).write_bytes(PACKAGE_MARKER_BYTES)
            base = _commit_fixture(root)

            # beta enters as first-publication-pending: kit.toml + payload only.
            beta = _write_pending_kit(root, "beta")
            _commit_changes(root, "add beta (first-publication-pending)")

            kit_dirs = discover_kit_dirs(root, expected_identities=self.TWO)
            self.assertEqual(["beta", "demo"], sorted(k.name for k in kit_dirs))
            self.assertEqual({"beta"}, first_publication_pending(root, kit_dirs))

            # check (active): demo stays fully verified; beta is pending.
            state, generated = check_catalog(root, expected_identities=self.TWO)
            self.assertEqual("published", state)
            self.assertEqual(["demo"], [name for name, _ in generated])

            # ci-check: beta is a first-publication candidate → signing-pending.
            ci_state, ci_generated = ci_check(
                root, base, expected_identities=self.TWO
            )
            self.assertEqual("signing-pending", ci_state)
            self.assertEqual({"beta", "demo"}, {name for name, _ in ci_generated})

            # The signer mints all three artifacts on merge; beta graduates.
            beta_manifest = (beta / "kit.toml").read_bytes()
            (beta / "kit.toml.sigstore").write_bytes(_fixture_bundle(beta_manifest))
            _publish_single(root, beta)

            self.assertEqual(set(), first_publication_pending(root, kit_dirs))
            graduated, gen = check_catalog(root, expected_identities=self.TWO)
            self.assertEqual("published", graduated)
            self.assertEqual(["beta", "demo"], sorted(name for name, _ in gen))

    def test_pending_kit_with_descriptor_but_no_sigstore_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            demo = _write_kit(root, "demo")
            _publish_single(root, demo)
            (root / PACKAGE_MARKER).write_bytes(PACKAGE_MARKER_BYTES)

            # beta carries a descriptor but no legacy signature — the exact
            # shape of deleting a published kit's sigstore to swap its payload.
            beta = _write_pending_kit(root, "beta")
            _, beta_descriptor = build_descriptor(
                root, beta, require_legacy_signature=False
            )
            (beta / DESCRIPTOR_NAME).write_bytes(beta_descriptor)

            kit_dirs = discover_kit_dirs(root, expected_identities=self.TWO)
            with self.assertRaisesRegex(PackageError, "without a legacy signature"):
                first_publication_pending(root, kit_dirs)
            # The demotion-hole guard also fails the whole active check closed.
            with self.assertRaisesRegex(PackageError, "without a legacy signature"):
                check_catalog(root, expected_identities=self.TWO)


if __name__ == "__main__":
    unittest.main()
