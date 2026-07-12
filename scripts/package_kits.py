#!/usr/bin/env python3
"""Build and validate deterministic signed-package descriptors for donmai kits.

The package contract is defined by the accepted architecture ADR:
`ADR-2026-07-10-deterministic-kit-packages-and-command-composition.md`.

This publisher-side tool deliberately separates these states:

* legacy-only bootstrap: every manifest has its historic manifest signature,
  and no package descriptor exists;
* first-publication-pending: an authorized kit that has never been signed. It
  carries only kit.toml plus payload — no legacy signature, no descriptor, no
  descriptor signature. Its payload/path closure and identity are validated,
  but it requires no descriptor to exist; the main-only signer mints the legacy
  signature, the descriptor, and the descriptor signature on merge, graduating
  it to published. A kit missing its legacy signature while still carrying a
  descriptor or descriptor signature is a demotion-hole attempt and is rejected;
* signing-pending candidate: the new payload produces a deterministic
  descriptor in memory while the on-disk descriptor/signature remain the
  previous self-consistent publication until the main-only signer runs; and
* published: every descriptor and both detached signature bundles are present,
  structurally bind their exact subjects, and the activation marker exists.

Only the signing workflow may move a kit from legacy-only or
first-publication-pending to published. The workflow additionally performs full
Sigstore trust verification; this pure-stdlib tool verifies bundle shape and
subject digest so local/PR drift checks remain hermetic.

The authorized-set expansion procedure — how a new directory enters
EXPECTED_KIT_IDENTITIES through an explicit, reviewed first-publication path
rather than silently — is defined by
`ADR-2026-07-12-kit-catalog-expansion.md`, which amends the deterministic
package contract in `ADR-2026-07-10-...`.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import unicodedata
from contextlib import ExitStack, contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping


PACKAGE_SCHEMA = "donmai.dev/kit-package/v1"
CATALOG_CANDIDATE_SCHEMA = "donmai.dev/kit-catalog-candidate/v1"
PACKAGE_MARKER = ".kit-package-v1-active"
PACKAGE_MARKER_BYTES = b'{"schema":"donmai.dev/kit-package/v1","state":"active"}'
MANIFEST_NAME = "kit.toml"
LEGACY_SIGNATURE_NAME = "kit.toml.sigstore"
DESCRIPTOR_NAME = "kit.package.json"
DESCRIPTOR_SIGNATURE_NAME = "kit.package.json.sigstore"
PACKAGE_METADATA_NAMES = {DESCRIPTOR_NAME, DESCRIPTOR_SIGNATURE_NAME}
EXPECTED_PUBLISHER = "did:web:donmai.dev"
EXPECTED_PACKAGE_SIGNER_POLICY = {
    "identity": "https://github.com/RenseiAI/donmai-kits/.github/workflows/sign.yml@refs/heads/main",
    "issuer": "https://token.actions.githubusercontent.com",
}
EXPECTED_MANIFEST_API = "rensei.dev/v1"
EXPECTED_KIT_IDENTITIES = {
    "go": "default/go",
    "java": "default/java",
    "python": "default/python",
    "ruby": "default/ruby",
    "rust": "default/rust",
    "swift": "default/swift",
    "ts-nextjs": "default/ts-nextjs",
    "typescript": "default/typescript",
}
SIGSTORE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FULL_GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_SAFE_INTEGER = (1 << 53) - 1
VERSION_CONTROL_NAMES = {".git", ".hg", ".svn"}
TEMP_SUFFIXES = (".partial", ".tmp")
TEMP_PREFIXES = (".tmp-", ".kit-staging-")
INSTALLER_MARKERS = {PACKAGE_MARKER, ".kit-installing", ".kit-generation"}
WINDOWS_RESERVED_BASENAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
    "com¹",
    "com²",
    "com³",
    "lpt¹",
    "lpt²",
    "lpt³",
}
FORBIDDEN_PATH_CHARS = set(':<>"|?*\\')

# Python 3.12 ships Unicode 15.0 data and Python 3.13 ships 15.1. The C+F
# mappings in CaseFolding.txt are byte-identical between those releases. This
# fingerprint pins the actual full case-fold mapping instead of trusting only
# a runtime version label.
ALLOWED_UNICODE_DATA_VERSIONS = {"15.0.0", "15.1.0"}
UNICODE_15_1_CASEFOLD_FINGERPRINT = (
    "2a17566332a6a1e32afbfd431f9c73a7f30caa22fb4ce881c4e35ebc2b7f2284"
)
HAS_SECURE_DIRFD_APIS = (
    os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.scandir in os.supports_fd
)


class PackageError(Exception):
    """A fail-closed package generation or validation error."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageError(message)


def _directory_open_flags() -> int:
    """Return the fail-closed flags required for descriptor-relative traversal."""
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    missing = [name for name in required if not hasattr(os, name)]
    _require(
        not missing,
        f"secure package traversal is unsupported on this host (missing {missing})",
    )
    _require(
        HAS_SECURE_DIRFD_APIS,
        "secure package traversal requires openat/statat and fd-scandir support",
    )
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _regular_open_flags() -> int:
    _require(
        hasattr(os, "O_NOFOLLOW"),
        "secure package reads require O_NOFOLLOW support",
    )
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _stable_file_metadata(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _stat_at(directory_fd: int, name: str, label: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise PackageError(f"cannot stat {label}: {exc}") from exc


@contextmanager
def _open_root_directory(root: Path) -> Iterator[int]:
    """Open the repository root without following its final path component."""
    try:
        before = root.lstat()
        descriptor = os.open(root, _directory_open_flags())
    except OSError as exc:
        raise PackageError(f"cannot securely open package root {root}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(before.st_mode)
            and stat.S_ISDIR(opened.st_mode)
            and _same_inode(before, opened),
            f"package root {root} changed identity while opening",
        )
        yield descriptor
        after = root.lstat()
        _require(
            _same_inode(opened, after) and stat.S_ISDIR(after.st_mode),
            f"package root {root} changed identity during traversal",
        )
    except OSError as exc:
        raise PackageError(f"cannot revalidate package root {root}: {exc}") from exc
    finally:
        os.close(descriptor)


@contextmanager
def _open_directory_at(
    parent_fd: int,
    name: str,
    label: str,
    *,
    expected: os.stat_result | None = None,
) -> Iterator[int]:
    """Open one child directory by dirfd and bind it to the lstat inode."""
    before = expected if expected is not None else _stat_at(parent_fd, name, label)
    _require(stat.S_ISDIR(before.st_mode), f"{label} is not a directory")
    try:
        descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise PackageError(f"cannot securely open directory {label}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(opened.st_mode) and _same_inode(before, opened),
            f"directory {label} changed identity while opening",
        )
        yield descriptor
        after = _stat_at(parent_fd, name, label)
        _require(
            stat.S_ISDIR(after.st_mode) and _same_inode(opened, after),
            f"directory {label} changed identity during traversal",
        )
    finally:
        os.close(descriptor)


@contextmanager
def _open_relative_directory(root: Path, parts: tuple[str, ...]) -> Iterator[int]:
    """Open every path component relative to a held repository-root dirfd."""
    with _open_root_directory(root) as root_fd, ExitStack() as stack:
        current_fd = root_fd
        walked: list[str] = []
        for part in parts:
            _require(part not in {"", ".", ".."}, "invalid secure path component")
            walked.append(part)
            current_fd = stack.enter_context(
                _open_directory_at(current_fd, part, "/".join(walked))
            )
        yield current_fd


def _relative_parts(root: Path, path: Path) -> tuple[str, ...]:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise PackageError(f"path {path} is outside package root {root}") from exc
    _require(relative.parts, f"path {path} does not name a package file")
    return relative.parts


def _read_regular_at(
    directory_fd: int,
    name: str,
    label: str,
) -> tuple[bytes, os.stat_result]:
    """Read a regular file through O_NOFOLLOW and reject inode/content swaps."""
    before = _stat_at(directory_fd, name, label)
    _require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    _require(before.st_nlink == 1, f"{label} is hard-linked")
    try:
        descriptor = os.open(name, _regular_open_flags(), dir_fd=directory_fd)
    except OSError as exc:
        raise PackageError(f"cannot securely open regular file {label}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and _same_inode(before, opened),
            f"regular file {label} changed identity while opening",
        )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        after_path = _stat_at(directory_fd, name, label)
        _require(
            _stable_file_metadata(before)
            == _stable_file_metadata(opened)
            == _stable_file_metadata(after_read)
            == _stable_file_metadata(after_path),
            f"regular file {label} changed while reading",
        )
        data = b"".join(chunks)
        _require(
            len(data) == after_read.st_size,
            f"regular file {label} size changed while reading",
        )
        return data, after_read
    finally:
        os.close(descriptor)


def _read_regular_file(root: Path, path: Path) -> tuple[bytes, os.stat_result]:
    parts = _relative_parts(root, path)
    with _open_relative_directory(root, parts[:-1]) as directory_fd:
        return _read_regular_at(
            directory_fd, parts[-1], path.relative_to(root).as_posix()
        )


def _read_optional_root_file(root: Path, name: str) -> bytes | None:
    """Read an optional repository-root file without following or racing links."""
    with _open_relative_directory(root, ()) as root_fd:
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise PackageError(f"cannot stat {name}: {exc}") from exc
        return _read_regular_at(root_fd, name, name)[0]


@lru_cache(maxsize=1)
def verify_unicode_profile() -> None:
    """Pin the portable collision key to Unicode 15.1 C+F semantics."""
    _require(
        unicodedata.unidata_version in ALLOWED_UNICODE_DATA_VERSIONS,
        "Unicode data version "
        f"{unicodedata.unidata_version!r} is not the package-v1 15.0/15.1 profile",
    )
    digest = hashlib.sha256()
    mapping_count = 0
    for codepoint in range(sys.maxunicode + 1):
        source = chr(codepoint)
        folded = source.casefold()
        if folded == source:
            continue
        digest.update(f"{codepoint:06X};".encode("ascii"))
        digest.update(" ".join(f"{ord(char):06X}" for char in folded).encode("ascii"))
        digest.update(b"\n")
        mapping_count += 1
    _require(mapping_count == 1530, "Unicode case-fold mapping count drifted")
    _require(
        digest.hexdigest() == UNICODE_15_1_CASEFOLD_FINGERPRINT,
        "Unicode case-fold mappings do not match the package-v1 Unicode 15.1 profile",
    )


def portable_collision_key(path: str) -> str:
    verify_unicode_profile()
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", path).casefold())


def validate_portable_path(path: str, *, allow_root_metadata: bool = False) -> str:
    """Validate one package-relative path and return its portable collision key."""
    _require(path != "", "package path must be non-empty")
    _require(
        path == unicodedata.normalize("NFC", path), f"path {path!r} is not UTF-8 NFC"
    )
    _require(not path.startswith("/"), f"path {path!r} must be relative")
    _require("\\" not in path, f"path {path!r} contains a backslash")
    segments = path.split("/")
    _require(
        all(segment not in {"", ".", ".."} for segment in segments),
        f"path {path!r} contains an empty, dot, or dot-dot segment",
    )

    for segment in segments:
        _require(
            not any(
                char in FORBIDDEN_PATH_CHARS or ord(char) < 32 or ord(char) == 127
                for char in segment
            ),
            f"path {path!r} contains a forbidden Windows/control character",
        )
        _require(
            not segment.endswith((".", " ")),
            f"path {path!r} contains a segment ending in dot or space",
        )
        folded_segment = portable_collision_key(segment)
        basename = folded_segment.split(".", 1)[0]
        _require(
            basename not in WINDOWS_RESERVED_BASENAMES,
            f"path {path!r} contains reserved Windows device basename {segment!r}",
        )
        _require(
            folded_segment not in VERSION_CONTROL_NAMES,
            f"path {path!r} contains version-control metadata",
        )
        _require(
            folded_segment not in INSTALLER_MARKERS,
            f"path {path!r} contains an installer marker",
        )
        _require(
            not folded_segment.startswith(TEMP_PREFIXES),
            f"path {path!r} contains a temporary-file prefix",
        )
        _require(
            not folded_segment.endswith(TEMP_SUFFIXES),
            f"path {path!r} contains a temporary-file suffix",
        )

    metadata_match = any(
        portable_collision_key(segment) in PACKAGE_METADATA_NAMES
        for segment in segments
    )
    if metadata_match:
        _require(
            allow_root_metadata
            and len(segments) == 1
            and path in PACKAGE_METADATA_NAMES,
            f"path {path!r} uses reserved package metadata name",
        )
    return portable_collision_key(path)


def ensure_unique_portable_paths(paths: Iterable[str]) -> None:
    """Reject two lexical paths that collapse to one package-v1 collision key."""
    owners: dict[str, str] = {}
    for path in paths:
        key = validate_portable_path(path)
        previous = owners.get(key)
        _require(
            previous is None, f"portable path collision: {previous!r} and {path!r}"
        )
        owners[key] = path


def _validate_i_json_subset(value: Any, location: str = "$") -> None:
    """Reject values outside the package schema's deterministic I-JSON subset."""
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        _require(
            -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER,
            f"{location} integer is outside the interoperable I-JSON range",
        )
        return
    if isinstance(value, float):
        raise PackageError(f"{location} floating-point values are not package-v1 JSON")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_i_json_subset(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _require(isinstance(key, str), f"{location} object key must be a string")
            _validate_i_json_subset(item, f"{location}.{key}")
        return
    raise PackageError(f"{location} has unsupported JSON type {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize the package-v1 I-JSON subset as RFC 8785 canonical bytes."""
    _validate_i_json_subset(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PackageError(f"value is not canonical I-JSON: {exc}") from exc
    return encoded


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PackageError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def strict_json_loads(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, PackageError) as exc:
        if isinstance(exc, PackageError):
            raise
        raise PackageError(f"{label} is not valid UTF-8 JSON: {exc}") from exc


def _decode_base64(value: Any, label: str) -> bytes:
    _require(
        isinstance(value, str) and value != "", f"{label} must be non-empty base64"
    )
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PackageError(f"{label} is not valid base64") from exc


def validate_sigstore_bundle(
    root: Path,
    bundle_path: Path,
    subject: bytes,
    *,
    require_subject_match: bool = True,
) -> bytes:
    """Validate bundle-v0.3 shape and, when required, its embedded subject digest.

    This is intentionally not a trust-root or certificate-policy verification;
    the signing workflow runs `cosign verify-blob` for that boundary.
    """
    raw, _ = _read_regular_file(root, bundle_path)
    bundle = strict_json_loads(raw, bundle_path.name)
    _require(isinstance(bundle, dict), f"{bundle_path.name} must be a JSON object")
    _require(
        bundle.get("mediaType") == SIGSTORE_MEDIA_TYPE,
        f"{bundle_path.name} must use Sigstore bundle v0.3",
    )
    message_signature = bundle.get("messageSignature")
    _require(
        isinstance(message_signature, dict),
        f"{bundle_path.name}.messageSignature must be an object",
    )
    _decode_base64(
        message_signature.get("signature"),
        f"{bundle_path.name}.messageSignature.signature",
    )
    message_digest = message_signature.get("messageDigest")
    _require(
        isinstance(message_digest, dict),
        f"{bundle_path.name}.messageSignature.messageDigest must be an object",
    )
    _require(
        message_digest.get("algorithm") == "SHA2_256",
        f"{bundle_path.name} must bind a SHA2_256 subject digest",
    )
    embedded_digest = _decode_base64(
        message_digest.get("digest"),
        f"{bundle_path.name}.messageSignature.messageDigest.digest",
    )
    _require(
        len(embedded_digest) == 32,
        f"{bundle_path.name} subject digest must be 32 bytes",
    )
    if require_subject_match:
        _require(
            embedded_digest == hashlib.sha256(subject).digest(),
            f"{bundle_path.name} subject digest does not match its exact artifact bytes",
        )
    verification = bundle.get("verificationMaterial")
    _require(
        isinstance(verification, dict),
        f"{bundle_path.name}.verificationMaterial must be an object",
    )
    certificate = verification.get("certificate")
    _require(
        isinstance(certificate, dict),
        f"{bundle_path.name}.verificationMaterial.certificate must be an object",
    )
    _decode_base64(
        certificate.get("rawBytes"),
        f"{bundle_path.name}.verificationMaterial.certificate.rawBytes",
    )
    tlog_entries = verification.get("tlogEntries")
    _require(
        isinstance(tlog_entries, list) and len(tlog_entries) > 0,
        f"{bundle_path.name}.verificationMaterial.tlogEntries must be non-empty",
    )
    return raw


def _git_mode_map(root: Path) -> dict[str, str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--stage", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return {}
    modes: dict[str, str] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode = metadata.split(b" ", 1)[0].decode("ascii")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise PackageError("git index contains an unsupported path record") from exc
        modes[path] = mode
    return modes


def _portable_mode(
    repo_path: str, info: os.stat_result, git_modes: dict[str, str]
) -> str:
    git_mode = git_modes.get(repo_path)
    if git_mode is not None:
        _require(
            git_mode in {"100644", "100755"},
            f"{repo_path} has unsupported git mode {git_mode}",
        )
        portable = "0755" if git_mode == "100755" else "0644"
        if os.name != "nt":
            filesystem_mode = "0755" if info.st_mode & 0o111 else "0644"
            _require(
                filesystem_mode == portable,
                f"{repo_path} filesystem executable bit does not match git mode {git_mode}",
            )
        return portable
    return "0755" if info.st_mode & 0o111 else "0644"


def _walk_payload(root: Path, kit_dir: Path) -> list[dict[str, Any]]:
    git_modes = _git_mode_map(root)
    collision_owners: dict[str, str] = {}
    entries: list[dict[str, Any]] = []
    file_snapshots: dict[str, tuple[tuple[int, ...], str, int]] = {}

    kit_parts = _relative_parts(root, kit_dir)
    _require(
        len(kit_parts) == 2 and kit_parts[0] == "kits",
        f"kit directory {kit_dir} must be exactly under kits/<kit>",
    )

    def directory_names(directory_fd: int, label: str) -> list[str]:
        try:
            with os.scandir(directory_fd) as iterator:
                names = [entry.name for entry in iterator]
            return sorted(names, key=lambda name: name.encode("utf-8"))
        except (OSError, UnicodeEncodeError) as exc:
            raise PackageError(f"cannot enumerate {label}: {exc}") from exc

    def visit(directory_fd: int, prefix: str = "") -> None:
        label = f"kits/{kit_dir.name}/{prefix}".rstrip("/")
        initial_names = directory_names(directory_fd, label)
        for name in initial_names:
            rel_path = f"{prefix}/{name}" if prefix else name
            allow_metadata = prefix == "" and name in PACKAGE_METADATA_NAMES
            collision_key = validate_portable_path(
                rel_path, allow_root_metadata=allow_metadata
            )
            previous = collision_owners.get(collision_key)
            _require(
                previous is None,
                f"portable path collision: {previous!r} and {rel_path!r}",
            )
            collision_owners[collision_key] = rel_path
            info = _stat_at(directory_fd, name, rel_path)
            _require(
                not stat.S_ISLNK(info.st_mode),
                f"payload path {rel_path!r} is a symlink",
            )
            if stat.S_ISDIR(info.st_mode):
                repo_path = f"kits/{kit_dir.name}/{rel_path}"
                indexed_mode = git_modes.get(repo_path)
                _require(
                    indexed_mode is None,
                    f"{repo_path} has unsupported indexed directory/gitlink mode {indexed_mode}",
                )
                with _open_directory_at(
                    directory_fd, name, rel_path, expected=info
                ) as child_fd:
                    visit(child_fd, rel_path)
                continue
            _require(
                stat.S_ISREG(info.st_mode),
                f"payload path {rel_path!r} is not a regular file",
            )
            _require(info.st_nlink == 1, f"payload path {rel_path!r} is hard-linked")
            if rel_path in PACKAGE_METADATA_NAMES:
                continue
            data, stable_info = _read_regular_at(directory_fd, name, rel_path)
            _require(
                len(data) <= MAX_SAFE_INTEGER,
                f"payload path {rel_path!r} exceeds the interoperable size limit",
            )
            entries.append(
                {
                    "path": rel_path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                    "mode": _portable_mode(
                        f"kits/{kit_dir.name}/{rel_path}", stable_info, git_modes
                    ),
                }
            )
            file_snapshots[rel_path] = (
                _stable_file_metadata(stable_info),
                hashlib.sha256(data).hexdigest(),
                len(data),
            )
        _require(
            directory_names(directory_fd, label) == initial_names,
            f"payload directory {label} changed during enumeration",
        )

    with _open_relative_directory(root, kit_parts) as kit_fd:
        visit(kit_fd)
        for rel_path, (metadata, digest, size) in sorted(file_snapshots.items()):
            current, current_info = _read_regular_file(
                root, kit_dir.joinpath(*rel_path.split("/"))
            )
            _require(
                _stable_file_metadata(current_info) == metadata
                and len(current) == size
                and hashlib.sha256(current).hexdigest() == digest,
                f"payload path {rel_path!r} changed after initial inventory",
            )
    entries.sort(key=lambda entry: entry["path"].encode("utf-8"))
    return entries


def _manifest_identity(raw: bytes, label: str) -> tuple[str, str, str]:
    try:
        manifest = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PackageError(f"cannot parse {label}: {exc}") from exc
    kit = manifest.get("kit")
    _require(isinstance(kit, dict), f"{label} is missing [kit]")
    kit_id = kit.get("id")
    version = kit.get("version")
    publisher = kit.get("authorIdentity")
    _require(
        isinstance(kit_id, str) and kit_id != "", "manifest kit.id must be non-empty"
    )
    _require(
        isinstance(version, str) and version != "",
        "manifest kit.version must be non-empty",
    )
    _require(
        publisher == EXPECTED_PUBLISHER,
        f"manifest authorIdentity must be {EXPECTED_PUBLISHER!r}",
    )
    return kit_id, version, publisher


def build_descriptor(
    root: Path,
    kit_dir: Path,
    *,
    require_legacy_subject_match: bool = True,
    require_legacy_signature: bool = True,
) -> tuple[dict[str, Any], bytes]:
    """Build the canonical descriptor for one kit directory.

    A published or signing-pending kit carries `kit.toml.sigstore`, which is
    itself inventoried; `require_legacy_signature=True` (the default) validates
    and inventories it. A first-publication-pending kit has never been signed,
    so it carries no legacy bundle yet; passing `require_legacy_signature=False`
    validates only the manifest + payload closure and asserts the legacy bundle
    is genuinely absent from the inventory. The main-only signer mints the
    legacy bundle before it generates the on-disk descriptor, so the published
    descriptor always inventories it.
    """
    manifest_path = kit_dir / MANIFEST_NAME
    manifest_bytes, _ = _read_regular_file(root, manifest_path)
    required_payload: list[tuple[str, bytes]] = [(MANIFEST_NAME, manifest_bytes)]
    if require_legacy_signature:
        legacy_signature = kit_dir / LEGACY_SIGNATURE_NAME
        legacy_signature_bytes = validate_sigstore_bundle(
            root,
            legacy_signature,
            manifest_bytes,
            require_subject_match=require_legacy_subject_match,
        )
        required_payload.append((LEGACY_SIGNATURE_NAME, legacy_signature_bytes))
    kit_id, version, publisher = _manifest_identity(manifest_bytes, str(manifest_path))
    entries = _walk_payload(root, kit_dir)
    entry_by_path = {entry["path"]: entry for entry in entries}
    for path, data in required_payload:
        entry = entry_by_path.get(path)
        _require(entry is not None, f"payload inventory is missing required {path}")
        _require(
            entry["size"] == len(data)
            and entry["sha256"] == hashlib.sha256(data).hexdigest(),
            f"{path} changed between trust validation and payload inventory",
        )
    if not require_legacy_signature:
        _require(
            LEGACY_SIGNATURE_NAME not in entry_by_path,
            f"kits/{kit_dir.name} first-publication payload must not include "
            f"{LEGACY_SIGNATURE_NAME} before the signer mints it",
        )
    descriptor = {
        "schema": PACKAGE_SCHEMA,
        "kit": {"id": kit_id, "version": version},
        "publisher": publisher,
        "manifest": MANIFEST_NAME,
        "entries": entries,
    }
    return descriptor, canonical_json_bytes(descriptor)


def _entry_map(entries: Any, label: str) -> dict[str, dict[str, Any]]:
    _require(isinstance(entries, list), f"{label}.entries must be an array")
    result: dict[str, dict[str, Any]] = {}
    ordered_paths: list[str] = []
    for index, entry in enumerate(entries):
        _require(isinstance(entry, dict), f"{label}.entries[{index}] must be an object")
        _require(
            set(entry) == {"path", "sha256", "size", "mode"},
            f"{label}.entries[{index}] has unknown or missing fields",
        )
        path = entry.get("path")
        _require(
            isinstance(path, str), f"{label}.entries[{index}].path must be a string"
        )
        validate_portable_path(path)
        _require(
            path not in result, f"{label}.entries contains duplicate path {path!r}"
        )
        _require(
            isinstance(entry.get("sha256"), str)
            and SHA256_RE.fullmatch(entry["sha256"]),
            f"{label}.entries[{index}].sha256 must be lowercase hex SHA-256",
        )
        _require(
            isinstance(entry.get("size"), int)
            and not isinstance(entry["size"], bool)
            and 0 <= entry["size"] <= MAX_SAFE_INTEGER,
            f"{label}.entries[{index}].size must be an interoperable non-negative integer",
        )
        _require(
            entry.get("mode") in {"0644", "0755"},
            f"{label}.entries[{index}].mode must be 0644 or 0755",
        )
        result[path] = entry
        ordered_paths.append(path)
    _require(
        ordered_paths == sorted(ordered_paths, key=lambda path: path.encode("utf-8")),
        f"{label}.entries are not sorted by normalized UTF-8 path bytes",
    )
    return result


def validate_descriptor_structure(
    root: Path, kit_dir: Path
) -> tuple[bytes, dict[str, Any]]:
    descriptor_path = kit_dir / DESCRIPTOR_NAME
    raw, _ = _read_regular_file(root, descriptor_path)
    parsed = strict_json_loads(raw, str(descriptor_path))
    _require(isinstance(parsed, dict), f"{descriptor_path} must be a JSON object")
    _require(
        set(parsed) == {"schema", "kit", "publisher", "manifest", "entries"},
        f"{descriptor_path} has unknown or missing top-level fields",
    )
    _require(
        raw == canonical_json_bytes(parsed),
        f"{descriptor_path} is not exact RFC 8785 canonical JSON",
    )
    _require(
        parsed.get("schema") == PACKAGE_SCHEMA,
        f"{descriptor_path} has unsupported schema",
    )
    _require(
        parsed.get("manifest") == MANIFEST_NAME,
        f"{descriptor_path}.manifest must be {MANIFEST_NAME!r}",
    )
    _require(
        parsed.get("publisher") == EXPECTED_PUBLISHER,
        f"{descriptor_path}.publisher is not the official publisher",
    )
    _entry_map(parsed.get("entries"), str(descriptor_path))
    return raw, parsed


def validate_descriptor(root: Path, kit_dir: Path) -> bytes:
    descriptor_path = kit_dir / DESCRIPTOR_NAME
    raw, parsed = validate_descriptor_structure(root, kit_dir)
    actual_entries = _entry_map(parsed.get("entries"), str(descriptor_path))

    expected, expected_bytes = build_descriptor(root, kit_dir)
    expected_entries = _entry_map(expected["entries"], "generated descriptor")
    missing = sorted(set(expected_entries) - set(actual_entries))
    extra = sorted(set(actual_entries) - set(expected_entries))
    _require(not missing, f"{descriptor_path} is missing payload entries: {missing}")
    _require(not extra, f"{descriptor_path} contains extra payload entries: {extra}")
    for path, expected_entry in expected_entries.items():
        _require(
            actual_entries[path] == expected_entry,
            f"{descriptor_path} entry {path!r} digest/size/mode does not match payload",
        )
    _require(
        parsed.get("kit") == expected["kit"],
        f"{descriptor_path}.kit identity/version does not match kit.toml",
    )
    _require(
        raw == expected_bytes,
        f"{descriptor_path} differs from deterministic generation",
    )
    return raw


def discover_kit_dirs(
    root: Path,
    *,
    expected_identities: Mapping[str, str] = EXPECTED_KIT_IDENTITIES,
) -> list[Path]:
    kits_dir = root / "kits"
    _require(kits_dir.is_dir(), f"missing kits directory at {kits_dir}")
    manifests = sorted(kits_dir.glob(f"*/{MANIFEST_NAME}"))
    _require(manifests, f"no kits/*/{MANIFEST_NAME} manifests found")
    nested = sorted(kits_dir.rglob(MANIFEST_NAME))
    _require(
        manifests == nested, "kit manifests must live exactly at kits/<kit>/kit.toml"
    )
    kit_dirs = [manifest.parent for manifest in manifests]
    actual_names = {kit_dir.name for kit_dir in kit_dirs}
    expected_names = set(expected_identities)
    _require(
        actual_names == expected_names,
        "official package publication is frozen to the authorized kit set; "
        f"missing={sorted(expected_names - actual_names)}, "
        f"extra={sorted(actual_names - expected_names)}",
    )
    for kit_dir in kit_dirs:
        manifest_path = kit_dir / MANIFEST_NAME
        manifest_bytes, _ = _read_regular_file(root, manifest_path)
        kit_id, _, _ = _manifest_identity(manifest_bytes, str(manifest_path))
        _require(
            kit_id == expected_identities[kit_dir.name],
            f"kits/{kit_dir.name} must retain authorized kit.id "
            f"{expected_identities[kit_dir.name]!r}, got {kit_id!r}",
        )
    return kit_dirs


def _package_artifacts(root: Path) -> list[Path]:
    return sorted(
        path
        for path in (root / "kits").rglob("kit.package.json*")
        if path.name in PACKAGE_METADATA_NAMES
    )


def _kit_file_present(root: Path, kit_dir: Path, name: str) -> bool:
    """Report whether kits/<kit>/<name> exists, without following any link."""
    kit_parts = _relative_parts(root, kit_dir)
    with _open_relative_directory(root, kit_parts) as kit_fd:
        try:
            os.stat(name, dir_fd=kit_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise PackageError(
                f"cannot stat kits/{kit_dir.name}/{name}: {exc}"
            ) from exc
        return True


def first_publication_pending(root: Path, kit_dirs: Iterable[Path]) -> set[str]:
    """Return the authorized kits that have never been signed.

    A kit is *first-publication-pending* iff it is authorized (present in
    `discover_kit_dirs`) and carries no `kit.toml.sigstore` on disk. During that
    window it holds only `kit.toml` plus payload — and, as an invariant, none of
    the three trust artifacts. Because the descriptor inventories the legacy
    bundle, a kit that carries a descriptor or descriptor signature but no legacy
    signature can only be an attempt to delete a published kit's legacy bundle
    and swap its payload; it is rejected here (the demotion-hole guard) rather
    than silently treated as pending. On merge the signer mints all three
    artifacts and the kit graduates to published.
    """
    pending: set[str] = set()
    for kit_dir in kit_dirs:
        if _kit_file_present(root, kit_dir, LEGACY_SIGNATURE_NAME):
            continue
        for name in (DESCRIPTOR_NAME, DESCRIPTOR_SIGNATURE_NAME):
            _require(
                not _kit_file_present(root, kit_dir, name),
                f"kits/{kit_dir.name} carries {name} without a legacy signature; "
                "a first-publication-pending kit must hold none of "
                f"{{{LEGACY_SIGNATURE_NAME}, {DESCRIPTOR_NAME}, "
                f"{DESCRIPTOR_SIGNATURE_NAME}}}",
            )
        pending.add(kit_dir.name)
    return pending


def check_catalog(
    root: Path,
    *,
    allow_legacy_only: bool = False,
    expected_identities: Mapping[str, str] = EXPECTED_KIT_IDENTITIES,
) -> tuple[str, list[tuple[str, str]]]:
    kit_dirs = discover_kit_dirs(root, expected_identities=expected_identities)
    marker_bytes = _read_optional_root_file(root, PACKAGE_MARKER)
    artifacts = _package_artifacts(root)
    if marker_bytes is None:
        _require(
            not artifacts,
            "mixed package migration state: package artifacts exist without activation marker",
        )
        _require(
            allow_legacy_only,
            "legacy-only package state is not allowed after package-v1 activation",
        )
        generated = []
        for kit_dir in kit_dirs:
            _, descriptor_bytes = build_descriptor(root, kit_dir)
            generated.append(
                (kit_dir.name, hashlib.sha256(descriptor_bytes).hexdigest())
            )
        return "legacy-only", generated

    _require(
        marker_bytes == PACKAGE_MARKER_BYTES,
        "package activation marker bytes are invalid",
    )
    pending = first_publication_pending(root, kit_dirs)
    published = [kit_dir for kit_dir in kit_dirs if kit_dir.name not in pending]
    expected_artifacts = {
        kit_dir / name
        for kit_dir in published
        for name in (DESCRIPTOR_NAME, DESCRIPTOR_SIGNATURE_NAME)
    }
    # A first-publication-pending kit contributes zero artifacts (asserted by
    # first_publication_pending), so the published subset accounts for every
    # descriptor artifact on disk. The published subset stays fully verified.
    _require(
        set(artifacts) == expected_artifacts,
        "active package state has missing, extra, or misplaced descriptor artifacts",
    )

    generated = []
    for kit_dir in published:
        descriptor_bytes = validate_descriptor(root, kit_dir)
        generated.append((kit_dir.name, hashlib.sha256(descriptor_bytes).hexdigest()))
        signature_path = kit_dir / DESCRIPTOR_SIGNATURE_NAME
        validate_sigstore_bundle(root, signature_path, descriptor_bytes)
    return "published", generated


def _record_catalog_identity(
    identities: dict[tuple[str, str], str],
    identity: tuple[str, str],
    package_digest: str,
) -> None:
    """Reject duplicate or equivocating package identities in one snapshot."""
    prior_digest = identities.get(identity)
    if prior_digest is not None:
        _require(
            prior_digest == package_digest,
            "catalog candidate package equivocation for "
            f"{identity[0]!r} version {identity[1]!r}",
        )
        raise PackageError(
            "catalog candidate contains duplicate package identity "
            f"{identity[0]!r} version {identity[1]!r}"
        )
    identities[identity] = package_digest


def build_catalog_snapshot_candidate(
    root: Path,
    *,
    source_revision: str,
    sequence: int,
    descriptor_locators: Iterable[str] | None = None,
) -> tuple[bytes, str]:
    """Return an unsigned canonical catalog candidate and its SHA-256 digest.

    This is deliberately an offline precursor, not publication metadata. It
    consumes only a complete, already-published package state and does not
    write, sign, fetch, or assign trust to its result.
    """
    _require(
        isinstance(source_revision, str)
        and FULL_GIT_REVISION_RE.fullmatch(source_revision) is not None,
        "catalog source_revision must be a full lowercase 40-hex Git revision",
    )
    _require(
        isinstance(sequence, int)
        and not isinstance(sequence, bool)
        and 1 <= sequence <= MAX_SAFE_INTEGER,
        "catalog sequence must be a positive interoperable integer",
    )
    state, _ = check_catalog(root, expected_identities=EXPECTED_KIT_IDENTITIES)
    _require(state == "published", "catalog candidate requires published packages")

    # Only the published subset carries signed descriptors. A
    # first-publication-pending kit has none yet, so it never appears in a
    # catalog snapshot until it graduates to published.
    kit_dirs = discover_kit_dirs(root, expected_identities=EXPECTED_KIT_IDENTITIES)
    pending = first_publication_pending(root, kit_dirs)
    published_names = sorted(
        name for name in EXPECTED_KIT_IDENTITIES if name not in pending
    )

    if descriptor_locators is None:
        locators = [f"kits/{name}/{DESCRIPTOR_NAME}" for name in published_names]
    else:
        locators = list(descriptor_locators)
    _require(
        len(locators) == len(published_names),
        "catalog candidate must consume exactly the published descriptor count",
    )

    expected_locators = {
        f"kits/{name}/{DESCRIPTOR_NAME}" for name in published_names
    }
    seen_locators: set[str] = set()
    rows: list[dict[str, Any]] = []
    identities: dict[tuple[str, str], str] = {}
    for locator in locators:
        _require(isinstance(locator, str), "descriptor locator must be a string")
        locator_parent, separator, locator_name = locator.rpartition("/")
        _require(
            separator == "/" and locator_name == DESCRIPTOR_NAME,
            f"descriptor locator {locator!r} must name {DESCRIPTOR_NAME}",
        )
        validate_portable_path(locator_parent)
        _require(
            locator in expected_locators,
            f"descriptor locator {locator!r} is not an authorized published descriptor",
        )
        _require(
            locator not in seen_locators,
            f"catalog candidate contains duplicate descriptor locator {locator!r}",
        )
        seen_locators.add(locator)

        kit_dir = root / Path(locator).parent
        descriptor_bytes = validate_descriptor(root, kit_dir)
        descriptor = strict_json_loads(descriptor_bytes, locator)
        kit = descriptor["kit"]
        identity = (kit["id"], kit["version"])
        package_digest = hashlib.sha256(descriptor_bytes).hexdigest()
        _record_catalog_identity(identities, identity, package_digest)

        manifest_bytes, _ = _read_regular_file(root, kit_dir / descriptor["manifest"])
        try:
            manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise PackageError(f"cannot parse {locator} manifest: {exc}") from exc
        _require(
            manifest.get("api") == EXPECTED_MANIFEST_API,
            f"{locator} manifest api is not {EXPECTED_MANIFEST_API!r}",
        )
        manifest_entry = _entry_map(descriptor["entries"], locator).get(
            descriptor["manifest"]
        )
        _require(
            manifest_entry is not None
            and manifest_entry["sha256"] == hashlib.sha256(manifest_bytes).hexdigest(),
            f"{locator} manifest compatibility subject does not match its descriptor",
        )
        rows.append(
            {
                "kit": {"id": identity[0], "version": identity[1]},
                "descriptor": locator,
                "packageDigest": package_digest,
                "packageSignerPolicy": EXPECTED_PACKAGE_SIGNER_POLICY,
                "compatibility": {
                    "kitPackageSchema": PACKAGE_SCHEMA,
                    "kitManifestApi": EXPECTED_MANIFEST_API,
                },
            }
        )

    _require(
        seen_locators == expected_locators,
        "catalog candidate descriptor inventory is incomplete or substituted",
    )
    rows.sort(
        key=lambda row: (
            row["kit"]["id"].encode("utf-8"),
            row["kit"]["version"].encode("utf-8"),
            row["packageDigest"].encode("ascii"),
        )
    )
    candidate = {
        "schema": CATALOG_CANDIDATE_SCHEMA,
        "state": "unsigned-candidate",
        "sourceRevision": source_revision,
        "sequence": sequence,
        "packages": rows,
    }
    canonical = canonical_json_bytes(candidate)
    return canonical, hashlib.sha256(canonical).hexdigest()


def check_signing_candidate(
    root: Path,
    changed_kits: set[str],
    *,
    expected_identities: Mapping[str, str] = EXPECTED_KIT_IDENTITIES,
) -> tuple[str, list[tuple[str, str]]]:
    """Validate a pre-sign candidate without treating it as published.

    Three shapes of kit are accepted in one candidate:

    * A **first-publication-pending** kit (authorized, never signed) carries no
      descriptor yet. We validate only its payload/path closure and identity in
      memory; no descriptor is required. Its historical-identity reuse is
      enforced by the caller's version-bump gate.
    * A **changed already-published** kit keeps its previously published
      descriptor/signature pair in the human PR. We validate that pair against
      itself (so corruption is still rejected) and validate the new payload/path
      closure in memory; a version bump is required separately.
    * An **unchanged published** kit is validated exactly as published.

    The main-only signer then mints/refreshes the legacy signature, generates
    the final descriptor, signs it, and runs the strict published check before
    committing.
    """
    kit_dirs = discover_kit_dirs(root, expected_identities=expected_identities)
    _require(
        _read_optional_root_file(root, PACKAGE_MARKER) == PACKAGE_MARKER_BYTES,
        "signing candidate requires the active package-v1 marker",
    )
    first_publication = first_publication_pending(root, kit_dirs)
    published_dirs = [
        kit_dir for kit_dir in kit_dirs if kit_dir.name not in first_publication
    ]
    artifacts = _package_artifacts(root)
    expected_artifacts = {
        kit_dir / name
        for kit_dir in published_dirs
        for name in (DESCRIPTOR_NAME, DESCRIPTOR_SIGNATURE_NAME)
    }
    _require(
        set(artifacts) == expected_artifacts,
        "signing candidate has missing, extra, or misplaced package artifacts",
    )
    known_kits = {kit_dir.name for kit_dir in kit_dirs}
    _require(
        changed_kits <= known_kits,
        f"signing candidate references unknown kits: {sorted(changed_kits - known_kits)}",
    )

    generated: list[tuple[str, str]] = []
    for kit_dir in kit_dirs:
        signature_path = kit_dir / DESCRIPTOR_SIGNATURE_NAME
        if kit_dir.name in first_publication:
            # First publication: no descriptor exists yet. Validate the payload
            # and identity closure in memory only; the main-only signer mints
            # the legacy signature, descriptor, and descriptor signature.
            _, candidate_descriptor = build_descriptor(
                root,
                kit_dir,
                require_legacy_signature=False,
            )
            generated.append(
                (kit_dir.name, hashlib.sha256(candidate_descriptor).hexdigest())
            )
            continue
        if kit_dir.name not in changed_kits:
            descriptor_bytes = validate_descriptor(root, kit_dir)
            validate_sigstore_bundle(root, signature_path, descriptor_bytes)
            generated.append(
                (kit_dir.name, hashlib.sha256(descriptor_bytes).hexdigest())
            )
            continue

        published_descriptor, _ = validate_descriptor_structure(root, kit_dir)
        validate_sigstore_bundle(root, signature_path, published_descriptor)
        _, candidate_descriptor = build_descriptor(
            root,
            kit_dir,
            require_legacy_subject_match=False,
        )
        generated.append(
            (kit_dir.name, hashlib.sha256(candidate_descriptor).hexdigest())
        )
    return "signing-pending", generated


def generate_catalog(
    root: Path,
    *,
    expected_identities: Mapping[str, str] = EXPECTED_KIT_IDENTITIES,
) -> list[tuple[str, str]]:
    generated: list[tuple[str, str]] = []
    for kit_dir in discover_kit_dirs(root, expected_identities=expected_identities):
        _, raw = build_descriptor(root, kit_dir)
        target = kit_dir / DESCRIPTOR_NAME
        with tempfile.NamedTemporaryFile(
            dir=kit_dir, prefix=".tmp-package-", delete=False
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(raw)
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, target)
        generated.append((kit_dir.name, hashlib.sha256(raw).hexdigest()))
    return generated


def _git_output(root: Path, args: list[str]) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise PackageError(
            result.stderr.decode("utf-8", "replace").strip() or "git command failed"
        )
    return result.stdout


def _git_file(root: Path, revision: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return result.stdout if result.returncode == 0 else None


def _working_tree_paths(root: Path) -> list[str]:
    """Return ordinary porcelain-v1 paths and reject rename/copy ambiguity."""
    raw = _git_output(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    paths: list[str] = []
    for record in (record for record in raw.split(b"\0") if record):
        _require(
            len(record) >= 4 and record[2:3] == b" ",
            "publication worktree contains an unsupported git status record",
        )
        status_code = record[:2].decode("ascii", "strict")
        _require(
            "R" not in status_code and "C" not in status_code,
            "publication worktree may not contain renames or copies",
        )
        try:
            path = record[3:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PackageError(
                "publication worktree contains a non-UTF-8 path"
            ) from exc
        paths.append(path)
    _require(len(paths) == len(set(paths)), "publication worktree repeats a path")
    return sorted(paths)


def check_publication_worktree(
    root: Path,
    *,
    expected_identities: Mapping[str, str] = EXPECTED_KIT_IDENTITIES,
) -> tuple[str, list[str]]:
    """Validate the signer-only dirty shape after full cosign verification."""
    check_catalog(root, expected_identities=expected_identities)
    kit_names = sorted(expected_identities)
    allowed = {PACKAGE_MARKER}
    for kit_name in kit_names:
        allowed.update(
            {
                f"kits/{kit_name}/{LEGACY_SIGNATURE_NAME}",
                f"kits/{kit_name}/{DESCRIPTOR_NAME}",
                f"kits/{kit_name}/{DESCRIPTOR_SIGNATURE_NAME}",
            }
        )
    dirty_paths = _working_tree_paths(root)
    unauthorized = sorted(set(dirty_paths) - allowed)
    _require(
        not unauthorized,
        f"signer produced unauthorized worktree changes: {unauthorized}",
    )

    if _git_file(root, "HEAD", PACKAGE_MARKER) is None:
        expected_bootstrap = {PACKAGE_MARKER}
        for kit_name in kit_names:
            expected_bootstrap.update(
                {
                    f"kits/{kit_name}/{DESCRIPTOR_NAME}",
                    f"kits/{kit_name}/{DESCRIPTOR_SIGNATURE_NAME}",
                }
            )
        _require(
            set(dirty_paths) == expected_bootstrap,
            "package-v1 bootstrap must publish exactly the activation marker and "
            f"{len(kit_names) * 2} package descriptor artifacts; "
            f"missing={sorted(expected_bootstrap - set(dirty_paths))}, "
            f"extra={sorted(set(dirty_paths) - expected_bootstrap)}",
        )
        return "bootstrap-publication", dirty_paths
    return "publication-update", dirty_paths


def _manifest_version(raw: bytes, label: str) -> str:
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PackageError(f"cannot parse {label}: {exc}") from exc
    kit = parsed.get("kit")
    _require(
        isinstance(kit, dict) and isinstance(kit.get("version"), str),
        f"{label} has no string kit.version",
    )
    return kit["version"]


def _manifest_id_version(raw: bytes, label: str) -> tuple[str, str]:
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PackageError(f"cannot parse {label}: {exc}") from exc
    kit = parsed.get("kit")
    _require(isinstance(kit, dict), f"{label} has no [kit] table")
    kit_id = kit.get("id")
    version = kit.get("version")
    _require(
        isinstance(kit_id, str) and kit_id != "",
        f"{label} has no non-empty string kit.id",
    )
    _require(
        isinstance(version, str) and version != "",
        f"{label} has no non-empty string kit.version",
    )
    return kit_id, version


def _historical_id_versions(
    root: Path, base_ref: str
) -> dict[tuple[str, str], tuple[str, str]]:
    """Index every kit id/version reachable from the trusted base history."""
    revisions = (
        _git_output(root, ["log", "--format=%H", base_ref, "--", "kits"])
        .decode("ascii")
        .splitlines()
    )
    identities: dict[tuple[str, str], tuple[str, str]] = {}
    for revision in revisions:
        raw_paths = _git_output(
            root, ["ls-tree", "-r", "--name-only", "-z", revision, "--", "kits"]
        )
        try:
            tree_paths = [
                path.decode("utf-8") for path in raw_paths.split(b"\0") if path
            ]
        except UnicodeDecodeError as exc:
            raise PackageError(
                f"historical tree {revision} contains a non-UTF-8 path"
            ) from exc
        manifest_paths = sorted(
            path
            for path in tree_paths
            if path.count("/") == 2 and path.endswith(f"/{MANIFEST_NAME}")
        )
        for manifest_rel in manifest_paths:
            historical = _git_file(root, revision, manifest_rel)
            if historical is None:
                continue
            identity = _manifest_id_version(historical, f"{revision}:{manifest_rel}")
            identities.setdefault(identity, (revision, manifest_rel))
    return identities


def changed_paths(root: Path, base_ref: str) -> list[str]:
    raw = _git_output(
        root, ["diff", "--name-only", "-z", base_ref, "HEAD", "--", "kits"]
    )
    return [path.decode("utf-8") for path in raw.split(b"\0") if path]


def check_version_bumps(root: Path, base_ref: str, paths: Iterable[str]) -> None:
    generated_names = {
        LEGACY_SIGNATURE_NAME,
        DESCRIPTOR_NAME,
        DESCRIPTOR_SIGNATURE_NAME,
    }
    changed_kits: set[str] = set()
    for path in paths:
        parts = path.split("/")
        if len(parts) < 3 or parts[0] != "kits" or parts[-1] in generated_names:
            continue
        changed_kits.add(parts[1])
    if not changed_kits:
        return
    historical_id_versions = _historical_id_versions(root, base_ref)
    for kit_name in sorted(changed_kits):
        manifest_rel = f"kits/{kit_name}/{MANIFEST_NAME}"
        before = _git_file(root, base_ref, manifest_rel)
        current_raw = _git_file(root, "HEAD", manifest_rel)
        if current_raw is None:
            # A directory move presents as a deletion plus an addition. The
            # deleted side has no candidate version to inspect; the added side
            # is still checked against the full historical identity index.
            continue
        kit_id, new_version = _manifest_id_version(current_raw, manifest_rel)
        if before is not None:
            old_version = _manifest_version(before, f"{base_ref}:{manifest_rel}")
            _require(
                old_version != new_version,
                f"payload changed under kits/{kit_name} without changing kit.version ({new_version})",
            )
        reused_by = historical_id_versions.get((kit_id, new_version))
        _require(
            reused_by is None,
            f"kit identity/version ({kit_id!r}, {new_version!r}) for kits/{kit_name} "
            f"reuses historical publication {reused_by}",
        )


def ci_check(
    root: Path,
    base_ref: str,
    *,
    expected_identities: Mapping[str, str] = EXPECTED_KIT_IDENTITIES,
) -> tuple[str, list[tuple[str, str]]]:
    paths = changed_paths(root, base_ref)
    generated_names = {
        LEGACY_SIGNATURE_NAME,
        DESCRIPTOR_NAME,
        DESCRIPTOR_SIGNATURE_NAME,
    }
    generated_changes = sorted(
        path for path in paths if path.split("/")[-1] in generated_names
    )
    _require(
        not generated_changes,
        "package descriptors and detached signatures may change only inside the "
        "main signing workflow after exact cosign identity verification: "
        f"{generated_changes}",
    )
    base_marker = _git_file(root, base_ref, PACKAGE_MARKER)
    head_marker = _read_optional_root_file(root, PACKAGE_MARKER)
    _require(
        not (
            base_marker == PACKAGE_MARKER_BYTES and head_marker != PACKAGE_MARKER_BYTES
        ),
        "package-v1 activation is monotonic; deleting/downgrading the marker is forbidden",
    )
    check_version_bumps(root, base_ref, paths)

    if head_marker is None:
        return check_catalog(
            root,
            allow_legacy_only=base_marker is None,
            expected_identities=expected_identities,
        )

    changed_kits = {
        path.split("/")[1]
        for path in paths
        if path.startswith("kits/")
        and len(path.split("/")) >= 3
        and path.split("/")[-1] not in generated_names
    }
    if changed_kits:
        return check_signing_candidate(
            root, changed_kits, expected_identities=expected_identities
        )
    return check_catalog(root, expected_identities=expected_identities)


def _print_result(state: str, generated: list[tuple[str, str]]) -> None:
    for kit_name, digest in generated:
        print(f"OK    kits/{kit_name}/{DESCRIPTOR_NAME} sha256:{digest}")
    if state == "legacy-only":
        print(
            f"package_kits: legacy-only bootstrap accepted; {len(generated)} descriptors generated in memory"
        )
    elif state == "generated":
        print(f"package_kits: generated {len(generated)} canonical package descriptors")
    else:
        print(
            f"package_kits: {len(generated)}/{len(generated)} package descriptors passed ({state})"
        )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--allow-legacy-only", action="store_true")

    subparsers.add_parser("generate")
    subparsers.add_parser("publication-check")

    ci_parser = subparsers.add_parser("ci-check")
    ci_parser.add_argument("--base-ref", required=True)

    args = parser.parse_args(argv[1:])
    root = args.root.resolve()
    try:
        if args.command == "generate":
            generated = generate_catalog(root)
            _print_result("generated", generated)
            return 0
        if args.command == "publication-check":
            state, paths = check_publication_worktree(root)
            print(
                f"package_kits: {state} shape passed "
                f"({len(paths)} generated worktree paths)"
            )
            return 0
        if args.command == "ci-check":
            state, generated = ci_check(root, args.base_ref)
            _print_result(state, generated)
            return 0
        state, generated = check_catalog(
            root,
            allow_legacy_only=args.allow_legacy_only,
        )
        _print_result(state, generated)
        return 0
    except (OSError, PackageError) as exc:
        print(f"package_kits: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
