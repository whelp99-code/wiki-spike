"""Existing-only admission for the Mac production Keychain adapter."""
from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from pathlib import Path

from wiki_spike.infrastructure.macos_keychain import (
    KeychainBackend,
    MacOSKeychainKeyStore,
    ProductionCustodyError,
    SecurityCliKeychainBackend,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

MAC_KEYCHAIN_SERVICE = "wiki-spike.second-brain-v1"
SERVING_ARK_HANDLE = "serving-ark-v1"

_OPAQUE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_INDEX_FIELDS = frozenset(
    {
        "ark_handle",
        "destroyed",
        "destroyed_at",
        "metadata_digest",
        "namespace",
        "receipt_digest",
    }
)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_INDEX_LIMIT = 4096


def _refuse(message: str) -> ProductionCustodyError:
    return ProductionCustodyError(f"existing Keychain {message}")


def _require_no_symlink_ancestor(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise _refuse(f"path is missing: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise _refuse(f"path would follow a symlink: {current}")


def _open_index_directory(path: Path) -> int:
    _require_no_symlink_ancestor(path)
    try:
        descriptor = os.open(path, _DIR_FLAGS)
    except OSError as exc:
        raise _refuse("index directory is unavailable") from exc
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.getuid():
        os.close(descriptor)
        raise _refuse("index owner is invalid")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise _refuse("index mode must be 0700")
    return descriptor


def _read_index(descriptor: int, name: str) -> bytes:
    try:
        file_descriptor = os.open(name, _FILE_FLAGS, dir_fd=descriptor)
    except OSError as exc:
        raise _refuse("record is unavailable") from exc
    try:
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise _refuse("record is not regular")
        if before.st_uid != os.getuid():
            raise _refuse("record owner is invalid")
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise _refuse("record mode must be 0600")
        if before.st_size > _INDEX_LIMIT:
            raise _refuse("record exceeds 4096 bytes")
        data = os.read(file_descriptor, before.st_size)
        if len(data) != before.st_size or os.read(file_descriptor, 1):
            raise _refuse("record read is unstable")
        after = os.fstat(file_descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise _refuse("record metadata changed during read")
        return data
    finally:
        os.close(file_descriptor)


def _text(mapping: dict[str, JsonValue], field: str) -> str:
    value = mapping[field]
    if not isinstance(value, str):
        raise _refuse(f"record {field} is invalid")
    return value


def _verify_index(raw: bytes, namespace: str, ark_handle: str) -> None:
    try:
        mapping = decode_json_object(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise _refuse("record is malformed") from exc
    if frozenset(mapping) != _INDEX_FIELDS or canonical_bytes(mapping) != raw:
        raise _refuse("record is non-canonical")
    if _text(mapping, "namespace") != namespace:
        raise _refuse("record namespace does not match")
    if _text(mapping, "ark_handle") != ark_handle:
        raise _refuse("record handle does not match")
    if _HEX_64.fullmatch(_text(mapping, "metadata_digest")) is None:
        raise _refuse("record metadata digest is invalid")
    if (
        mapping["destroyed"] is not False
        or mapping["destroyed_at"] is not None
        or mapping["receipt_digest"] is not None
    ):
        raise _refuse("record is not active")


def open_existing_macos_keychain_store(
    *,
    index_dir: Path,
    service: str,
    namespace: str,
    ark_handle: str,
    backend: KeychainBackend | None = None,
    keychain_directory: Path,
) -> MacOSKeychainKeyStore:
    """Validate one active production index without provisioning or commands."""
    if service != MAC_KEYCHAIN_SERVICE or ark_handle != SERVING_ARK_HANDLE:
        raise ProductionCustodyError(
            "fixed production Keychain service or handle does not match"
        )
    if _OPAQUE.fullmatch(namespace) is None:
        raise ProductionCustodyError("invalid opaque namespace")
    _require_no_symlink_ancestor(keychain_directory)
    directory_descriptor = _open_index_directory(index_dir)
    try:
        account = hashlib.sha256(f"{namespace}\0{ark_handle}".encode()).hexdigest()
        raw = _read_index(directory_descriptor, f"{account}.json")
    finally:
        os.close(directory_descriptor)
    _verify_index(raw, namespace, ark_handle)
    selected_backend = backend
    if selected_backend is None:
        if sys.platform != "darwin":
            raise ProductionCustodyError("macOS Keychain custody requires Darwin")
        selected_backend = SecurityCliKeychainBackend()
    store = MacOSKeychainKeyStore.__new__(MacOSKeychainKeyStore)
    store.index_dir = Path(index_dir)
    store.service = service
    store.backend = selected_backend
    store.keychain_directory = Path(keychain_directory)
    return store
