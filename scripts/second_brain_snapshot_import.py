#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=42"]
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly:
#      uv run scripts/second_brain_snapshot_import.py --help
# ──────────────────
"""Fixture-safe CLI for non-serving encrypted bounded snapshot import."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

type JsonValue = None | bool | str | list[JsonValue] | dict[str, JsonValue]

_ = sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


class SnapshotImportCliError(ValueError):
    """The CLI input or output boundary refused an operation."""


class _JsonLoads(Protocol):
    def __call__(
        self,
        s: str,
        *,
        object_pairs_hook: Callable[[list[tuple[str, JsonValue]]], dict[str, JsonValue]],
        parse_int: Callable[[str], JsonValue],
        parse_float: Callable[[str], JsonValue],
        parse_constant: Callable[[str], JsonValue],
    ) -> JsonValue: ...


class _Arguments(argparse.Namespace):
    """Mutable parse target owned exclusively by argparse."""

    request: Path = Path()
    snapshot: Path = Path()
    database: Path = Path()
    cas_root: Path = Path()
    output: Path = Path()
    profile: Path = Path()
    profile_receipt: Path = Path()
    owner_public_key: Path = Path()
    approver_public_key: Path = Path()
    sqlcipher_artifact: Path = Path()
    key_fd: int | None = None
    keychain_service: str | None = None
    keychain_account: str | None = None


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    parsed: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in parsed:
            raise SnapshotImportCliError(f"duplicate field: {key}")
        parsed[key] = value
    return parsed


def _reject_number(_raw: str) -> JsonValue:
    return "\0raw-number"


def _decode_json(loader: _JsonLoads, text: str) -> dict[str, JsonValue]:
    parsed = loader(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_int=_reject_number,
        parse_float=_reject_number,
        parse_constant=_reject_number,
    )
    if not isinstance(parsed, dict):
        raise SnapshotImportCliError("JSON must be an object")
    return parsed


def _load_json(path: Path) -> dict[str, JsonValue]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SnapshotImportCliError("JSON cannot be read") from exc
    return _decode_json(json.loads, text)


def _read_key(arguments: _Arguments) -> bytes:
    if arguments.key_fd is not None:
        if arguments.keychain_service is not None or arguments.keychain_account is not None:
            raise SnapshotImportCliError("key FD and Keychain options are mutually exclusive")
        try:
            data = os.read(arguments.key_fd, 32)
            extra = os.read(arguments.key_fd, 1)
        except OSError as exc:
            raise SnapshotImportCliError("inherited key FD cannot be read") from exc
        if len(data) != 32 or extra:
            raise SnapshotImportCliError("inherited key FD must supply exactly 32 bytes")
        return data
    if not arguments.keychain_service or not arguments.keychain_account:
        raise SnapshotImportCliError("a key FD or Keychain service/account is required")
    from wiki_spike.infrastructure.macos_keychain_backend import (
        SecurityCliKeychainBackend,
    )

    secret = SecurityCliKeychainBackend().read(
        service=arguments.keychain_service,
        account=arguments.keychain_account,
    )
    if secret is None:
        raise SnapshotImportCliError("Keychain did not yield a 32-byte import key")
    try:
        key = bytes.fromhex(secret)
    except ValueError as exc:
        raise SnapshotImportCliError("Keychain did not yield a 32-byte import key") from exc
    if len(key) != 32:
        raise SnapshotImportCliError("Keychain did not yield a 32-byte import key")
    return key


def _write_atomic_new(path: Path, payload: bytes) -> None:
    if not path.parent.is_dir():
        raise SnapshotImportCliError("output parent must be an existing directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise SnapshotImportCliError("output already exists; overwrite refused") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def _arguments() -> _Arguments:
    parser = argparse.ArgumentParser(
        description="Import a bounded snapshot into non-serving encrypted lifecycle storage."
    )
    _ = parser.add_argument("--request", required=True, type=Path)
    _ = parser.add_argument("--snapshot", required=True, type=Path)
    _ = parser.add_argument("--database", required=True, type=Path)
    _ = parser.add_argument("--cas-root", required=True, type=Path)
    _ = parser.add_argument("--output", required=True, type=Path)
    _ = parser.add_argument("--profile", required=True, type=Path)
    _ = parser.add_argument("--profile-receipt", required=True, type=Path)
    _ = parser.add_argument("--owner-public-key", required=True, type=Path)
    _ = parser.add_argument("--approver-public-key", required=True, type=Path)
    _ = parser.add_argument("--sqlcipher-artifact", required=True, type=Path)
    _ = parser.add_argument("--key-fd", type=int)
    _ = parser.add_argument("--keychain-service")
    _ = parser.add_argument("--keychain-account")
    arguments = _Arguments()
    _ = parser.parse_args(namespace=arguments)
    return arguments


def _sanitized(message: str) -> str:
    return "".join(character if character.isprintable() else "?" for character in message)


def _public_key(path: Path) -> Ed25519PublicKey:
    try:
        raw = bytes.fromhex(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError) as exc:
        raise SnapshotImportCliError("public key cannot be read") from exc
    if len(raw) != 32:
        raise SnapshotImportCliError("public key must be 32 raw Ed25519 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def main() -> int:
    from wiki_spike.applications.source_discovery_service import (
        SourceDiscoveryError,
        discover_source,
    )
    from wiki_spike.applications.source_import_service import (
        SourceImportError,
        SourceImportService,
    )
    from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
    from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
    from wiki_spike.infrastructure.persistence_profile import (
        PersistenceProfileAuthorizationError,
        verify_mac_persistence_profile,
    )
    from wiki_spike.infrastructure.snapshot_import_store import (
        LifecycleSnapshotImportStore,
        SnapshotImportStoreError,
    )
    from wiki_spike.memory_core.contracts import canonical_bytes
    from wiki_spike.memory_core.errors import CoreContractError
    from wiki_spike.memory_core.second_brain_persistence import (
        MacPersistenceProfileV1,
        PersistenceProfileReceiptV1,
    )
    from wiki_spike.memory_core.snapshot_import import (
        BoundedSnapshotV1,
        SnapshotImportRequestV1,
    )
    from wiki_spike.memory_core.source_discovery import SourceDiscoveryRequestV1

    arguments = _arguments()
    database = None
    try:
        request = SnapshotImportRequestV1.from_mapping(_load_json(arguments.request))
        snapshot = BoundedSnapshotV1.from_mapping(_load_json(arguments.snapshot))
        discovery = discover_source(
            SourceDiscoveryRequestV1.from_mapping(
                {
                    "request_version": "second-brain-source-discovery-request-v1",
                    "source_name": request.source_name,
                    "source_root": request.source_root,
                }
            )
        )
        key = _read_key(arguments)
        profile_body = _load_json(arguments.profile)
        receipt_body = _load_json(arguments.profile_receipt)
        owner = _public_key(arguments.owner_public_key)
        approver = _public_key(arguments.approver_public_key)
        database = LifecycleDatabase(arguments.database)
        database.initialize()
        cas = EncryptedContentStore(arguments.cas_root)
        profile = verify_mac_persistence_profile(
            profile=MacPersistenceProfileV1.from_mapping(profile_body),
            receipt=PersistenceProfileReceiptV1.from_mapping(receipt_body),
            owner_public_key=owner,
            approver_public_key=approver,
            sqlcipher_artifact_path=arguments.sqlcipher_artifact,
            database=database,
            cas=cas,
        )
        store = LifecycleSnapshotImportStore(
            database=database,
            cas=cas,
            persistence_profile=profile,
            encryption_key=key,
        )
        receipt = SourceImportService(store=store, max_file_bytes=1024 * 1024).import_snapshot(
            request=request,
            snapshot=snapshot,
            discovery=discovery,
        )
        payload = canonical_bytes(receipt.to_mapping()) + b"\n"
        _write_atomic_new(arguments.output, payload)
        sys.stdout.buffer.write(payload)
    except json.JSONDecodeError:
        print("snapshot import refused: request JSON is invalid", file=sys.stderr)
        return 2
    except OSError:
        print("snapshot import refused: filesystem operation failed", file=sys.stderr)
        return 2
    except (
        CoreContractError,
        SourceDiscoveryError,
        SourceImportError,
        SnapshotImportStoreError,
        SnapshotImportCliError,
        PersistenceProfileAuthorizationError,
    ) as exc:
        print(f"snapshot import refused: {_sanitized(str(exc))}", file=sys.stderr)
        return 2
    finally:
        if database is not None:
            database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
