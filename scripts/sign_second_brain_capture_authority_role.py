#!/usr/bin/env python3
"""User-run signer for one trusted metadata-capture authority role."""
from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.second_brain_contracts import Ed25519SignatureEnvelopeV1
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    UnifiedDbMetadataCaptureOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_sign import (
    METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
    metadata_capture_authorization_signing_bytes,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

Role = Literal["approver", "owner"]
_ROLES: Final = ("approver", "owner")
_FILE_FLAGS: Final = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS: Final = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class CaptureAuthorityRoleSignerError(Exception):
    """The metadata-capture role signature request failed closed."""


@dataclass(frozen=True, slots=True)
class Arguments:
    role: Role
    key_id: str
    expected_public_key_b64: str
    body: Path
    private_key: Path
    output: Path


class _Parsed(argparse.Namespace):
    role: str = ""
    key_id: str = ""
    expected_public_key_b64: str = ""
    body: Path = Path()
    private_key: Path = Path()
    output: Path = Path()


def _arguments(argv: list[str] | None) -> Arguments:
    parser = argparse.ArgumentParser(
        description="Sign one inspected metadata-capture body without exporting a private key."
    )
    _ = parser.add_argument("--role", required=True, choices=_ROLES)
    _ = parser.add_argument("--key-id", required=True)
    _ = parser.add_argument("--expected-public-key-b64", required=True)
    _ = parser.add_argument("--body", required=True, type=Path)
    _ = parser.add_argument("--private-key", required=True, type=Path)
    _ = parser.add_argument("--output", required=True, type=Path)
    parsed = _Parsed()
    _ = parser.parse_args(argv, namespace=parsed)
    role_raw = parsed.role
    if role_raw == "owner":
        role: Role = "owner"
    elif role_raw == "approver":
        role = "approver"
    else:
        raise CaptureAuthorityRoleSignerError("unknown role")
    return Arguments(
        role,
        parsed.key_id,
        parsed.expected_public_key_b64,
        parsed.body,
        parsed.private_key,
        parsed.output,
    )


def _reject_symlink_output(path: Path) -> None:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            parent = current.parent
            if parent == current:
                return
            current = parent
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise CaptureAuthorityRoleSignerError("output would be a symlink")
        if current == path:
            raise CaptureAuthorityRoleSignerError("output already exists")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _body(path: Path) -> dict[str, JsonValue]:
    try:
        parsed = decode_json_object(path.read_text(encoding="utf-8"))
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(parsed)
    except (
        OSError,
        UnicodeError,
        UnifiedDbExportError,
        InvalidContractValue,
        UnknownContractField,
        UnsupportedContractVersion,
    ) as exc:
        raise CaptureAuthorityRoleSignerError(
            "authorization body cannot be read safely"
        ) from exc
    return parsed


def _private_key(path: Path) -> Ed25519PrivateKey:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CaptureAuthorityRoleSignerError("private key is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CaptureAuthorityRoleSignerError("private key must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CaptureAuthorityRoleSignerError(
            "private key permissions must deny group and other access"
        )
    try:
        descriptor = os.open(path, _READ_FLAGS)
        with os.fdopen(descriptor, "rb") as stream:
            loaded = serialization.load_pem_private_key(stream.read(), password=None)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CaptureAuthorityRoleSignerError(
            "private key is not a usable unencrypted PEM key"
        ) from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise CaptureAuthorityRoleSignerError("private key must be Ed25519")
    return loaded


def _expected_public_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise CaptureAuthorityRoleSignerError(
            "trusted public binding is not valid base64"
        ) from exc
    if len(decoded) != 32:
        raise CaptureAuthorityRoleSignerError(
            "trusted public binding must contain 32 bytes"
        )
    return decoded


def _write_new(path: Path, payload: bytes) -> None:
    if not path.parent.is_dir():
        raise CaptureAuthorityRoleSignerError("output parent directory does not exist")
    try:
        descriptor = os.open(path, _FILE_FLAGS, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            _ = stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise CaptureAuthorityRoleSignerError(
            "signature envelope cannot be written"
        ) from exc


def sign(arguments: Arguments) -> None:
    _reject_symlink_output(arguments.output)
    if not arguments.output.parent.is_dir():
        raise CaptureAuthorityRoleSignerError("output parent directory does not exist")
    body = _body(arguments.body)
    key = _private_key(arguments.private_key)
    public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(public_key, _expected_public_key(arguments.expected_public_key_b64)):
        raise CaptureAuthorityRoleSignerError(
            "private key does not match the trusted public binding"
        )
    envelope = {
        "key_id": arguments.key_id,
        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "role": arguments.role,
        "signature_b64": base64.b64encode(
            key.sign(metadata_capture_authorization_signing_bytes(body))
        ).decode("ascii"),
        "signature_version": METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
    }
    _ = Ed25519SignatureEnvelopeV1.from_mapping(
        envelope,
        version=METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
    )
    payload = (
        json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    _write_new(arguments.output, payload)


def main(argv: list[str] | None = None) -> int:
    try:
        sign(_arguments(argv))
    except CaptureAuthorityRoleSignerError as exc:
        print(f"metadata capture signing refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
