#!/usr/bin/env python3
"""User-run signer for aggregate and evidence resolver payloads."""
from __future__ import annotations

import argparse
import base64
import hmac
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_SIGNATURE_VERSION,
    CONTRACT_SIGNING_DOMAIN,
    Ed25519SignatureEnvelopeV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import (
    decode_json_object,
)

Role = Literal["approver", "owner"]
_ROLES: Final = ("approver", "owner")
_EVIDENCE_VERSION: Final = "second-brain-evidence-manifest-signature-v1"
_EVIDENCE_DOMAIN: Final = b"wiki-spike.second-brain.evidence-manifest.v1\x00"

type JsonObject = dict[str, JsonValue]


class ResolverRoleSignerError(Exception):
    """A resolver role-signature request failed closed."""


@dataclass(frozen=True, slots=True)
class Arguments:
    role: Role
    key_id: str
    expected_public_key_b64: str
    private_key: Path
    resolver_signing_dir: Path
    output_directory: Path


class _Parsed(argparse.Namespace):
    role: str = ""
    key_id: str = ""
    expected_public_key_b64: str = ""
    private_key: Path = Path()
    resolver_signing_dir: Path = Path()
    output_directory: Path = Path()


def _arguments(argv: list[str] | None) -> Arguments:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--role", required=True, choices=_ROLES)
    _ = parser.add_argument("--key-id", required=True)
    _ = parser.add_argument("--expected-public-key-b64", required=True)
    _ = parser.add_argument("--private-key", required=True, type=Path)
    _ = parser.add_argument("--resolver-signing-dir", required=True, type=Path)
    _ = parser.add_argument("--output-directory", required=True, type=Path)
    parsed = _Parsed()
    _ = parser.parse_args(argv, namespace=parsed)
    role: Role = "owner" if parsed.role == "owner" else "approver"
    return Arguments(
        role=role,
        key_id=parsed.key_id,
        expected_public_key_b64=parsed.expected_public_key_b64,
        private_key=parsed.private_key,
        resolver_signing_dir=parsed.resolver_signing_dir,
        output_directory=parsed.output_directory,
    )


def _load_json(path: Path) -> JsonObject:
    try:
        value = decode_json_object(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ResolverRoleSignerError("resolver payload cannot be read safely") from exc
    if path.read_bytes() != canonical_bytes(value):
        raise ResolverRoleSignerError("resolver payload must be canonical JSON")
    return value


def _private_key(path: Path) -> Ed25519PrivateKey:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ResolverRoleSignerError("private key is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ResolverRoleSignerError("private key must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ResolverRoleSignerError(
            "private key permissions must deny group and other access"
        )
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            loaded = serialization.load_pem_private_key(stream.read(), password=None)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ResolverRoleSignerError(
            "private key is not a usable unencrypted PEM key"
        ) from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ResolverRoleSignerError("private key must be Ed25519")
    return loaded


def _expected_public_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ResolverRoleSignerError(
            "trusted public binding is not valid base64"
        ) from exc
    if len(decoded) != 32:
        raise ResolverRoleSignerError(
            "trusted public binding must contain 32 bytes"
        )
    return decoded


def _write_new(path: Path, payload: bytes) -> None:
    if path.exists():
        if path.read_bytes() == payload:
            return
        raise ResolverRoleSignerError("existing resolver signature is stale")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            _ = stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise ResolverRoleSignerError(
            "resolver signature envelope cannot be written"
        ) from exc


def _envelope(
    arguments: Arguments,
    key: Ed25519PrivateKey,
    public_key: bytes,
    stem: str,
    version: str,
    domain: bytes,
) -> None:
    payload = _load_json(
        arguments.resolver_signing_dir / f"{stem}.payload.json"
    )
    envelope = {
        "key_id": arguments.key_id,
        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "role": arguments.role,
        "signature_b64": base64.b64encode(
            key.sign(domain + canonical_bytes(payload))
        ).decode("ascii"),
        "signature_version": version,
    }
    signature = Ed25519SignatureEnvelopeV1.from_mapping(
        envelope,
        version=version,
    )
    if not signature.verify(domain, payload):
        raise ResolverRoleSignerError("generated resolver signature is invalid")
    output = (
        arguments.output_directory
        / f"{stem}.{arguments.role}-envelope.json"
    )
    _write_new(output, canonical_bytes(envelope))


def sign(arguments: Arguments) -> None:
    if not arguments.output_directory.is_dir():
        raise ResolverRoleSignerError("output directory does not exist")
    key = _private_key(arguments.private_key)
    public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(
        public_key,
        _expected_public_key(arguments.expected_public_key_b64),
    ):
        raise ResolverRoleSignerError(
            "private key does not match the trusted public binding"
        )
    _envelope(
        arguments,
        key,
        public_key,
        "aggregate",
        CONTRACT_SIGNATURE_VERSION,
        CONTRACT_SIGNING_DOMAIN,
    )
    _envelope(
        arguments,
        key,
        public_key,
        "evidence-manifest",
        _EVIDENCE_VERSION,
        _EVIDENCE_DOMAIN,
    )


def main(argv: list[str] | None = None) -> int:
    try:
        sign(_arguments(argv))
    except ResolverRoleSignerError as exc:
        print(f"resolver role signing refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
