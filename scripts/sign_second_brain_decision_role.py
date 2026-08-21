#!/usr/bin/env python3
"""User-run signer for one trusted Second Brain decision role."""
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
from typing import Final, Literal, cast

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    DECISION_SIGNATURE_VERSION,
    DECISION_SIGNING_DOMAIN,
    Ed25519SignatureEnvelopeV1,
)

Role = Literal["approver", "owner"]
_ROLES: Final = frozenset({"approver", "owner"})


class DecisionRoleSignerError(ValueError):
    """The role signature request failed closed."""


@dataclass(frozen=True, slots=True)
class Arguments:
    role: Role
    key_id: str
    expected_public_key_b64: str
    body: Path
    private_key: Path
    output: Path


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DecisionRoleSignerError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _arguments(argv: list[str] | None) -> Arguments:
    parser = argparse.ArgumentParser(
        description="Sign one inspected decision body without exporting a private key."
    )
    parser.add_argument("--role", required=True, choices=sorted(_ROLES))
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--expected-public-key-b64", required=True)
    parser.add_argument("--body", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parsed = parser.parse_args(argv)
    return Arguments(
        cast(Role, parsed.role),
        cast(str, parsed.key_id),
        cast(str, parsed.expected_public_key_b64),
        cast(Path, parsed.body),
        cast(Path, parsed.private_key),
        cast(Path, parsed.output),
    )


def _body(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicates,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise DecisionRoleSignerError("decision body cannot be read safely") from exc
    if not isinstance(value, dict):
        raise DecisionRoleSignerError("decision body must be a JSON object")
    if "signatures" in value:
        raise DecisionRoleSignerError("decision body must not contain signatures")
    return value


def _private_key(path: Path) -> Ed25519PrivateKey:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise DecisionRoleSignerError("private key is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise DecisionRoleSignerError("private key must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise DecisionRoleSignerError("private key permissions must deny group and other access")
    try:
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise DecisionRoleSignerError("private key is not a usable unencrypted PEM key") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise DecisionRoleSignerError("private key must be Ed25519")
    return loaded


def _expected_public_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise DecisionRoleSignerError("trusted public binding is not valid base64") from exc
    if len(decoded) != 32:
        raise DecisionRoleSignerError("trusted public binding must contain 32 bytes")
    return decoded


def _write_new(path: Path, payload: bytes) -> None:
    if path.exists():
        raise DecisionRoleSignerError("output already exists")
    if not path.parent.is_dir():
        raise DecisionRoleSignerError("output parent directory does not exist")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise DecisionRoleSignerError("signature envelope cannot be written") from exc


def _signing_bytes(body: dict[str, object]) -> bytes:
    return DECISION_SIGNING_DOMAIN + canonical_bytes(body)


def sign(arguments: Arguments) -> None:
    if arguments.output.exists():
        raise DecisionRoleSignerError("output already exists")
    if not arguments.output.parent.is_dir():
        raise DecisionRoleSignerError("output parent directory does not exist")
    body = _body(arguments.body)
    key = _private_key(arguments.private_key)
    public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(
        public_key,
        _expected_public_key(arguments.expected_public_key_b64),
    ):
        raise DecisionRoleSignerError("private key does not match the trusted public binding")
    envelope = {
        "key_id": arguments.key_id,
        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "role": arguments.role,
        "signature_b64": base64.b64encode(key.sign(_signing_bytes(body))).decode("ascii"),
        "signature_version": DECISION_SIGNATURE_VERSION,
    }
    Ed25519SignatureEnvelopeV1.from_mapping(
        envelope,
        version=DECISION_SIGNATURE_VERSION,
    )
    payload = (
        json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    _write_new(arguments.output, payload)


def main(argv: list[str] | None = None) -> int:
    try:
        sign(_arguments(argv))
    except DecisionRoleSignerError as exc:
        print(f"decision role signing refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
