#!/usr/bin/env python3
"""Public-only assemble/verify for Mac persistence receipts.

This tool never reads, holds, derives, or generates a private key. It binds
two public Ed25519 envelopes onto an unsigned MacPersistenceProfileV1 and
emits a canonical PersistenceProfileReceiptV1.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from base64 import b64decode
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from wiki_spike.infrastructure import crypto
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.second_brain_contracts import Ed25519SignatureEnvelopeV1
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_digest,
)
from wiki_spike.memory_core.second_brain_persistence import (
    PERSISTENCE_PROFILE_RECEIPT_V1,
    PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
    MacPersistenceProfileV1,
    PersistenceProfileReceiptV1,
    persistence_profile_authorization_payload,
)

SIGNATURE_VERSION = "second-brain-persistence-profile-signature-v1"
_FILE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)


class PersistenceReceiptToolError(Exception):
    """Operator-facing failure."""


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PersistenceReceiptToolError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PersistenceReceiptToolError(f"{path} must contain a JSON object")
    return data


def _profile(path: Path) -> MacPersistenceProfileV1:
    return MacPersistenceProfileV1.from_mapping(_load(path))


def _envelope(path: Path) -> Ed25519SignatureEnvelopeV1:
    return Ed25519SignatureEnvelopeV1.from_mapping(
        _load(path), version=SIGNATURE_VERSION
    )


def _public_key(envelope: Ed25519SignatureEnvelopeV1) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(
        b64decode(envelope.public_key_b64, validate=True)
    )


def _signature_hex(envelope: Ed25519SignatureEnvelopeV1) -> str:
    return b64decode(envelope.signature_b64, validate=True).hex()


def _ordered_envelopes(
    paths: list[str],
) -> tuple[Ed25519SignatureEnvelopeV1, Ed25519SignatureEnvelopeV1]:
    if len(paths) != 2:
        raise PersistenceReceiptToolError(
            "exactly two public envelopes are required, approver then owner"
        )
    approver = _envelope(Path(paths[0]))
    owner = _envelope(Path(paths[1]))
    if approver.role != "approver" or owner.role != "owner":
        raise PersistenceReceiptToolError(
            "envelopes must be ordered approver then owner"
        )
    if approver.key_id == owner.key_id:
        raise PersistenceReceiptToolError("owner and approver key ids must be distinct")
    if _public_key(approver).public_bytes_raw() == _public_key(owner).public_bytes_raw():
        raise PersistenceReceiptToolError(
            "owner and approver public keys must be distinct"
        )
    return approver, owner


def _receipt(
    profile: MacPersistenceProfileV1,
    authorized_at: str,
    approver: Ed25519SignatureEnvelopeV1,
    owner: Ed25519SignatureEnvelopeV1,
) -> PersistenceProfileReceiptV1:
    payload = persistence_profile_authorization_payload(
        receipt_version=PERSISTENCE_PROFILE_RECEIPT_V1,
        profile_digest=profile.profile_digest,
        owner_key_id=owner.key_id,
        approver_key_id=approver.key_id,
        authorized_at=authorized_at,
    )
    try:
        crypto.verify(
            _public_key(approver),
            PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
            payload,
            _signature_hex(approver),
        )
        crypto.verify(
            _public_key(owner),
            PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
            payload,
            _signature_hex(owner),
        )
    except (InvalidSignature, ValueError) as exc:
        raise PersistenceReceiptToolError(
            "persistence profile signature verification failed"
        ) from exc
    body = {
        "receipt_version": PERSISTENCE_PROFILE_RECEIPT_V1,
        "profile_digest": profile.profile_digest,
        "owner_key_id": owner.key_id,
        "approver_key_id": approver.key_id,
        "owner_signature": _signature_hex(owner),
        "approver_signature": _signature_hex(approver),
        "authorized_at": authorized_at,
    }
    return PersistenceProfileReceiptV1.from_mapping(
        body
        | {
            "receipt_digest": canonical_ledger_digest(
                "persistence-profile-receipt-v1", body
            )
        }
    )


def _write_create_only(path: Path, content: bytes) -> None:
    try:
        descriptor = os.open(path, _FILE_FLAGS, 0o600)
    except FileExistsError as exc:
        raise PersistenceReceiptToolError("output already exists") from exc
    except OSError as exc:
        raise PersistenceReceiptToolError("output cannot be created") from exc
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    except OSError as exc:
        os.close(descriptor)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise PersistenceReceiptToolError("output write failed") from exc
    os.close(descriptor)


def cmd_verify(args: argparse.Namespace) -> int:
    profile = _profile(Path(args.profile))
    approver, owner = _ordered_envelopes(args.signature)
    receipt = _receipt(profile, args.authorized_at, approver, owner)
    print(
        json.dumps(
            {"signatures_verified": True, "receipt_digest": receipt.receipt_digest},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_assemble(args: argparse.Namespace) -> int:
    dest = Path(args.out)
    profile = _profile(Path(args.profile))
    approver, owner = _ordered_envelopes(args.signature)
    receipt = _receipt(profile, args.authorized_at, approver, owner)
    mapping = receipt.to_mapping()
    if set(mapping) != PersistenceProfileReceiptV1.FIELDS:
        raise PersistenceReceiptToolError("receipt fields are not canonical")
    _write_create_only(dest, canonical_bytes(mapping) + b"\n")
    print(
        json.dumps(
            {"written_to": args.out, "receipt_digest": receipt.receipt_digest},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _add_shared(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", required=True)
    parser.add_argument("--authorized-at", required=True)
    parser.add_argument("--signature", action="append", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Public-only assemble/verify for Mac persistence receipts."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify public persistence envelopes")
    _add_shared(verify)
    verify.set_defaults(func=cmd_verify)
    assemble = sub.add_parser("assemble", help="write a create-only persistence receipt")
    _add_shared(assemble)
    assemble.add_argument("--out", required=True)
    assemble.set_defaults(func=cmd_assemble)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except PersistenceReceiptToolError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    except (
        InvalidContractValue,
        UnknownContractField,
        UnsupportedContractVersion,
        OSError,
        ValueError,
        TypeError,
    ) as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
