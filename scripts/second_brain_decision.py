#!/usr/bin/env python3
"""Offline helper for DB-01..DB-08 signed decision records.

A valid record is signed over ``DECISION_SIGNING_DOMAIN + canonical_bytes(body)``
where ``body`` is the record without its ``signatures`` field. ``canonical_bytes``
is this repository's own normalisation, so the byte string cannot be reproduced
by hand; emitting it is the whole point of ``signing-bytes``.

This tool never reads, holds, derives, or generates a private key. It emits the
bytes an owner signs elsewhere, assembles a record around signatures produced
elsewhere, and verifies the result. It cannot manufacture an approval.
"""
from __future__ import annotations

import argparse
import json
import sys
from base64 import b64encode
from hashlib import sha256
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.memory_core.contracts import canonical_bytes  # noqa: E402
from wiki_spike.memory_core.second_brain_contracts import (  # noqa: E402
    DECISION_IDS,
    DECISION_RECORD_VERSION,
    DECISION_SIGNATURE_VERSION,
    DECISION_SIGNING_DOMAIN,
    _SCOPE_KIND_BY_DECISION,
    DecisionRecordV1,
    Ed25519SignatureEnvelopeV1,
)

BODY_FIELDS = sorted(DecisionRecordV1.FIELDS - {"signatures"})


class DecisionToolError(Exception):
    """Operator-facing failure."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DecisionToolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)
    except (OSError, ValueError) as exc:
        raise DecisionToolError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise DecisionToolError(f"{path} must contain a JSON object")
    return data


def _body(data: dict[str, Any], path: Path) -> dict[str, Any]:
    """Return the signing body, rejecting a partially-signed input."""
    if "signatures" in data:
        raise DecisionToolError(
            f"{path} must not carry a signatures field; sign the body, then assemble"
        )
    missing = set(BODY_FIELDS) - set(data)
    unknown = set(data) - set(BODY_FIELDS)
    if missing or unknown:
        raise DecisionToolError(
            f"{path} body fields are wrong; missing={sorted(missing)} unknown={sorted(unknown)}"
        )
    return data


def signing_bytes(body: dict[str, Any]) -> bytes:
    return DECISION_SIGNING_DOMAIN + canonical_bytes(body)


def cmd_skeleton(args: argparse.Namespace) -> int:
    decision_id = args.decision_id
    if decision_id not in DECISION_IDS:
        raise DecisionToolError(f"decision_id must be one of {sorted(DECISION_IDS)}")
    kind = _SCOPE_KIND_BY_DECISION.get(decision_id, "global")
    if kind == "global" and args.scope_name is not None:
        raise DecisionToolError(f"{decision_id} is global and takes no --scope-name")
    if kind != "global" and not args.scope_name:
        raise DecisionToolError(f"{decision_id} is {kind}-scoped and requires --scope-name")
    body = {
        "decision_version": DECISION_RECORD_VERSION,
        "decision_id": decision_id,
        "outcome": "GO",
        "scope_kind": kind,
        "scope_name": args.scope_name,
        "record_revision": "1",
        "decided_at": "REPLACE-WITH-RFC3339-UTC",
        "supersedes": None,
        "post_interview_reconciliation": {
            "original_question": "REPLACE-WITH-THE-VERBATIM-ORIGINAL-QUESTION",
            "reconciliation": "REPLACE-WITH-THE-RECONCILED-DECISION",
        },
        "reason": "REPLACE-WITH-THE-DECISION-REASON",
        "evidence_refs": ["REPLACE-WITH-AT-LEAST-ONE-EVIDENCE-REF"],
        "evidence_digest": "REPLACE-WITH-SHA256-OF-THE-EVIDENCE-BUNDLE",
        "expires_at": "REPLACE-WITH-RFC3339-UTC",
    }
    print(json.dumps(body, indent=2, ensure_ascii=False))
    return 0


def cmd_signing_bytes(args: argparse.Namespace) -> int:
    path = Path(args.body)
    payload = signing_bytes(_body(_load(path), path))
    if args.out:
        Path(args.out).write_bytes(payload)
    report = {
        "domain": DECISION_SIGNING_DOMAIN.decode("utf-8").rstrip("\x00"),
        "bytes": len(payload),
        "sha256": sha256(payload).hexdigest(),
        "written_to": args.out,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _envelope(path: Path) -> Ed25519SignatureEnvelopeV1:
    return Ed25519SignatureEnvelopeV1.from_mapping(
        _load(path), version=DECISION_SIGNATURE_VERSION
    )


def cmd_envelope(args: argparse.Namespace) -> int:
    """Wrap a raw Ed25519 signature and public key into a signature envelope."""
    signature = Path(args.signature).read_bytes()
    if len(signature) != 64:
        raise DecisionToolError(
            f"{args.signature} holds {len(signature)} bytes; an Ed25519 signature is 64"
        )
    public_key = Path(args.public_key).read_bytes()
    if len(public_key) != 32:
        raise DecisionToolError(
            f"{args.public_key} holds {len(public_key)} bytes; expected a 32-byte raw "
            "Ed25519 public key (openssl pkey -pubout -outform DER emits a 44-byte "
            "SubjectPublicKeyInfo whose trailing 32 bytes are the key)"
        )
    envelope = {
        "signature_version": DECISION_SIGNATURE_VERSION,
        "role": args.role,
        "key_id": args.key_id,
        "public_key_b64": b64encode(public_key).decode("ascii"),
        "signature_b64": b64encode(signature).decode("ascii"),
    }
    # Round-trip through the contract so a malformed envelope fails here rather
    # than at assemble time. Raises on rejection; the return value is unused.
    Ed25519SignatureEnvelopeV1.from_mapping(envelope, version=DECISION_SIGNATURE_VERSION)
    print(json.dumps(envelope, indent=2, sort_keys=True))
    return 0


def cmd_assemble(args: argparse.Namespace) -> int:
    body_path = Path(args.body)
    body = _body(_load(body_path), body_path)
    envelopes = [_envelope(Path(p)) for p in args.signature]
    roles = sorted(item.role for item in envelopes)
    if roles != ["approver", "owner"]:
        raise DecisionToolError(
            f"exactly one approver and one owner signature are required; got {roles}"
        )
    # The contract requires canonical approver-then-owner ordering.
    ordered = sorted(envelopes, key=lambda item: 0 if item.role == "approver" else 1)
    record = {**body, "signatures": [item.to_mapping() for item in ordered]}
    payload = signing_bytes(body)
    for item in ordered:
        if not item.verify(DECISION_SIGNING_DOMAIN, body):
            raise DecisionToolError(
                f"{item.role} signature does not verify over this body "
                f"(signing bytes sha256 {sha256(payload).hexdigest()}); "
                "the body changed after it was signed, or the wrong key signed it"
            )
    DecisionRecordV1.from_mapping(record)
    Path(args.out).write_text(
        json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"written_to": args.out, "decision_id": body["decision_id"]}, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.record)
    record = DecisionRecordV1.from_mapping(_load(path))
    body = record.signing_payload()
    results = []
    for item in record.signatures:
        ok = item.verify(DECISION_SIGNING_DOMAIN, body)
        results.append({"role": item.role, "key_id": item.key_id, "verified": ok})
    verified = all(item["verified"] for item in results)
    report = {
        "record": str(path),
        "decision_id": record.decision_id,
        "outcome": record.outcome,
        "scope_kind": record.scope_kind,
        "scope_name": record.scope_name,
        "record_revision": record.record_revision,
        "expires_at": record.expires_at,
        "evidence_digest": record.evidence_digest,
        "signatures": results,
        "signatures_verified": verified,
    }
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    if not verified:
        return 1
    print(
        "NOTE: signatures verify against the keys embedded in the record. Binding "
        "those keys to the trusted owner/approver identities is a separate check "
        "performed by resolve_second_brain_contract with TrustedDecisionKeyBindingsV1.",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    skeleton = sub.add_parser("skeleton", help="print an unsigned record body template")
    skeleton.add_argument("--decision-id", required=True)
    skeleton.add_argument("--scope-name", default=None)
    skeleton.set_defaults(func=cmd_skeleton)

    emit = sub.add_parser("signing-bytes", help="emit the exact bytes an owner must sign")
    emit.add_argument("--body", required=True)
    emit.add_argument("--out", default=None)
    emit.set_defaults(func=cmd_signing_bytes)

    envelope = sub.add_parser("envelope", help="wrap a raw signature into a signature envelope")
    envelope.add_argument("--role", required=True, choices=("owner", "approver"))
    envelope.add_argument("--key-id", required=True)
    envelope.add_argument("--public-key", required=True, help="32-byte raw Ed25519 public key")
    envelope.add_argument("--signature", required=True, help="64-byte raw Ed25519 signature")
    envelope.set_defaults(func=cmd_envelope)

    assemble = sub.add_parser("assemble", help="combine a body and two signatures into a record")
    assemble.add_argument("--body", required=True)
    assemble.add_argument("--signature", action="append", required=True)
    assemble.add_argument("--out", required=True)
    assemble.set_defaults(func=cmd_assemble)

    verify = sub.add_parser("verify", help="validate a record and its signatures")
    verify.add_argument("--record", required=True)
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except DecisionToolError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # contract rejections are operator-facing too
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
