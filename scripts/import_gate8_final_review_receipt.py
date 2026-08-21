#!/usr/bin/env python3
"""Strictly write and import one Gate 8 final review receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Final, Protocol, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from wiki_spike.infrastructure.conformance import (
    ARCHITECT,
    ATTESTATION_FIELDS,
    CRITIC,
    EVIDENCE_JOIN_SCHEMA,
    FINAL_REVIEW_RECEIPT_SCHEMA,
    PRE_REVIEW_MANIFEST_SCHEMA,
    REQUIRED_LANES,
    EvidenceJoin,
    PreReviewManifest,
    ReviewAttestation,
    build_evidence_join,
    build_pre_review_manifest,
    import_final_review_receipt,
    verify_evidence_join,
    write_final_review_receipt,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes

_MANIFEST_FIELDS: frozenset[str] = frozenset(
    ("schema", "workspace_id", "implementation_commit", "bundles", "manifest_digest")
)
_JOIN_FIELDS: frozenset[str] = frozenset(
    (
        "schema",
        "workspace_id",
        "implementation_commit",
        "import_receipts",
        "manifest_digest",
        "join_digest",
    )
)
_DURABLE_OUTPUT_TREE: Final = Path("artifacts") / "encrypted-lifecycle" / "gate8-final"
_DURABLE_OUTPUT_TREE_ERROR: Final = (
    "durable output must be under artifacts/encrypted-lifecycle/gate8-final"
)
_DURABLE_SYMLINK_ERROR: Final = "durable output path must not traverse symlinks"

RawJsonValue = (
    None
    | bool
    | int
    | float
    | str
    | list["RawJsonValue"]
    | dict[str, "RawJsonValue"]
)


def _parse_json_value(value: RawJsonValue) -> JsonValue:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, list):
        return [_parse_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _parse_json_value(item) for key, item in value.items()}
    raise TypeError("JSON value must use the canonical string-only wire types")


def _object(path: Path) -> dict[str, JsonValue]:
    try:
        raw_value = cast(RawJsonValue, json.loads(path.read_bytes()))
        value = _parse_json_value(raw_value)
    except (OSError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"{path}: expected UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise TypeError(f"{path}: expected a JSON object")
    return value


def _required_string(value: Mapping[str, JsonValue], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str):
        raise TypeError(f"{field}: expected a string")
    return item


def _closed_lane_receipts(
    value: JsonValue,
    *,
    field: str,
) -> dict[str, Mapping[str, JsonValue]]:
    if not isinstance(value, list) or len(value) != len(REQUIRED_LANES):
        raise ValueError(f"{field}: exactly {len(REQUIRED_LANES)} lanes are required")
    receipts: dict[str, Mapping[str, JsonValue]] = {}
    observed: list[str] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"lane", "receipt"}:
            raise ValueError(f"{field}: each lane must use the closed lane/receipt wire")
        lane = _required_string(item, "lane")
        receipt = item["receipt"]
        if not isinstance(receipt, dict) or lane in receipts:
            raise ValueError(f"{field}: lane names must be unique strings")
        observed.append(lane)
        receipts[lane] = receipt
    if tuple(observed) != REQUIRED_LANES:
        raise ValueError(f"{field}: lanes must use canonical order {REQUIRED_LANES}")
    return receipts


def _manifest(path: Path) -> PreReviewManifest:
    wire = _object(path)
    if (
        set(wire) != set(_MANIFEST_FIELDS)
        or _required_string(wire, "schema") != PRE_REVIEW_MANIFEST_SCHEMA
    ):
        raise ValueError(f"{path}: invalid pre-review manifest wire")
    receipts = _closed_lane_receipts(wire["bundles"], field="bundles")
    manifest = build_pre_review_manifest(
        workspace_id=_required_string(wire, "workspace_id"),
        implementation_commit=_required_string(wire, "implementation_commit"),
        bundles=receipts,
    )
    expected: dict[str, JsonValue] = {
        "schema": manifest.schema,
        "workspace_id": manifest.workspace_id,
        "implementation_commit": manifest.implementation_commit,
        "bundles": [
            {"lane": bundle.lane, "receipt": bundle.receipt}
            for bundle in manifest.bundles
        ],
        "manifest_digest": manifest.manifest_digest,
    }
    if canonical_bytes(wire) != canonical_bytes(expected):
        raise ValueError(f"{path}: manifest does not recompute exactly")
    return manifest


def _evidence_join(path: Path, *, manifest_digest: str) -> EvidenceJoin:
    wire = _object(path)
    if (
        set(wire) != set(_JOIN_FIELDS)
        or _required_string(wire, "schema") != EVIDENCE_JOIN_SCHEMA
    ):
        raise ValueError(f"{path}: invalid evidence-join wire")
    receipts = _closed_lane_receipts(wire["import_receipts"], field="import_receipts")
    evidence_join = build_evidence_join(
        workspace_id=_required_string(wire, "workspace_id"),
        implementation_commit=_required_string(wire, "implementation_commit"),
        import_receipts=receipts,
        manifest_digest=_required_string(wire, "manifest_digest"),
    )
    verify_evidence_join(evidence_join, manifest_digest)
    expected: dict[str, JsonValue] = {
        "schema": evidence_join.schema,
        "workspace_id": evidence_join.workspace_id,
        "implementation_commit": evidence_join.implementation_commit,
        "import_receipts": [
            {"lane": lane, "receipt": receipt}
            for lane, receipt in evidence_join.import_receipts
        ],
        "manifest_digest": evidence_join.manifest_digest,
        "join_digest": evidence_join.join_digest,
    }
    if canonical_bytes(wire) != canonical_bytes(expected):
        raise ValueError(f"{path}: evidence join does not recompute exactly")
    return evidence_join


def _attestation(path: Path, *, role: str) -> ReviewAttestation:
    wire = _object(path)
    if set(wire) != set(ATTESTATION_FIELDS) or _required_string(
        wire, "reviewer_role"
    ) != role:
        raise ValueError(f"{path}: invalid {role} attestation wire")
    return ReviewAttestation(
        schema=_required_string(wire, "schema"),
        reviewer_role=_required_string(wire, "reviewer_role"),
        verdict=_required_string(wire, "verdict"),
        workspace_id=_required_string(wire, "workspace_id"),
        implementation_commit=_required_string(wire, "implementation_commit"),
        manifest_digest=_required_string(wire, "manifest_digest"),
        reviewer_key_id=_required_string(wire, "reviewer_key_id"),
        issued_at=_required_string(wire, "issued_at"),
        expires_at=_required_string(wire, "expires_at"),
        signature=_required_string(wire, "signature"),
    )


def _public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"{path}: invalid public PEM") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{path}: reviewer key must be Ed25519")
    return key


def _path_has_symlink(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            return True
    return False


def _require_durable_output(
    parser: argparse.ArgumentParser,
    *,
    output: Path,
    repository_root: Path,
) -> None:
    durable_tree = Path(os.path.abspath(repository_root / _DURABLE_OUTPUT_TREE))
    output_path = Path(os.path.abspath(output))
    try:
        relative = output_path.relative_to(durable_tree)
    except ValueError:
        relative = Path()
    if relative == Path():
        parser.error(_DURABLE_OUTPUT_TREE_ERROR)
    if _path_has_symlink(output_path) or _path_has_symlink(durable_tree):
        parser.error(_DURABLE_SYMLINK_ERROR)


class Arguments(Protocol):
    manifest: Path
    evidence_join: Path
    architect_attestation: Path
    architect_public_key: Path
    critic_attestation: Path
    critic_public_key: Path
    now: str
    output: Path
    durable: bool
    repository_root: Path | None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--manifest", type=Path, required=True)
    _ = parser.add_argument("--evidence-join", type=Path, required=True)
    _ = parser.add_argument("--architect-attestation", type=Path, required=True)
    _ = parser.add_argument("--architect-public-key", type=Path, required=True)
    _ = parser.add_argument("--critic-attestation", type=Path, required=True)
    _ = parser.add_argument("--critic-public-key", type=Path, required=True)
    _ = parser.add_argument("--now", required=True)
    _ = parser.add_argument("--output", type=Path, required=True)
    _ = parser.add_argument("--durable", action="store_true")
    _ = parser.add_argument("--repository-root", type=Path)
    return parser


def main() -> int:
    parser = _parser()
    # argparse guarantees these required/type/action contracts at this boundary.
    args = cast(Arguments, cast(object, parser.parse_args()))
    if args.durable:
        if args.repository_root is None:
            parser.error("--repository-root is required when --durable is set")
        _require_durable_output(
            parser,
            output=args.output,
            repository_root=args.repository_root,
        )
    manifest = _manifest(args.manifest)
    evidence_join = _evidence_join(
        args.evidence_join,
        manifest_digest=manifest.manifest_digest,
    )
    architect = _attestation(args.architect_attestation, role=ARCHITECT)
    critic = _attestation(args.critic_attestation, role=CRITIC)
    trusted_reviewers = {
        ARCHITECT: (architect.reviewer_key_id, _public_key(args.architect_public_key)),
        CRITIC: (critic.reviewer_key_id, _public_key(args.critic_public_key)),
    }
    receipt = write_final_review_receipt(
        workspace_id=manifest.workspace_id,
        implementation_commit=manifest.implementation_commit,
        manifest=manifest,
        evidence_join=evidence_join,
        attestations=(architect, critic),
        trusted_reviewers=trusted_reviewers,
        now=args.now,
    )
    imported = import_final_review_receipt(
        receipt,
        trusted_reviewers=trusted_reviewers,
        workspace_id=manifest.workspace_id,
        implementation_commit=manifest.implementation_commit,
        manifest=manifest,
        evidence_join=evidence_join,
        now=args.now,
    )
    if tuple(attestation.reviewer_role for attestation in imported) != (
        ARCHITECT,
        CRITIC,
    ):
        raise ValueError("imported reviewer role order is invalid")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as output:
        _ = output.write(receipt)

    raw_receipt_wire = cast(RawJsonValue, json.loads(receipt))
    receipt_wire = _parse_json_value(raw_receipt_wire)
    if not isinstance(receipt_wire, dict):
        raise TypeError("generated receipt must be a JSON object")
    artifact_inventory = receipt_wire["artifact_inventory"]
    if not isinstance(artifact_inventory, dict):
        raise TypeError("generated receipt inventory must be a JSON object")
    summary = {
        "schema": FINAL_REVIEW_RECEIPT_SCHEMA,
        "workspace_id": manifest.workspace_id,
        "implementation_commit": manifest.implementation_commit,
        "manifest_digest": manifest.manifest_digest,
        "join_digest": evidence_join.join_digest,
        "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
        "artifact_inventory_digest": hashlib.sha256(
            canonical_bytes(artifact_inventory)
        ).hexdigest(),
    }
    print(canonical_bytes(summary).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
