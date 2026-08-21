#!/usr/bin/env python3
"""Build canonical resolver inputs and sign aggregate plus evidence envelopes."""
from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
import stat
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, Literal, cast

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_DIGEST_VERSION,
    CONTRACT_ENVELOPE_VERSION,
    CONTRACT_SIGNATURE_VERSION,
    CONTRACT_SIGNING_DOMAIN,
    DecisionRecordV1,
    ExpectedScopeManifestV1,
    ResolvedScopeV1,
    SecondBrainContractDigestV1,
    _FEATURE_BY_GLOBAL_DECISION,
    detached_signing_bytes,
)

Role = Literal["approver", "owner"]
_ROLES: Final = frozenset({"approver", "owner"})
EVIDENCE_MANIFEST_VERSION = "second-brain-evidence-manifest-v1"
EVIDENCE_ENVELOPE_VERSION = "second-brain-evidence-manifest-envelope-v1"
EVIDENCE_SIGNATURE_VERSION = "second-brain-evidence-manifest-signature-v1"
EVIDENCE_SIGNING_DOMAIN = b"wiki-spike.second-brain.evidence-manifest.v1\x00"
SCOPE_VERSION = "second-brain-resolved-scope-v1"
NO_GO_REASON = "signed NO_GO"


class BuilderError(Exception):
    """Fail-closed builder error."""


def _private_key(path: Path) -> Ed25519PrivateKey:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise BuilderError("private key is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise BuilderError("private key must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise BuilderError("private key permissions must deny group and other access")
    try:
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise BuilderError("private key is not a usable unencrypted PEM key") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise BuilderError("private key must be Ed25519")
    return loaded


def _public_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")


def _sign(
    *,
    role: Role,
    key: Ed25519PrivateKey,
    key_id: str,
    expected_b64: str,
    domain: bytes,
    payload: dict[str, Any],
    version: str,
) -> dict[str, str]:
    public_b64 = _public_b64(key)
    if not hmac.compare_digest(public_b64, expected_b64):
        raise BuilderError("private key does not match the trusted public binding")
    signature = base64.b64encode(key.sign(detached_signing_bytes(domain, payload))).decode(
        "ascii"
    )
    return {
        "key_id": key_id,
        "public_key_b64": public_b64,
        "role": role,
        "signature_b64": signature,
        "signature_version": version,
    }


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BuilderError(f"{path} must contain a JSON object")
    return value


def _write_canonical(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        os.chmod(path, 0o644)
    path.write_bytes(canonical_bytes(value))
    os.chmod(path, 0o444)


def _records(records_dir: Path) -> list[DecisionRecordV1]:
    records: list[DecisionRecordV1] = []
    for path in sorted(records_dir.glob("*.json")):
        records.append(DecisionRecordV1.from_mapping(_load_json(path)))
    if not records:
        raise BuilderError("records directory is empty")
    return records


def _scope(records: list[DecisionRecordV1], bindings: bytes, expected: bytes) -> dict[str, Any]:
    enabled: dict[str, list[str]] = {
        "source_profile": [],
        "migration_source": [],
        "external_model_route": [],
        "export_destination": [],
    }
    disabled: dict[str, dict[str, str]] = {
        "source_profile": {},
        "migration_source": {},
        "external_model_route": {},
        "export_destination": {},
    }
    for record in records:
        if record.scope_kind == "global" or record.scope_name is None:
            continue
        if record.outcome == "GO":
            enabled[record.scope_kind].append(record.scope_name)
        else:
            disabled[record.scope_kind][record.scope_name] = NO_GO_REASON
    for names in enabled.values():
        names.sort()
    features = sorted(
        _FEATURE_BY_GLOBAL_DECISION[record.decision_id]
        for record in records
        if record.scope_kind == "global" and record.outcome == "GO"
    )
    return {
        "capability_manifest_digest": sha256(bindings).hexdigest(),
        "disabled_export_destinations": disabled["export_destination"],
        "disabled_external_model_routes": disabled["external_model_route"],
        "disabled_migration_sources": disabled["migration_source"],
        "disabled_source_profiles": disabled["source_profile"],
        "egress_destinations": enabled["export_destination"],
        "enabled_external_model_routes": enabled["external_model_route"],
        "enabled_migration_sources": enabled["migration_source"],
        "enabled_source_profiles": enabled["source_profile"],
        "feature_flags": features,
        "mandatory_release_constraints": ["signed-release-baseline"],
        "scope_version": SCOPE_VERSION,
        "source_manifest_digest": sha256(expected).hexdigest(),
    }


def _evidence_body(records: list[DecisionRecordV1]) -> dict[str, Any]:
    entries = sorted(
        (
            {
                "decision_id": record.decision_id,
                "evidence_digest": record.evidence_digest,
                "scope_kind": record.scope_kind,
                "scope_name": record.scope_name,
            }
            for record in records
        ),
        key=lambda item: (
            str(item["decision_id"]),
            str(item["scope_kind"]),
            str(item["scope_name"] or ""),
        ),
    )
    return {
        "decision_evidence": entries,
        "evidence_manifest_version": EVIDENCE_MANIFEST_VERSION,
        "expires_at": "2027-08-07T00:00:00Z",
        "observed_at": "2026-08-21T15:00:00Z",
    }


def build(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-key", required=True, type=Path)
    parser.add_argument("--approver-key", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path("."))
    parsed = parser.parse_args(argv)
    root = parsed.root.resolve()
    records_dir = root / "artifacts/product-release/second-brain-v1/decisions"
    bindings_path = (
        root / "artifacts/product-release/second-brain-v1/governance/trusted-bindings.json"
    )
    expected_path = (
        root / "artifacts/product-release/second-brain-v1/governance/expected-scopes.json"
    )
    out_dir = root / "artifacts/product-release/second-brain-v1/resolver"
    records = _records(records_dir)
    bindings_raw = bindings_path.read_bytes()
    expected_raw = expected_path.read_bytes()
    bindings = _load_json(bindings_path)
    aggregate_binding = bindings["aggregate_binding"]
    if not isinstance(aggregate_binding, dict):
        raise BuilderError("aggregate_binding must be an object")
    expected = ExpectedScopeManifestV1.from_mapping(_load_json(expected_path))
    scope_mapping = _scope(records, bindings_raw, expected_raw)
    scope = ResolvedScopeV1.from_mapping(scope_mapping)
    contract = SecondBrainContractDigestV1.create(records, scope, expected)
    owner_key = _private_key(parsed.owner_key)
    approver_key = _private_key(parsed.approver_key)
    owner_id = str(aggregate_binding["owner_key_id"])
    approver_id = str(aggregate_binding["approver_key_id"])
    owner_b64 = str(aggregate_binding["owner_public_key_b64"])
    approver_b64 = str(aggregate_binding["approver_public_key_b64"])
    aggregate_payload = {
        "contract_body": contract.body(),
        "contract_digest": contract.digest,
        "contract_version": CONTRACT_DIGEST_VERSION,
    }
    evidence_body = _evidence_body(records)
    evidence_digest = sha256(canonical_bytes(evidence_body)).hexdigest()
    evidence_payload = {
        "evidence_body": evidence_body,
        "evidence_envelope_version": EVIDENCE_ENVELOPE_VERSION,
        "evidence_manifest_digest": evidence_digest,
    }
    aggregate = {
        "contract_envelope_version": CONTRACT_ENVELOPE_VERSION,
        **aggregate_payload,
        "signatures": [
            _sign(
                role="approver",
                key=approver_key,
                key_id=approver_id,
                expected_b64=approver_b64,
                domain=CONTRACT_SIGNING_DOMAIN,
                payload=aggregate_payload,
                version=CONTRACT_SIGNATURE_VERSION,
            ),
            _sign(
                role="owner",
                key=owner_key,
                key_id=owner_id,
                expected_b64=owner_b64,
                domain=CONTRACT_SIGNING_DOMAIN,
                payload=aggregate_payload,
                version=CONTRACT_SIGNATURE_VERSION,
            ),
        ],
    }
    evidence = {
        **evidence_payload,
        "signatures": [
            _sign(
                role="approver",
                key=approver_key,
                key_id=approver_id,
                expected_b64=approver_b64,
                domain=EVIDENCE_SIGNING_DOMAIN,
                payload=evidence_payload,
                version=EVIDENCE_SIGNATURE_VERSION,
            ),
            _sign(
                role="owner",
                key=owner_key,
                key_id=owner_id,
                expected_b64=owner_b64,
                domain=EVIDENCE_SIGNING_DOMAIN,
                payload=evidence_payload,
                version=EVIDENCE_SIGNATURE_VERSION,
            ),
        ],
    }
    _write_canonical(out_dir / "resolved-scope.json", scope.to_mapping())
    _write_canonical(out_dir / "aggregate-envelope.json", aggregate)
    _write_canonical(out_dir / "evidence-manifest-envelope.json", evidence)
    print(
        json.dumps(
            {
                "out": str(out_dir),
                "records": str(len(records)),
                "contract_digest": contract.digest,
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return build(argv)
    except BuilderError as exc:
        print(f"resolver input build refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
