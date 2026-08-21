"""Create unsigned canonical resolver material without private-key access."""
from __future__ import annotations

import os
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Final

from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_DIGEST_VERSION,
    DecisionRecordV1,
    ExpectedScopeManifestV1,
    ResolvedScopeV1,
    SecondBrainContractDigestV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import (
    decode_json_object,
)

EVIDENCE_MANIFEST_VERSION: Final = "second-brain-evidence-manifest-v1"
EVIDENCE_ENVELOPE_VERSION: Final = "second-brain-evidence-manifest-envelope-v1"
EVIDENCE_SIGNATURE_VERSION: Final = "second-brain-evidence-manifest-signature-v1"
EVIDENCE_SIGNING_DOMAIN: Final = (
    b"wiki-spike.second-brain.evidence-manifest.v1\x00"
)
SCOPE_VERSION: Final = "second-brain-resolved-scope-v1"
NO_GO_REASON: Final = "signed NO_GO"
RELEASE: Final = Path("artifacts/product-release/second-brain-v1")
FEATURE_BY_GLOBAL_DECISION: Final = {
    "DB-01": "identity-auth",
    "DB-04": "conflict-behavior",
    "DB-05": "benchmark-governance",
    "DB-07": "cutover-retention",
}

type JsonObject = dict[str, JsonValue]


class BuilderError(Exception):
    """Fail-closed resolver-input builder error."""


def load_json(path: Path) -> JsonObject:
    try:
        return decode_json_object(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise BuilderError(f"{path} cannot be read safely") from exc


def write_canonical(path: Path, value: Mapping[str, JsonValue]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        _ = os.chmod(path, 0o644)
    _ = path.write_bytes(canonical_bytes(value))
    _ = os.chmod(path, 0o444)


def _records(records_dir: Path) -> list[DecisionRecordV1]:
    records = [
        DecisionRecordV1.from_mapping(load_json(path))
        for path in sorted(records_dir.glob("*.json"))
    ]
    if not records:
        raise BuilderError("records directory is empty")
    return records


def _json_names(values: list[str]) -> list[JsonValue]:
    result: list[JsonValue] = []
    result.extend(values)
    return result


def _json_reasons(values: Mapping[str, str]) -> JsonObject:
    return {name: reason for name, reason in values.items()}


def _scope(
    records: list[DecisionRecordV1],
    bindings_raw: bytes,
    expected_raw: bytes,
) -> JsonObject:
    enabled: dict[str, list[str]] = {
        "source_profile": [],
        "migration_source": [],
        "external_model_route": [],
        "export_destination": [],
    }
    disabled: dict[str, dict[str, str]] = {
        name: {} for name in enabled
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
        FEATURE_BY_GLOBAL_DECISION[record.decision_id]
        for record in records
        if record.scope_kind == "global" and record.outcome == "GO"
    )
    return {
        "capability_manifest_digest": sha256(bindings_raw).hexdigest(),
        "disabled_export_destinations": _json_reasons(
            disabled["export_destination"]
        ),
        "disabled_external_model_routes": _json_reasons(
            disabled["external_model_route"]
        ),
        "disabled_migration_sources": _json_reasons(
            disabled["migration_source"]
        ),
        "disabled_source_profiles": _json_reasons(disabled["source_profile"]),
        "egress_destinations": _json_names(enabled["export_destination"]),
        "enabled_external_model_routes": _json_names(
            enabled["external_model_route"]
        ),
        "enabled_migration_sources": _json_names(
            enabled["migration_source"]
        ),
        "enabled_source_profiles": _json_names(enabled["source_profile"]),
        "feature_flags": _json_names(features),
        "mandatory_release_constraints": _json_names(
            ["signed-release-baseline"]
        ),
        "scope_version": SCOPE_VERSION,
        "source_manifest_digest": sha256(expected_raw).hexdigest(),
    }


def _evidence_body(records: list[DecisionRecordV1]) -> JsonObject:
    entries: list[JsonValue] = [
        {
            "decision_id": record.decision_id,
            "evidence_digest": record.evidence_digest,
            "scope_kind": record.scope_kind,
            "scope_name": record.scope_name,
        }
        for record in sorted(
            records,
            key=lambda item: (
                item.decision_id,
                item.scope_kind,
                item.scope_name or "",
            ),
        )
    ]
    return {
        "decision_evidence": entries,
        "evidence_manifest_version": EVIDENCE_MANIFEST_VERSION,
        "expires_at": "2027-08-07T00:00:00Z",
        "observed_at": "2026-08-21T15:00:00Z",
    }


def _prepared(root: Path) -> tuple[JsonObject, JsonObject, JsonObject]:
    release = root / RELEASE
    records = _records(release / "decisions")
    bindings_raw = (release / "governance/trusted-bindings.json").read_bytes()
    expected_raw = (release / "governance/expected-scopes.json").read_bytes()
    expected = ExpectedScopeManifestV1.from_mapping(
        load_json(release / "governance/expected-scopes.json")
    )
    scope = ResolvedScopeV1.from_mapping(
        _scope(records, bindings_raw, expected_raw)
    )
    contract = SecondBrainContractDigestV1.create(records, scope, expected)
    aggregate_payload: JsonObject = {
        "contract_body": contract.body(),
        "contract_digest": contract.digest,
        "contract_version": CONTRACT_DIGEST_VERSION,
    }
    evidence_body = _evidence_body(records)
    evidence_payload: JsonObject = {
        "evidence_body": evidence_body,
        "evidence_envelope_version": EVIDENCE_ENVELOPE_VERSION,
        "evidence_manifest_digest": sha256(
            canonical_bytes(evidence_body)
        ).hexdigest(),
    }
    return scope.to_mapping(), aggregate_payload, evidence_payload


def prepare(root: Path) -> None:
    scope, aggregate, evidence = _prepared(root)
    release = root / RELEASE
    write_canonical(release / "resolver/resolved-scope.json", scope)
    signing = release / "resolver-signing"
    write_canonical(signing / "aggregate.payload.json", aggregate)
    write_canonical(signing / "evidence-manifest.payload.json", evidence)
