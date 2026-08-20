"""Resolution-receipt parse and records-directory digest for Mac authority."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from .contracts import JsonValue, canonical_bytes
from .errors import UnsupportedContractVersion
from .mac_signed_authority_parse import (
    RESOLUTION_RECEIPT_VERSION,
    optional_digest,
    optional_string,
    parse_bool,
    parse_decision_identity,
    parse_utc_text,
    require_array,
    require_mapping,
    strict_fields,
)
from .second_brain_contracts import DecisionRecordV1, ResolvedScopeV1
from .snapshot_import_parse import parse_digest, parse_string

_RECEIPT_FIELDS: Final = frozenset(
    {
        "resolution_receipt_version",
        "resolver_outcome",
        "stage0_contract_usable",
        "live_operation_authorized",
        "next_governance_gate",
        "resolved_at",
        "resolved_scope",
        "input_sha256",
        "evidence_freshness",
        "contract_digest",
        "blocked_decisions",
    }
)
_INPUT_FIELDS: Final = frozenset(
    {
        "records_dir",
        "resolved_scope",
        "expected_scopes",
        "aggregate",
        "trusted_bindings",
        "evidence_manifest",
    }
)
_FRESHNESS_FIELDS: Final = frozenset(
    {
        "state",
        "signed_manifest_digest",
        "observed_at",
        "expires_at",
        "evaluated_at",
    }
)
_BLOCKED_FIELDS: Final = frozenset(
    {"decision_id", "scope_kind", "scope_name", "decision_digest"}
)


@dataclass(frozen=True, slots=True)
class ReceiptInputDigestsV1:
    records_dir: str
    resolved_scope: str
    expected_scopes: str
    aggregate: str
    trusted_bindings: str
    evidence_manifest: str


@dataclass(frozen=True, slots=True)
class EvidenceFreshnessV1:
    state: str
    signed_manifest_digest: str
    observed_at: str
    expires_at: str
    evaluated_at: str


@dataclass(frozen=True, slots=True)
class BlockedDecisionV1:
    decision_id: str
    scope_kind: str
    scope_name: str | None
    decision_digest: str


@dataclass(frozen=True, slots=True)
class ResolutionReceiptV1:
    resolution_receipt_version: str
    resolver_outcome: str
    stage0_contract_usable: bool
    live_operation_authorized: bool
    next_governance_gate: str | None
    resolved_at: str
    resolved_scope: ResolvedScopeV1
    input_sha256: ReceiptInputDigestsV1
    evidence_freshness: EvidenceFreshnessV1
    contract_digest: str | None
    blocked_decisions: tuple[BlockedDecisionV1, ...]


def _parse_input_digests(value: JsonValue) -> ReceiptInputDigestsV1:
    data = require_mapping(value, "input_sha256")
    strict_fields(data, _INPUT_FIELDS)
    return ReceiptInputDigestsV1(
        parse_digest(data["records_dir"], "input_sha256.records_dir"),
        parse_digest(data["resolved_scope"], "input_sha256.resolved_scope"),
        parse_digest(data["expected_scopes"], "input_sha256.expected_scopes"),
        parse_digest(data["aggregate"], "input_sha256.aggregate"),
        parse_digest(data["trusted_bindings"], "input_sha256.trusted_bindings"),
        parse_digest(data["evidence_manifest"], "input_sha256.evidence_manifest"),
    )


def _parse_freshness(value: JsonValue) -> EvidenceFreshnessV1:
    data = require_mapping(value, "evidence_freshness")
    strict_fields(data, _FRESHNESS_FIELDS)
    return EvidenceFreshnessV1(
        parse_string(data["state"], "evidence_freshness.state"),
        parse_digest(data["signed_manifest_digest"], "signed_manifest_digest"),
        parse_utc_text(data["observed_at"], "evidence_freshness.observed_at"),
        parse_utc_text(data["expires_at"], "evidence_freshness.expires_at"),
        parse_utc_text(data["evaluated_at"], "evidence_freshness.evaluated_at"),
    )


def _parse_blocked(value: JsonValue, field: str) -> BlockedDecisionV1:
    data = require_mapping(value, field)
    strict_fields(data, _BLOCKED_FIELDS)
    identity = parse_decision_identity(data, field)
    return BlockedDecisionV1(
        identity[0],
        identity[1],
        identity[2],
        parse_digest(data["decision_digest"], f"{field}.decision_digest"),
    )


def parse_resolution_receipt(value: JsonValue) -> ResolutionReceiptV1:
    data = require_mapping(value, "resolution_receipt")
    strict_fields(data, _RECEIPT_FIELDS)
    if data["resolution_receipt_version"] != RESOLUTION_RECEIPT_VERSION:
        raise UnsupportedContractVersion("unsupported resolution_receipt_version")
    blocked = tuple(
        _parse_blocked(item, f"blocked_decisions[{index}]")
        for index, item in enumerate(
            require_array(data["blocked_decisions"], "blocked_decisions")
        )
    )
    return ResolutionReceiptV1(
        RESOLUTION_RECEIPT_VERSION,
        parse_string(data["resolver_outcome"], "resolver_outcome"),
        parse_bool(data["stage0_contract_usable"], "stage0_contract_usable"),
        parse_bool(data["live_operation_authorized"], "live_operation_authorized"),
        optional_string(data["next_governance_gate"], "next_governance_gate"),
        parse_utc_text(data["resolved_at"], "resolved_at"),
        ResolvedScopeV1.from_mapping(require_mapping(data["resolved_scope"], "resolved_scope")),
        _parse_input_digests(data["input_sha256"]),
        _parse_freshness(data["evidence_freshness"]),
        optional_digest(data["contract_digest"], "contract_digest"),
        blocked,
    )


def records_directory_digest(records: Sequence[tuple[str, DecisionRecordV1]]) -> str:
    hashed: list[JsonValue] = [
        {"name": name, "sha256": sha256(canonical_bytes(record.to_mapping())).hexdigest()}
        for name, record in records
    ]
    return sha256(canonical_bytes({"records": hashed})).hexdigest()
