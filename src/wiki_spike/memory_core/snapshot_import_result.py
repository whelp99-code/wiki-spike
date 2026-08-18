"""Receipt, restore, and payload types for non-serving snapshot import."""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import import SnapshotImportRequestV1

SNAPSHOT_IMPORT_RECEIPT_V1: Final = "second-brain-snapshot-import-receipt-v1"
SCOPE_JOIN_SEAM_V1: Final = "second-brain-snapshot-import-scope-join-v1"
IMPORT_STATE_READY: Final = "READY_NON_SERVING"
IMPORT_TRANSITIONS: Final = (
    "DISCOVERED",
    "IMPORTING",
    "RECONCILING",
    "READY_NON_SERVING",
)
SCOPE_AUTHORITY_NON_AUTHORITATIVE: Final = "NON_AUTHORITATIVE_CALLER_ASSERTED"

_DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")
_TOKEN: Final = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_RECEIPT_FIELDS: Final = frozenset(
    {
        "receipt_version",
        "cohort_id",
        "state",
        "transitions",
        "serving_promoted",
        "cutover_eligible",
        "scope_authority_state",
        "scope_join_seam",
        "resolved_scope_digest",
        "discovery_manifest_digest",
        "snapshot_digest",
        "record_count",
        "receipt_digest",
    }
)


def _strict(data: Mapping[str, JsonValue], fields: frozenset[str]) -> None:
    unknown = set(data) - fields
    if unknown:
        raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    missing = fields - set(data)
    if missing:
        raise InvalidContractValue(f"missing required fields: {sorted(missing)}")


def _string(value: JsonValue, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty string")
    return value


def _digest(value: JsonValue, field: str) -> str:
    parsed = _string(value, field)
    if _DIGEST.fullmatch(parsed) is None:
        raise InvalidContractValue(f"{field} must be a lowercase SHA-256 digest")
    return parsed


@dataclass(frozen=True, slots=True)
class ImportedRecordPayloadV1:
    native_id: str
    revision: str
    watermark: str
    tombstone: bool
    relative_path: str | None
    content_digest: str | None
    content: bytes | None


@dataclass(frozen=True, slots=True)
class RestoredSnapshotRecordV1:
    native_id: str
    revision: str
    watermark: str
    tombstone: bool
    content: bytes | None


@dataclass(frozen=True, slots=True)
class RestoredSnapshotV1:
    records: tuple[RestoredSnapshotRecordV1, ...]


@dataclass(frozen=True, slots=True)
class SnapshotImportReceiptV1:
    receipt_version: str
    cohort_id: str
    state: str
    transitions: tuple[str, ...]
    serving_promoted: bool
    cutover_eligible: bool
    scope_authority_state: str
    scope_join_seam: str
    resolved_scope_digest: str
    discovery_manifest_digest: str
    snapshot_digest: str
    record_count: str
    receipt_digest: str

    @classmethod
    def create(
        cls, request: SnapshotImportRequestV1, record_count: int
    ) -> SnapshotImportReceiptV1:
        if record_count < 0:
            raise InvalidContractValue("record_count must be a non-negative integer")
        provisional = cls(
            SNAPSHOT_IMPORT_RECEIPT_V1,
            request.cohort_id,
            IMPORT_STATE_READY,
            IMPORT_TRANSITIONS,
            False,
            False,
            SCOPE_AUTHORITY_NON_AUTHORITATIVE,
            SCOPE_JOIN_SEAM_V1,
            request.resolved_scope_digest,
            request.discovery_manifest_digest,
            request.snapshot_digest,
            str(record_count),
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"receipt_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> SnapshotImportReceiptV1:
        _strict(data, _RECEIPT_FIELDS)
        version = _string(data["receipt_version"], "receipt_version")
        if version != SNAPSHOT_IMPORT_RECEIPT_V1:
            raise UnsupportedContractVersion(f"unsupported receipt_version: {version!r}")
        transitions = data["transitions"]
        if not isinstance(transitions, list) or any(
            not isinstance(item, str) for item in transitions
        ):
            raise InvalidContractValue("transitions must be an array of strings")
        parsed = tuple(str(item) for item in transitions)
        if parsed != IMPORT_TRANSITIONS:
            raise InvalidContractValue("transitions must be the closed non-serving sequence")
        if data["serving_promoted"] is not False or data["cutover_eligible"] is not False:
            raise InvalidContractValue("receipt must remain non-serving and non-cutover")
        authority = _string(data["scope_authority_state"], "scope_authority_state")
        if authority != SCOPE_AUTHORITY_NON_AUTHORITATIVE:
            raise InvalidContractValue(
                "resolved_scope_digest is not serving or cutover authority"
            )
        seam = _string(data["scope_join_seam"], "scope_join_seam")
        if seam != SCOPE_JOIN_SEAM_V1:
            raise InvalidContractValue("scope_join_seam is not the strict later join seam")
        count = _string(data["record_count"], "record_count")
        if re.fullmatch(r"^(0|[1-9][0-9]*)$", count) is None:
            raise InvalidContractValue("record_count must be a canonical decimal string")
        receipt = cls(
            version,
            _string(data["cohort_id"], "cohort_id"),
            _string(data["state"], "state"),
            parsed,
            False,
            False,
            authority,
            seam,
            _digest(data["resolved_scope_digest"], "resolved_scope_digest"),
            _digest(data["discovery_manifest_digest"], "discovery_manifest_digest"),
            _digest(data["snapshot_digest"], "snapshot_digest"),
            count,
            _digest(data["receipt_digest"], "receipt_digest"),
        )
        if receipt.state != IMPORT_STATE_READY:
            raise InvalidContractValue("state must be READY_NON_SERVING")
        if _TOKEN.fullmatch(receipt.cohort_id) is None:
            raise InvalidContractValue("cohort_id has an invalid shape")
        if receipt.receipt_digest != receipt.computed_digest():
            raise InvalidContractValue("receipt_digest does not bind receipt fields")
        return receipt

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["receipt_digest"]
        return canonical_ledger_digest("snapshot-import-receipt-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "receipt_version": self.receipt_version,
            "cohort_id": self.cohort_id,
            "state": self.state,
            "transitions": list(self.transitions),
            "serving_promoted": self.serving_promoted,
            "cutover_eligible": self.cutover_eligible,
            "scope_authority_state": self.scope_authority_state,
            "scope_join_seam": self.scope_join_seam,
            "resolved_scope_digest": self.resolved_scope_digest,
            "discovery_manifest_digest": self.discovery_manifest_digest,
            "snapshot_digest": self.snapshot_digest,
            "record_count": self.record_count,
            "receipt_digest": self.receipt_digest,
        }


def snapshot_import_scope_join_payload(
    receipt: SnapshotImportReceiptV1,
) -> dict[str, JsonValue]:
    """Later Stage-6 join seam. This receipt is not cutover or serving authority."""
    return {
        "scope_join_seam": receipt.scope_join_seam,
        "scope_authority_state": receipt.scope_authority_state,
        "cutover_eligible": False,
        "serving_promoted": False,
        "resolved_scope_digest": receipt.resolved_scope_digest,
        "discovery_manifest_digest": receipt.discovery_manifest_digest,
        "snapshot_digest": receipt.snapshot_digest,
        "cohort_id": receipt.cohort_id,
    }
