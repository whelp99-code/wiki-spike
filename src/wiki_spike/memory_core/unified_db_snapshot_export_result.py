"""Body-free export receipt contract."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import (
    EXPORT_ONLY,
    parse_decimal,
    parse_false,
    parse_true,
)

RECEIPT_VERSION: Final = "second-brain-unified-db-export-receipt-v1"
EXPORT_STATE: Final = "FIXTURE_EXPORTED_NOT_AUTHORIZED"
_RECEIPT_FIELDS: Final = frozenset(
    {
        "receipt_version",
        "state",
        "operation",
        "source_name",
        "body_reads_in_evidence",
        "source_mutation",
        "source_unchanged",
        "import_invoked",
        "serving_promotion",
        "cutover_eligible",
        "plaintext_leaked",
        "native_identity_leaked",
        "record_count",
        "live_record_count",
        "tombstone_count",
        "byte_count",
        "snapshot_digest",
        "payload_manifest_digest",
        "cursor_map_digest",
        "opening_proof_digest",
        "closing_proof_digest",
        "package_digest",
        "profile_digest",
        "plan_digest",
        "evidence_digest",
        "receipt_digest",
    }
)


def require_export_flags(data: Mapping[str, JsonValue]) -> None:
    _ = parse_false(data["source_mutation"], "source_mutation")
    _ = parse_true(data["source_unchanged"], "source_unchanged")
    _ = parse_false(data["import_invoked"], "import_invoked")
    _ = parse_false(data["serving_promotion"], "serving_promotion")
    _ = parse_false(data["cutover_eligible"], "cutover_eligible")
    _ = parse_false(data["plaintext_leaked"], "plaintext_leaked")
    _ = parse_false(data["native_identity_leaked"], "native_identity_leaked")
    if data["body_reads_in_evidence"] != "0":
        raise InvalidContractValue("body_reads_in_evidence must be 0")


@dataclass(frozen=True, slots=True)
class UnifiedDbExportReceiptV1:
    receipt_version: str
    state: str
    operation: str
    source_name: str
    body_reads_in_evidence: str
    source_mutation: bool
    source_unchanged: bool
    import_invoked: bool
    serving_promotion: bool
    cutover_eligible: bool
    plaintext_leaked: bool
    native_identity_leaked: bool
    record_count: str
    live_record_count: str
    tombstone_count: str
    byte_count: str
    snapshot_digest: str
    payload_manifest_digest: str
    cursor_map_digest: str
    opening_proof_digest: str
    closing_proof_digest: str
    package_digest: str
    profile_digest: str
    plan_digest: str
    evidence_digest: str
    receipt_digest: str

    @classmethod
    def create(
        cls,
        record_count: str,
        live_record_count: str,
        tombstone_count: str,
        byte_count: str,
        snapshot_digest: str,
        payload_manifest_digest: str,
        cursor_map_digest: str,
        opening_proof_digest: str,
        closing_proof_digest: str,
        package_digest: str,
        profile_digest: str,
        plan_digest: str,
        evidence_digest: str,
    ) -> UnifiedDbExportReceiptV1:
        provisional = cls(
            RECEIPT_VERSION,
            EXPORT_STATE,
            EXPORT_ONLY,
            "unified-db",
            "0",
            False,
            True,
            False,
            False,
            False,
            False,
            False,
            record_count,
            live_record_count,
            tombstone_count,
            byte_count,
            snapshot_digest,
            payload_manifest_digest,
            cursor_map_digest,
            opening_proof_digest,
            closing_proof_digest,
            package_digest,
            profile_digest,
            plan_digest,
            evidence_digest,
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"receipt_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbExportReceiptV1:
        strict_fields(data, _RECEIPT_FIELDS)
        version = parse_string(data["receipt_version"], "receipt_version")
        if version != RECEIPT_VERSION:
            raise UnsupportedContractVersion(f"unsupported receipt_version: {version!r}")
        require_export_flags(data)
        receipt = cls(
            version,
            parse_string(data["state"], "state"),
            parse_string(data["operation"], "operation"),
            parse_string(data["source_name"], "source_name"),
            "0",
            False,
            True,
            False,
            False,
            False,
            False,
            False,
            parse_decimal(data["record_count"], "record_count"),
            parse_decimal(data["live_record_count"], "live_record_count"),
            parse_decimal(data["tombstone_count"], "tombstone_count"),
            parse_decimal(data["byte_count"], "byte_count"),
            parse_digest(data["snapshot_digest"], "snapshot_digest"),
            parse_digest(data["payload_manifest_digest"], "payload_manifest_digest"),
            parse_digest(data["cursor_map_digest"], "cursor_map_digest"),
            parse_digest(data["opening_proof_digest"], "opening_proof_digest"),
            parse_digest(data["closing_proof_digest"], "closing_proof_digest"),
            parse_digest(data["package_digest"], "package_digest"),
            parse_digest(data["profile_digest"], "profile_digest"),
            parse_digest(data["plan_digest"], "plan_digest"),
            parse_digest(data["evidence_digest"], "evidence_digest"),
            parse_digest(data["receipt_digest"], "receipt_digest"),
        )
        if receipt.state != EXPORT_STATE or receipt.operation != EXPORT_ONLY:
            raise InvalidContractValue("receipt must stay fixture export-only")
        if receipt.source_name != "unified-db":
            raise InvalidContractValue("source_name must be unified-db")
        if receipt.receipt_digest != receipt.computed_digest():
            raise InvalidContractValue("receipt_digest does not bind receipt fields")
        return receipt

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["receipt_digest"]
        return canonical_ledger_digest("unified-db-export-receipt-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "receipt_version": self.receipt_version,
            "state": self.state,
            "operation": self.operation,
            "source_name": self.source_name,
            "body_reads_in_evidence": self.body_reads_in_evidence,
            "source_mutation": self.source_mutation,
            "source_unchanged": self.source_unchanged,
            "import_invoked": self.import_invoked,
            "serving_promotion": self.serving_promotion,
            "cutover_eligible": self.cutover_eligible,
            "plaintext_leaked": self.plaintext_leaked,
            "native_identity_leaked": self.native_identity_leaked,
            "record_count": self.record_count,
            "live_record_count": self.live_record_count,
            "tombstone_count": self.tombstone_count,
            "byte_count": self.byte_count,
            "snapshot_digest": self.snapshot_digest,
            "payload_manifest_digest": self.payload_manifest_digest,
            "cursor_map_digest": self.cursor_map_digest,
            "opening_proof_digest": self.opening_proof_digest,
            "closing_proof_digest": self.closing_proof_digest,
            "package_digest": self.package_digest,
            "profile_digest": self.profile_digest,
            "plan_digest": self.plan_digest,
            "evidence_digest": self.evidence_digest,
            "receipt_digest": self.receipt_digest,
        }
