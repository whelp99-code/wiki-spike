"""Body-free fixture export evidence contract."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import parse_decimal
from .unified_db_snapshot_export_result import EXPORT_STATE, require_export_flags

EVIDENCE_VERSION: Final = "second-brain-unified-db-export-evidence-v1"
_EVIDENCE_FIELDS: Final = frozenset(
    {
        "evidence_version",
        "state",
        "coverage_scope",
        "body_reads_in_evidence",
        "source_mutation",
        "source_unchanged",
        "import_invoked",
        "serving_promotion",
        "cutover_eligible",
        "live_export_authorized",
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
        "evidence_digest",
    }
)


@dataclass(frozen=True, slots=True)
class UnifiedDbExportEvidenceV1:
    evidence_version: str
    state: str
    coverage_scope: str
    body_reads_in_evidence: str
    source_mutation: bool
    source_unchanged: bool
    import_invoked: bool
    serving_promotion: bool
    cutover_eligible: bool
    live_export_authorized: bool
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
    evidence_digest: str

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
    ) -> UnifiedDbExportEvidenceV1:
        provisional = cls(
            EVIDENCE_VERSION,
            EXPORT_STATE,
            "fixture-only",
            "0",
            False,
            True,
            False,
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
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"evidence_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbExportEvidenceV1:
        strict_fields(data, _EVIDENCE_FIELDS)
        version = parse_string(data["evidence_version"], "evidence_version")
        if version != EVIDENCE_VERSION:
            raise UnsupportedContractVersion(f"unsupported evidence_version: {version!r}")
        require_export_flags(data)
        if data["live_export_authorized"] is not False:
            raise InvalidContractValue("live_export_authorized must be false")
        if data["coverage_scope"] != "fixture-only":
            raise InvalidContractValue("coverage_scope must be fixture-only")
        evidence = cls(
            version,
            parse_string(data["state"], "state"),
            "fixture-only",
            "0",
            False,
            True,
            False,
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
            parse_digest(data["evidence_digest"], "evidence_digest"),
        )
        if evidence.state != EXPORT_STATE:
            raise InvalidContractValue("state must be FIXTURE_EXPORTED_NOT_AUTHORIZED")
        if evidence.evidence_digest != evidence.computed_digest():
            raise InvalidContractValue("evidence_digest does not bind evidence fields")
        return evidence

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["evidence_digest"]
        return canonical_ledger_digest("unified-db-export-evidence-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "evidence_version": self.evidence_version,
            "state": self.state,
            "coverage_scope": self.coverage_scope,
            "body_reads_in_evidence": self.body_reads_in_evidence,
            "source_mutation": self.source_mutation,
            "source_unchanged": self.source_unchanged,
            "import_invoked": self.import_invoked,
            "serving_promotion": self.serving_promotion,
            "cutover_eligible": self.cutover_eligible,
            "live_export_authorized": self.live_export_authorized,
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
            "evidence_digest": self.evidence_digest,
        }
