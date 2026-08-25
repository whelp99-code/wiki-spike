"""Body-free contracts for the resolver-verified production migration import gate.

These value objects are pure, versioned, and serializable evidence records
(mirroring the existing snapshot-import and unified-db export contracts). They
carry no live credentials and prove nothing on their own: the in-process
resolver in ``wiki_spike.applications.production_migration_import_gate`` is the
only place that joins them into a minted, non-serializable authority.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .snapshot_import_result import SnapshotImportReceiptV1

PRODUCTION_MIGRATION_SOURCE: Final = "unified-db"
TRUSTED_DB03_REVISION: Final = "2"
SCOPE_AUTHORITY_RESOLVER_VERIFIED_DB03_GO: Final = "RESOLVER_VERIFIED_DB03_GO"
PRODUCTION_IMPORT_STATE: Final = "READY_NON_SERVING"

LIVE_EXPORT_EVIDENCE_V1: Final = "second-brain-production-live-export-evidence-v1"
LIVE_EXPORT_COVERAGE_SCOPE: Final = "live"
IMMUTABLE_MIGRATION_PACKAGE_V1: Final = "second-brain-immutable-migration-package-v1"
PRODUCTION_MIGRATION_IMPORT_RECEIPT_V1: Final = (
    "second-brain-production-migration-import-receipt-v1"
)

_TIMESTAMP_LEN: Final = 20
_EVIDENCE_FIELDS: Final = frozenset(
    {
        "evidence_version",
        "source_name",
        "coverage_scope",
        "live_export_authorized",
        "record_count",
        "snapshot_digest",
        "discovery_manifest_digest",
        "package_digest",
        "captured_at",
        "expires_at",
        "evidence_digest",
    }
)
_PACKAGE_FIELDS: Final = frozenset(
    {
        "package_version",
        "source_name",
        "snapshot_digest",
        "discovery_manifest_digest",
        "certificate_digest",
        "package_digest",
    }
)
_RECEIPT_FIELDS: Final = frozenset(
    {
        "receipt_version",
        "cohort_id",
        "state",
        "scope_authority_state",
        "serving_promoted",
        "cutover_eligible",
        "resolved_scope_digest",
        "snapshot_digest",
        "discovery_manifest_digest",
        "package_digest",
        "evidence_digest",
        "underlying_receipt_digest",
        "receipt_digest",
    }
)


def parse_canonical_instant(value: JsonValue, field: str) -> str:
    """Parse the canonical ``YYYY-MM-DDTHH:MM:SSZ`` wire timestamp, no fractions."""
    text = parse_string(value, field)
    if len(text) != _TIMESTAMP_LEN or text[10] != "T" or not text.endswith("Z"):
        raise InvalidContractValue(f"{field} must be a canonical UTC timestamp")
    return text


def instant_in_half_open_window(now: str, issued_at: str, expires_at: str) -> bool:
    """Fixed-width canonical UTC strings compare lexicographically like instants."""
    return issued_at <= now < expires_at


@dataclass(frozen=True, slots=True)
class LiveExportEvidenceV1:
    """Body-free proof that a live (non-fixture) unified-db export was captured.

    Distinct from ``unified_db_snapshot_export_evidence.UnifiedDbExportEvidenceV1``,
    which is permanently pinned to ``coverage_scope == "fixture-only"`` and
    ``live_export_authorized is False``. That fixture type can never satisfy
    this contract; the production resolver rejects it by type.
    """

    evidence_version: str
    source_name: str
    coverage_scope: str
    live_export_authorized: bool
    record_count: str
    snapshot_digest: str
    discovery_manifest_digest: str
    package_digest: str
    captured_at: str
    expires_at: str
    evidence_digest: str

    @classmethod
    def create(
        cls,
        *,
        source_name: str,
        record_count: str,
        snapshot_digest: str,
        discovery_manifest_digest: str,
        package_digest: str,
        captured_at: str,
        expires_at: str,
    ) -> LiveExportEvidenceV1:
        provisional = cls(
            LIVE_EXPORT_EVIDENCE_V1,
            source_name,
            LIVE_EXPORT_COVERAGE_SCOPE,
            True,
            record_count,
            snapshot_digest,
            discovery_manifest_digest,
            package_digest,
            captured_at,
            expires_at,
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"evidence_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> LiveExportEvidenceV1:
        strict_fields(data, _EVIDENCE_FIELDS)
        version = parse_string(data["evidence_version"], "evidence_version")
        if version != LIVE_EXPORT_EVIDENCE_V1:
            raise UnsupportedContractVersion(f"unsupported evidence_version: {version!r}")
        if data["coverage_scope"] != LIVE_EXPORT_COVERAGE_SCOPE:
            raise InvalidContractValue("coverage_scope must be live")
        if data["live_export_authorized"] is not True:
            raise InvalidContractValue("live_export_authorized must be true")
        record_count = parse_string(data["record_count"], "record_count")
        captured_at = parse_canonical_instant(data["captured_at"], "captured_at")
        expires_at = parse_canonical_instant(data["expires_at"], "expires_at")
        if expires_at <= captured_at:
            raise InvalidContractValue("expires_at must be after captured_at")
        evidence = cls(
            version,
            parse_string(data["source_name"], "source_name"),
            LIVE_EXPORT_COVERAGE_SCOPE,
            True,
            record_count,
            parse_digest(data["snapshot_digest"], "snapshot_digest"),
            parse_digest(data["discovery_manifest_digest"], "discovery_manifest_digest"),
            parse_digest(data["package_digest"], "package_digest"),
            captured_at,
            expires_at,
            parse_digest(data["evidence_digest"], "evidence_digest"),
        )
        if evidence.evidence_digest != evidence.computed_digest():
            raise InvalidContractValue("evidence_digest does not bind evidence fields")
        return evidence

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["evidence_digest"]
        return canonical_ledger_digest("production-live-export-evidence-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "evidence_version": self.evidence_version,
            "source_name": self.source_name,
            "coverage_scope": self.coverage_scope,
            "live_export_authorized": self.live_export_authorized,
            "record_count": self.record_count,
            "snapshot_digest": self.snapshot_digest,
            "discovery_manifest_digest": self.discovery_manifest_digest,
            "package_digest": self.package_digest,
            "captured_at": self.captured_at,
            "expires_at": self.expires_at,
            "evidence_digest": self.evidence_digest,
        }


@dataclass(frozen=True, slots=True)
class ImmutableMigrationPackageV1:
    """Digest-bound, immutable triple: bounded snapshot + discovery + certificate.

    The certificate binds the manifest to one closed, mutation-checked scan
    (see ``second_brain_complete_snapshot.CompleteSnapshotCertificateV1``), so
    this package cannot be re-pointed at a different snapshot or scan after
    construction without changing ``package_digest``.
    """

    package_version: str
    source_name: str
    snapshot_digest: str
    discovery_manifest_digest: str
    certificate_digest: str
    package_digest: str

    @classmethod
    def create(
        cls,
        *,
        source_name: str,
        snapshot_digest: str,
        discovery_manifest_digest: str,
        certificate_digest: str,
    ) -> ImmutableMigrationPackageV1:
        provisional = cls(
            IMMUTABLE_MIGRATION_PACKAGE_V1,
            source_name,
            snapshot_digest,
            discovery_manifest_digest,
            certificate_digest,
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"package_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> ImmutableMigrationPackageV1:
        strict_fields(data, _PACKAGE_FIELDS)
        version = parse_string(data["package_version"], "package_version")
        if version != IMMUTABLE_MIGRATION_PACKAGE_V1:
            raise UnsupportedContractVersion(f"unsupported package_version: {version!r}")
        package = cls(
            version,
            parse_string(data["source_name"], "source_name"),
            parse_digest(data["snapshot_digest"], "snapshot_digest"),
            parse_digest(data["discovery_manifest_digest"], "discovery_manifest_digest"),
            parse_digest(data["certificate_digest"], "certificate_digest"),
            parse_digest(data["package_digest"], "package_digest"),
        )
        if package.package_digest != package.computed_digest():
            raise InvalidContractValue("package_digest does not bind package fields")
        return package

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["package_digest"]
        return canonical_ledger_digest("immutable-migration-package-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "package_version": self.package_version,
            "source_name": self.source_name,
            "snapshot_digest": self.snapshot_digest,
            "discovery_manifest_digest": self.discovery_manifest_digest,
            "certificate_digest": self.certificate_digest,
            "package_digest": self.package_digest,
        }


@dataclass(frozen=True, slots=True)
class ProductionMigrationImportReceiptV1:
    """Production-gate receipt: resolver-verified, always non-serving/non-cutover.

    This is a distinct wire type from ``snapshot_import_result.SnapshotImportReceiptV1``
    (the #83 fixture importer's receipt, permanently pinned to
    ``scope_authority_state == NON_AUTHORITATIVE_CALLER_ASSERTED``). Minting this
    type never mutates, weakens, or bypasses that contract; it only wraps the
    underlying fixture-mechanism receipt with resolver-verified DB-03 authority
    evidence, and it stays non-serving and non-cutover in exactly the same way.
    """

    receipt_version: str
    cohort_id: str
    state: str
    scope_authority_state: str
    serving_promoted: bool
    cutover_eligible: bool
    resolved_scope_digest: str
    snapshot_digest: str
    discovery_manifest_digest: str
    package_digest: str
    evidence_digest: str
    underlying_receipt_digest: str
    receipt_digest: str

    @classmethod
    def create(
        cls,
        *,
        underlying: SnapshotImportReceiptV1,
        resolved_scope_digest: str,
        package_digest: str,
        evidence_digest: str,
    ) -> ProductionMigrationImportReceiptV1:
        if underlying.state != PRODUCTION_IMPORT_STATE:
            raise InvalidContractValue("underlying receipt must be READY_NON_SERVING")
        provisional = cls(
            PRODUCTION_MIGRATION_IMPORT_RECEIPT_V1,
            underlying.cohort_id,
            PRODUCTION_IMPORT_STATE,
            SCOPE_AUTHORITY_RESOLVER_VERIFIED_DB03_GO,
            False,
            False,
            resolved_scope_digest,
            underlying.snapshot_digest,
            underlying.discovery_manifest_digest,
            package_digest,
            evidence_digest,
            underlying.receipt_digest,
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"receipt_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> ProductionMigrationImportReceiptV1:
        strict_fields(data, _RECEIPT_FIELDS)
        version = parse_string(data["receipt_version"], "receipt_version")
        if version != PRODUCTION_MIGRATION_IMPORT_RECEIPT_V1:
            raise UnsupportedContractVersion(f"unsupported receipt_version: {version!r}")
        if data["state"] != PRODUCTION_IMPORT_STATE:
            raise InvalidContractValue("state must be READY_NON_SERVING")
        if data["scope_authority_state"] != SCOPE_AUTHORITY_RESOLVER_VERIFIED_DB03_GO:
            raise InvalidContractValue(
                "scope_authority_state must be RESOLVER_VERIFIED_DB03_GO"
            )
        if data["serving_promoted"] is not False or data["cutover_eligible"] is not False:
            raise InvalidContractValue("receipt must remain non-serving and non-cutover")
        receipt = cls(
            version,
            parse_string(data["cohort_id"], "cohort_id"),
            PRODUCTION_IMPORT_STATE,
            SCOPE_AUTHORITY_RESOLVER_VERIFIED_DB03_GO,
            False,
            False,
            parse_digest(data["resolved_scope_digest"], "resolved_scope_digest"),
            parse_digest(data["snapshot_digest"], "snapshot_digest"),
            parse_digest(data["discovery_manifest_digest"], "discovery_manifest_digest"),
            parse_digest(data["package_digest"], "package_digest"),
            parse_digest(data["evidence_digest"], "evidence_digest"),
            parse_digest(data["underlying_receipt_digest"], "underlying_receipt_digest"),
            parse_digest(data["receipt_digest"], "receipt_digest"),
        )
        if receipt.receipt_digest != receipt.computed_digest():
            raise InvalidContractValue("receipt_digest does not bind receipt fields")
        return receipt

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["receipt_digest"]
        return canonical_ledger_digest("production-migration-import-receipt-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "receipt_version": self.receipt_version,
            "cohort_id": self.cohort_id,
            "state": self.state,
            "scope_authority_state": self.scope_authority_state,
            "serving_promoted": self.serving_promoted,
            "cutover_eligible": self.cutover_eligible,
            "resolved_scope_digest": self.resolved_scope_digest,
            "snapshot_digest": self.snapshot_digest,
            "discovery_manifest_digest": self.discovery_manifest_digest,
            "package_digest": self.package_digest,
            "evidence_digest": self.evidence_digest,
            "underlying_receipt_digest": self.underlying_receipt_digest,
            "receipt_digest": self.receipt_digest,
        }
