"""Profile and plan contracts for fixture-only unified-db export."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import (
    ABSENCE_POLICY,
    DELETION_POLICY,
    EXPORT_ONLY,
    HISTORY_POLICY,
    IDENTITY_MAPPING,
    MAX_BOUND,
    PLAN_VERSION,
    PROFILE_VERSION,
    REVISION_MAPPING,
    ROW_ORDER,
    WATERMARK_MAPPING,
    parse_const,
    parse_decimal,
    parse_false,
    parse_names,
)

_PROFILE_FIELDS: Final = frozenset(
    {
        "profile_version",
        "source_name",
        "operation",
        "source_allowlist",
        "identity_mapping",
        "revision_mapping",
        "watermark_mapping",
        "deletion_policy",
        "history_policy",
        "absence_policy",
        "import_requested",
        "serve_requested",
        "promote_requested",
        "cutover_requested",
        "max_records",
        "max_record_bytes",
        "max_aggregate_bytes",
        "profile_digest",
    }
)
_PLAN_FIELDS: Final = frozenset(
    {
        "plan_version",
        "profile_digest",
        "fixture_id",
        "fixture_digest",
        "row_set_digest",
        "expected_source_ids",
        "row_order",
        "db_commitment",
        "catalog_commitment",
        "source_commitment",
        "data_root_commitment",
        "plan_digest",
    }
)


@dataclass(frozen=True, slots=True)
class UnifiedDbExportProfileV1:
    profile_version: str
    source_name: str
    operation: str
    source_allowlist: tuple[str, ...]
    identity_mapping: str
    revision_mapping: str
    watermark_mapping: str
    deletion_policy: str
    history_policy: str
    absence_policy: str
    import_requested: bool
    serve_requested: bool
    promote_requested: bool
    cutover_requested: bool
    max_records: str
    max_record_bytes: str
    max_aggregate_bytes: str
    profile_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbExportProfileV1:
        strict_fields(data, _PROFILE_FIELDS)
        version = parse_string(data["profile_version"], "profile_version")
        if version != PROFILE_VERSION:
            raise UnsupportedContractVersion(f"unsupported profile_version: {version!r}")
        profile = cls(
            version,
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_const(data["operation"], "operation", EXPORT_ONLY),
            parse_names(data["source_allowlist"], "source_allowlist"),
            parse_const(data["identity_mapping"], "identity_mapping", IDENTITY_MAPPING),
            parse_const(data["revision_mapping"], "revision_mapping", REVISION_MAPPING),
            parse_const(data["watermark_mapping"], "watermark_mapping", WATERMARK_MAPPING),
            parse_const(data["deletion_policy"], "deletion_policy", DELETION_POLICY),
            parse_const(data["history_policy"], "history_policy", HISTORY_POLICY),
            parse_const(data["absence_policy"], "absence_policy", ABSENCE_POLICY),
            parse_false(data["import_requested"], "import_requested"),
            parse_false(data["serve_requested"], "serve_requested"),
            parse_false(data["promote_requested"], "promote_requested"),
            parse_false(data["cutover_requested"], "cutover_requested"),
            parse_decimal(data["max_records"], "max_records"),
            parse_decimal(data["max_record_bytes"], "max_record_bytes"),
            parse_decimal(data["max_aggregate_bytes"], "max_aggregate_bytes"),
            parse_digest(data["profile_digest"], "profile_digest"),
        )
        if int(profile.max_record_bytes) > int(MAX_BOUND) or int(profile.max_aggregate_bytes) > int(
            MAX_BOUND
        ):
            raise InvalidContractValue("export bound exceeds 1048576")
        if profile.profile_digest != profile.computed_digest():
            raise InvalidContractValue("profile_digest does not bind profile fields")
        return profile

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["profile_digest"]
        return canonical_ledger_digest("unified-db-export-profile-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "profile_version": self.profile_version,
            "source_name": self.source_name,
            "operation": self.operation,
            "source_allowlist": list(self.source_allowlist),
            "identity_mapping": self.identity_mapping,
            "revision_mapping": self.revision_mapping,
            "watermark_mapping": self.watermark_mapping,
            "deletion_policy": self.deletion_policy,
            "history_policy": self.history_policy,
            "absence_policy": self.absence_policy,
            "import_requested": self.import_requested,
            "serve_requested": self.serve_requested,
            "promote_requested": self.promote_requested,
            "cutover_requested": self.cutover_requested,
            "max_records": self.max_records,
            "max_record_bytes": self.max_record_bytes,
            "max_aggregate_bytes": self.max_aggregate_bytes,
            "profile_digest": self.profile_digest,
        }


@dataclass(frozen=True, slots=True)
class UnifiedDbExportPlanV1:
    plan_version: str
    profile_digest: str
    fixture_id: str
    fixture_digest: str
    row_set_digest: str
    expected_source_ids: tuple[str, ...]
    row_order: str
    db_commitment: str
    catalog_commitment: str
    source_commitment: str
    data_root_commitment: str
    plan_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbExportPlanV1:
        strict_fields(data, _PLAN_FIELDS)
        version = parse_string(data["plan_version"], "plan_version")
        if version != PLAN_VERSION:
            raise UnsupportedContractVersion(f"unsupported plan_version: {version!r}")
        plan = cls(
            version,
            parse_digest(data["profile_digest"], "profile_digest"),
            parse_string(data["fixture_id"], "fixture_id"),
            parse_digest(data["fixture_digest"], "fixture_digest"),
            parse_digest(data["row_set_digest"], "row_set_digest"),
            parse_names(data["expected_source_ids"], "expected_source_ids"),
            parse_const(data["row_order"], "row_order", ROW_ORDER),
            parse_digest(data["db_commitment"], "db_commitment"),
            parse_digest(data["catalog_commitment"], "catalog_commitment"),
            parse_digest(data["source_commitment"], "source_commitment"),
            parse_digest(data["data_root_commitment"], "data_root_commitment"),
            parse_digest(data["plan_digest"], "plan_digest"),
        )
        if plan.plan_digest != plan.computed_digest():
            raise InvalidContractValue("plan_digest does not bind plan fields")
        return plan

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["plan_digest"]
        return canonical_ledger_digest("unified-db-export-plan-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "plan_version": self.plan_version,
            "profile_digest": self.profile_digest,
            "fixture_id": self.fixture_id,
            "fixture_digest": self.fixture_digest,
            "row_set_digest": self.row_set_digest,
            "expected_source_ids": list(self.expected_source_ids),
            "row_order": self.row_order,
            "db_commitment": self.db_commitment,
            "catalog_commitment": self.catalog_commitment,
            "source_commitment": self.source_commitment,
            "data_root_commitment": self.data_root_commitment,
            "plan_digest": self.plan_digest,
        }
