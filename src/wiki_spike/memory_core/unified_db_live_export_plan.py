"""One-shot live export plan binding identity, mapping, and commitments."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_export_authorization import AUTHORIZATION_KIND
from .unified_db_live_export_mapping import ABSENCE_POLICY, DELETION_SEMANTICS
from .unified_db_live_export_parse import parse_ascii_token, parse_mapper_version
from .unified_db_snapshot_export import EXPORT_ONLY, parse_const

LIVE_PLAN_VERSION: Final = "second-brain-unified-db-live-export-plan-v1"
LIVE_PLAN_DOMAIN: Final = "unified-db-live-export-plan-v1"
_FIELDS: Final = frozenset(
    {
        "plan_version",
        "source_name",
        "operation",
        "authorization_kind",
        "profile_digest",
        "source_identity_digest",
        "catalog_digest",
        "mapper_id",
        "mapper_version",
        "mapping_digest",
        "adapter_digest",
        "destination_digest",
        "quiescence_digest",
        "deletion_semantics",
        "absence_policy",
        "plan_digest",
    }
)


@dataclass(frozen=True, slots=True)
class UnifiedDbLiveExportPlanV1:
    plan_version: str
    source_name: str
    operation: str
    authorization_kind: str
    profile_digest: str
    source_identity_digest: str
    catalog_digest: str
    mapper_id: str
    mapper_version: str
    mapping_digest: str
    adapter_digest: str
    destination_digest: str
    quiescence_digest: str
    deletion_semantics: str
    absence_policy: str
    plan_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbLiveExportPlanV1:
        strict_fields(data, _FIELDS)
        version = parse_string(data["plan_version"], "plan_version")
        if version != LIVE_PLAN_VERSION:
            raise UnsupportedContractVersion(f"unsupported plan_version: {version!r}")
        parsed = cls(
            version,
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_const(data["operation"], "operation", EXPORT_ONLY),
            parse_const(data["authorization_kind"], "authorization_kind", AUTHORIZATION_KIND),
            parse_digest(data["profile_digest"], "profile_digest"),
            parse_digest(data["source_identity_digest"], "source_identity_digest"),
            parse_digest(data["catalog_digest"], "catalog_digest"),
            parse_ascii_token(data["mapper_id"], "mapper_id"),
            parse_mapper_version(data["mapper_version"], "mapper_version"),
            parse_digest(data["mapping_digest"], "mapping_digest"),
            parse_digest(data["adapter_digest"], "adapter_digest"),
            parse_digest(data["destination_digest"], "destination_digest"),
            parse_digest(data["quiescence_digest"], "quiescence_digest"),
            parse_const(
                data["deletion_semantics"], "deletion_semantics", DELETION_SEMANTICS
            ),
            parse_const(data["absence_policy"], "absence_policy", ABSENCE_POLICY),
            parse_digest(data["plan_digest"], "plan_digest"),
        )
        if parsed.mapper_id == parsed.source_identity_digest:
            raise InvalidContractValue("mapper identity must be distinct from source identity")
        if parsed.plan_digest != parsed.computed_digest():
            raise InvalidContractValue("plan_digest does not bind plan fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["plan_digest"]
        return canonical_ledger_digest(LIVE_PLAN_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "plan_version": self.plan_version,
            "source_name": self.source_name,
            "operation": self.operation,
            "authorization_kind": self.authorization_kind,
            "profile_digest": self.profile_digest,
            "source_identity_digest": self.source_identity_digest,
            "catalog_digest": self.catalog_digest,
            "mapper_id": self.mapper_id,
            "mapper_version": self.mapper_version,
            "mapping_digest": self.mapping_digest,
            "adapter_digest": self.adapter_digest,
            "destination_digest": self.destination_digest,
            "quiescence_digest": self.quiescence_digest,
            "deletion_semantics": self.deletion_semantics,
            "absence_policy": self.absence_policy,
            "plan_digest": self.plan_digest,
        }
