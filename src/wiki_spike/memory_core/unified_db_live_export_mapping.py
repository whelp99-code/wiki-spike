"""Reviewed live-export mapping profile with explicit deletion semantics."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_live_export_parse import (
    parse_ascii_token,
    parse_identifier,
    parse_mapper_version,
    parse_qualified_table,
    require_column,
)
from .unified_db_snapshot_export import parse_const, parse_names

MAPPING_VERSION: Final = "second-brain-unified-db-live-export-mapping-v1"
MAPPING_DOMAIN: Final = "unified-db-live-export-mapping-v1"
DELETION_SEMANTICS: Final = "EXPLICIT_TOMBSTONE_ONLY"
ABSENCE_POLICY: Final = "ABSENCE_IS_NOT_DELETION"
_FIELDS: Final = frozenset(
    {
        "mapping_version",
        "mapper_id",
        "mapper_version",
        "source_name",
        "source_identity_digest",
        "table",
        "columns",
        "native_identity",
        "revision",
        "content_hash",
        "watermark",
        "tombstone",
        "deletion_semantics",
        "absence_policy",
        "select_template_digest",
        "mapping_digest",
    }
)


@dataclass(frozen=True, slots=True)
class UnifiedDbLiveExportMappingV1:
    mapping_version: str
    mapper_id: str
    mapper_version: str
    source_name: str
    source_identity_digest: str
    table: str
    columns: tuple[str, ...]
    native_identity: str
    revision: str
    content_hash: str
    watermark: str
    tombstone: str
    deletion_semantics: str
    absence_policy: str
    select_template_digest: str
    mapping_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbLiveExportMappingV1:
        strict_fields(data, _FIELDS)
        version = parse_string(data["mapping_version"], "mapping_version")
        if version != MAPPING_VERSION:
            raise UnsupportedContractVersion(f"unsupported mapping_version: {version!r}")
        columns = parse_names(data["columns"], "columns")
        for column in columns:
            _ = parse_identifier(column, "columns")
        parsed = cls(
            version,
            parse_ascii_token(data["mapper_id"], "mapper_id"),
            parse_mapper_version(data["mapper_version"], "mapper_version"),
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_digest(data["source_identity_digest"], "source_identity_digest"),
            parse_qualified_table(data["table"], "table"),
            columns,
            require_column(
                parse_identifier(data["native_identity"], "native_identity"),
                columns,
                "native_identity",
            ),
            require_column(parse_identifier(data["revision"], "revision"), columns, "revision"),
            require_column(
                parse_identifier(data["content_hash"], "content_hash"),
                columns,
                "content_hash",
            ),
            require_column(
                parse_identifier(data["watermark"], "watermark"),
                columns,
                "watermark",
            ),
            require_column(
                parse_identifier(data["tombstone"], "tombstone"),
                columns,
                "tombstone",
            ),
            parse_const(
                data["deletion_semantics"], "deletion_semantics", DELETION_SEMANTICS
            ),
            parse_const(data["absence_policy"], "absence_policy", ABSENCE_POLICY),
            parse_digest(data["select_template_digest"], "select_template_digest"),
            parse_digest(data["mapping_digest"], "mapping_digest"),
        )
        if parsed.mapper_id == parsed.source_identity_digest:
            raise InvalidContractValue("mapper identity must be distinct from source identity")
        if parsed.mapping_digest != parsed.computed_digest():
            raise InvalidContractValue("mapping_digest does not bind mapping fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["mapping_digest"]
        return canonical_ledger_digest(MAPPING_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "mapping_version": self.mapping_version,
            "mapper_id": self.mapper_id,
            "mapper_version": self.mapper_version,
            "source_name": self.source_name,
            "source_identity_digest": self.source_identity_digest,
            "table": self.table,
            "columns": list(self.columns),
            "native_identity": self.native_identity,
            "revision": self.revision,
            "content_hash": self.content_hash,
            "watermark": self.watermark,
            "tombstone": self.tombstone,
            "deletion_semantics": self.deletion_semantics,
            "absence_policy": self.absence_policy,
            "select_template_digest": self.select_template_digest,
            "mapping_digest": self.mapping_digest,
        }
