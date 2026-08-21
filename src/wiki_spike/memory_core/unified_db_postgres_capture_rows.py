"""Closed catalog-row variants for schema/table/column/constraint/index metadata."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum, unique

from .contracts import JsonValue
from .errors import InvalidContractValue
from .snapshot_import_parse import parse_string, strict_fields
from .unified_db_live_export_parse import (
    OID_MAX,
    parse_canonical_uint,
    parse_identifier,
)
from .unified_db_postgres_capture_member_rows import (
    CatalogColumnRowV1,
    CatalogConstraintRowV1,
    CatalogIndexRowV1,
)
from .unified_db_snapshot_export import parse_const

__all__ = (
    "CatalogColumnRowV1",
    "CatalogConstraintRowV1",
    "CatalogIndexRowV1",
    "CatalogKind",
    "CatalogRowV1",
    "CatalogSchemaRowV1",
    "CatalogTableRowV1",
    "parse_catalog_row",
)
_RELKIND = "r"


@unique
class CatalogKind(StrEnum):
    SCHEMA = "schema"
    TABLE = "table"
    COLUMN = "column"
    CONSTRAINT = "constraint"
    INDEX = "index"


@dataclass(frozen=True, slots=True)
class CatalogSchemaRowV1:
    kind: str
    schema_name: str
    schema_oid: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> CatalogSchemaRowV1:
        strict_fields(data, frozenset({"kind", "schema_name", "schema_oid"}))
        return cls(
            parse_const(data["kind"], "kind", CatalogKind.SCHEMA.value),
            parse_identifier(data["schema_name"], "schema_name"),
            parse_canonical_uint(data["schema_oid"], "schema_oid", OID_MAX),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "kind": self.kind,
            "schema_name": self.schema_name,
            "schema_oid": self.schema_oid,
        }

    def sort_key(self) -> tuple[str, ...]:
        return ("0", self.schema_name, self.schema_oid)


@dataclass(frozen=True, slots=True)
class CatalogTableRowV1:
    kind: str
    schema_name: str
    table_name: str
    table_oid: str
    relkind: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> CatalogTableRowV1:
        strict_fields(
            data, frozenset({"kind", "schema_name", "table_name", "table_oid", "relkind"})
        )
        return cls(
            parse_const(data["kind"], "kind", CatalogKind.TABLE.value),
            parse_identifier(data["schema_name"], "schema_name"),
            parse_identifier(data["table_name"], "table_name"),
            parse_canonical_uint(data["table_oid"], "table_oid", OID_MAX),
            parse_const(data["relkind"], "relkind", _RELKIND),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "kind": self.kind,
            "schema_name": self.schema_name,
            "table_name": self.table_name,
            "table_oid": self.table_oid,
            "relkind": self.relkind,
        }

    def sort_key(self) -> tuple[str, ...]:
        return ("1", self.schema_name, self.table_name, self.table_oid)


type CatalogRowV1 = (
    CatalogSchemaRowV1
    | CatalogTableRowV1
    | CatalogColumnRowV1
    | CatalogConstraintRowV1
    | CatalogIndexRowV1
)


def parse_catalog_row(data: Mapping[str, JsonValue]) -> CatalogRowV1:
    kind = _parse_kind(data.get("kind") if "kind" in data else None)
    match kind:  # noqa: MATCH_OK
        case CatalogKind.SCHEMA:
            return CatalogSchemaRowV1.from_mapping(data)
        case CatalogKind.TABLE:
            return CatalogTableRowV1.from_mapping(data)
        case CatalogKind.COLUMN:
            return CatalogColumnRowV1.from_mapping(data)
        case CatalogKind.CONSTRAINT:
            return CatalogConstraintRowV1.from_mapping(data)
        case CatalogKind.INDEX:
            return CatalogIndexRowV1.from_mapping(data)


def _parse_kind(value: JsonValue) -> CatalogKind:
    text = parse_string(value, "kind")
    for kind in CatalogKind:
        if kind.value == text:
            return kind
    raise InvalidContractValue("catalog row kind is not closed")
