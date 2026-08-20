"""Column, constraint, and index catalog-row variants."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .contracts import JsonValue
from .errors import InvalidContractValue
from .snapshot_import_parse import parse_string, strict_fields
from .unified_db_live_export_parse import parse_identifier
from .unified_db_snapshot_export import parse_const, parse_decimal

_BOOLS = frozenset({"true", "false"})
_CONSTRAINTS = frozenset({"p", "f", "u", "c"})


@dataclass(frozen=True, slots=True)
class CatalogColumnRowV1:
    kind: str
    schema_name: str
    table_name: str
    column_name: str
    ordinal: str
    type_name: str
    not_null: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> CatalogColumnRowV1:
        strict_fields(
            data,
            frozenset(
                {
                    "kind",
                    "schema_name",
                    "table_name",
                    "column_name",
                    "ordinal",
                    "type_name",
                    "not_null",
                }
            ),
        )
        return cls(
            parse_const(data["kind"], "kind", "column"),
            parse_identifier(data["schema_name"], "schema_name"),
            parse_identifier(data["table_name"], "table_name"),
            parse_identifier(data["column_name"], "column_name"),
            parse_decimal(data["ordinal"], "ordinal"),
            parse_identifier(data["type_name"], "type_name"),
            _parse_flag(data["not_null"], "not_null"),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "kind": self.kind,
            "schema_name": self.schema_name,
            "table_name": self.table_name,
            "column_name": self.column_name,
            "ordinal": self.ordinal,
            "type_name": self.type_name,
            "not_null": self.not_null,
        }

    def sort_key(self) -> tuple[str, ...]:
        return ("2", self.schema_name, self.table_name, self.ordinal, self.column_name)


@dataclass(frozen=True, slots=True)
class CatalogConstraintRowV1:
    kind: str
    schema_name: str
    table_name: str
    constraint_name: str
    constraint_type: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> CatalogConstraintRowV1:
        strict_fields(
            data,
            frozenset(
                {"kind", "schema_name", "table_name", "constraint_name", "constraint_type"}
            ),
        )
        constraint_type = parse_string(data["constraint_type"], "constraint_type")
        if constraint_type not in _CONSTRAINTS:
            raise InvalidContractValue("constraint_type is not closed")
        return cls(
            parse_const(data["kind"], "kind", "constraint"),
            parse_identifier(data["schema_name"], "schema_name"),
            parse_identifier(data["table_name"], "table_name"),
            parse_identifier(data["constraint_name"], "constraint_name"),
            constraint_type,
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "kind": self.kind,
            "schema_name": self.schema_name,
            "table_name": self.table_name,
            "constraint_name": self.constraint_name,
            "constraint_type": self.constraint_type,
        }

    def sort_key(self) -> tuple[str, ...]:
        return ("3", self.schema_name, self.table_name, self.constraint_name)


@dataclass(frozen=True, slots=True)
class CatalogIndexRowV1:
    kind: str
    schema_name: str
    table_name: str
    index_name: str
    unique: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> CatalogIndexRowV1:
        strict_fields(
            data, frozenset({"kind", "schema_name", "table_name", "index_name", "unique"})
        )
        return cls(
            parse_const(data["kind"], "kind", "index"),
            parse_identifier(data["schema_name"], "schema_name"),
            parse_identifier(data["table_name"], "table_name"),
            parse_identifier(data["index_name"], "index_name"),
            _parse_flag(data["unique"], "unique"),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "kind": self.kind,
            "schema_name": self.schema_name,
            "table_name": self.table_name,
            "index_name": self.index_name,
            "unique": self.unique,
        }

    def sort_key(self) -> tuple[str, ...]:
        return ("4", self.schema_name, self.table_name, self.index_name)


def _parse_flag(value: JsonValue, field: str) -> str:
    text = parse_string(value, field)
    if text not in _BOOLS:
        raise InvalidContractValue(f"{field} must be true or false")
    return text
