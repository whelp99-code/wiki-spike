"""Bounded, sorted catalog snapshot for later mapper review."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_postgres_capture_rows import (
    CatalogColumnRowV1,
    CatalogConstraintRowV1,
    CatalogIndexRowV1,
    CatalogRowV1,
    CatalogSchemaRowV1,
    CatalogTableRowV1,
    parse_catalog_row,
)
from .unified_db_snapshot_export import parse_decimal

CATALOG_VERSION: Final = "second-brain-unified-db-postgres-catalog-v1"
CATALOG_DOMAIN: Final = "unified-db-postgres-catalog-v1"
MAX_CATALOG_ROWS: Final = 4096
MAX_CATALOG_BYTES: Final = 1048576
_SNAPSHOT_FIELDS: Final = frozenset(
    {"catalog_version", "rows", "row_count", "byte_count", "catalog_digest"}
)

__all__ = (
    "CATALOG_DOMAIN",
    "CATALOG_VERSION",
    "MAX_CATALOG_BYTES",
    "MAX_CATALOG_ROWS",
    "CatalogColumnRowV1",
    "CatalogConstraintRowV1",
    "CatalogIndexRowV1",
    "CatalogRowV1",
    "CatalogSchemaRowV1",
    "CatalogTableRowV1",
    "PostgresCatalogSnapshotV1",
    "parse_catalog_row",
)


@dataclass(frozen=True, slots=True)
class PostgresCatalogSnapshotV1:
    catalog_version: str
    rows: tuple[CatalogRowV1, ...]
    row_count: str
    byte_count: str
    catalog_digest: str

    @classmethod
    def from_rows(cls, rows: tuple[CatalogRowV1, ...]) -> PostgresCatalogSnapshotV1:
        encoded: list[JsonValue] = []
        for row in rows:
            encoded.append(row.to_mapping())
        unsigned: dict[str, JsonValue] = {
            "catalog_version": CATALOG_VERSION,
            "rows": encoded,
            "row_count": str(len(rows)),
            "byte_count": str(len(canonical_bytes({"rows": encoded}))),
        }
        return cls.from_mapping(
            unsigned | {"catalog_digest": canonical_ledger_digest(CATALOG_DOMAIN, unsigned)}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PostgresCatalogSnapshotV1:
        strict_fields(data, _SNAPSHOT_FIELDS)
        version = parse_string(data["catalog_version"], "catalog_version")
        if version != CATALOG_VERSION:
            raise UnsupportedContractVersion(f"unsupported catalog_version: {version!r}")
        raw = data["rows"]
        if not isinstance(raw, list):
            raise InvalidContractValue("rows must be an array")
        if len(raw) > MAX_CATALOG_ROWS:
            raise InvalidContractValue("catalog row bound exceeded")
        rows = tuple(parse_catalog_row(item) for item in raw if isinstance(item, Mapping))
        if len(rows) != len(raw):
            raise InvalidContractValue("every catalog row must be an object")
        keys = tuple(row.sort_key() for row in rows)
        if keys != tuple(sorted(set(keys))):
            if len(set(keys)) != len(keys):
                raise InvalidContractValue("catalog rows must be unique without duplicates")
            raise InvalidContractValue("catalog rows must be lexically sorted")
        encoded = [row.to_mapping() for row in rows]
        byte_count = parse_decimal(data["byte_count"], "byte_count")
        expected_bytes = str(len(canonical_bytes({"rows": encoded})))
        if byte_count != expected_bytes:
            raise InvalidContractValue("byte_count does not match catalog rows")
        if int(byte_count) > MAX_CATALOG_BYTES:
            raise InvalidContractValue("byte_count exceeds the catalog bound")
        row_count = parse_decimal(data["row_count"], "row_count")
        if row_count != str(len(rows)):
            raise InvalidContractValue("row_count does not match catalog rows")
        parsed = cls(
            version,
            rows,
            row_count,
            byte_count,
            parse_digest(data["catalog_digest"], "catalog_digest"),
        )
        if parsed.catalog_digest != parsed.computed_digest():
            raise InvalidContractValue("catalog_digest does not bind catalog rows")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["catalog_digest"]
        return canonical_ledger_digest(CATALOG_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "catalog_version": self.catalog_version,
            "rows": [row.to_mapping() for row in self.rows],
            "row_count": self.row_count,
            "byte_count": self.byte_count,
            "catalog_digest": self.catalog_digest,
        }
