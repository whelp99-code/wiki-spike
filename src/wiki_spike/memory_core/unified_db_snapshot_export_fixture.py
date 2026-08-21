"""Closed fixture contract bound by plan digest."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import UnifiedDbExportRowV1
from .unified_db_snapshot_export_cursors import SnapshotCursorMapV1

FIXTURE_VERSION: Final = "second-brain-unified-db-export-fixture-v1"
_FIELDS: Final = frozenset(
    {
        "fixture_version",
        "fixture_id",
        "db_commitment",
        "catalog_commitment",
        "source_commitment",
        "data_root_commitment",
        "cursors",
        "rows",
        "row_set_digest",
        "fixture_digest",
    }
)


def row_set_digest(rows: tuple[UnifiedDbExportRowV1, ...]) -> str:
    return canonical_ledger_digest(
        "unified-db-export-row-set-v1",
        {"rows": [row.to_mapping() for row in rows]},
    )


@dataclass(frozen=True, slots=True)
class UnifiedDbExportFixtureV1:
    fixture_version: str
    fixture_id: str
    db_commitment: str
    catalog_commitment: str
    source_commitment: str
    data_root_commitment: str
    cursors: SnapshotCursorMapV1
    rows: tuple[UnifiedDbExportRowV1, ...]
    row_set_digest: str
    fixture_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbExportFixtureV1:
        strict_fields(data, _FIELDS)
        version = parse_string(data["fixture_version"], "fixture_version")
        if version != FIXTURE_VERSION:
            raise UnsupportedContractVersion(f"unsupported fixture_version: {version!r}")
        raw_rows = data["rows"]
        if not isinstance(raw_rows, list):
            raise InvalidContractValue("rows must be an array")
        rows = tuple(
            UnifiedDbExportRowV1.from_mapping(item)
            for item in raw_rows
            if isinstance(item, Mapping)
        )
        if len(rows) != len(raw_rows):
            raise InvalidContractValue("every fixture row must be an object")
        cursors = SnapshotCursorMapV1.from_mapping(
            data["cursors"] if isinstance(data["cursors"], Mapping) else {}
        )
        parsed = cls(
            version,
            parse_string(data["fixture_id"], "fixture_id"),
            parse_digest(data["db_commitment"], "db_commitment"),
            parse_digest(data["catalog_commitment"], "catalog_commitment"),
            parse_digest(data["source_commitment"], "source_commitment"),
            parse_digest(data["data_root_commitment"], "data_root_commitment"),
            cursors,
            rows,
            parse_digest(data["row_set_digest"], "row_set_digest"),
            parse_digest(data["fixture_digest"], "fixture_digest"),
        )
        if parsed.row_set_digest != row_set_digest(rows):
            raise InvalidContractValue("row_set_digest does not bind fixture rows")
        if parsed.fixture_digest != parsed.computed_digest():
            raise InvalidContractValue("fixture_digest does not bind fixture fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["fixture_digest"]
        return canonical_ledger_digest("unified-db-export-fixture-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "fixture_version": self.fixture_version,
            "fixture_id": self.fixture_id,
            "db_commitment": self.db_commitment,
            "catalog_commitment": self.catalog_commitment,
            "source_commitment": self.source_commitment,
            "data_root_commitment": self.data_root_commitment,
            "cursors": self.cursors.to_mapping(),
            "rows": [row.to_mapping() for row in self.rows],
            "row_set_digest": self.row_set_digest,
            "fixture_digest": self.fixture_digest,
        }
