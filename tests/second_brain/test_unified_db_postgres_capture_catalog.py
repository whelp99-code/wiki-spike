"""Catalog-row typing, sort, bounds, and mutation tests."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.second_brain.unified_db_postgres_capture_support import (
    CATALOG_SCHEMA,
    CATALOG_VERSION,
    catalog_body,
    catalog_row_dicts,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_postgres_capture_catalog import (
    MAX_CATALOG_BYTES,
    MAX_CATALOG_ROWS,
    CatalogColumnRowV1,
    CatalogConstraintRowV1,
    CatalogIndexRowV1,
    CatalogSchemaRowV1,
    CatalogTableRowV1,
    PostgresCatalogSnapshotV1,
    parse_catalog_row,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def _parse(data: Mapping[str, JsonValue]) -> PostgresCatalogSnapshotV1:
    return PostgresCatalogSnapshotV1.from_mapping(data)


def _draft_status(schema_path: Path, instance: Mapping[str, JsonValue]) -> int:
    script = (
        "import json,sys,jsonschema;"
        "schema=json.load(open(sys.argv[1], encoding='utf-8'));"
        "jsonschema.Draft202012Validator.check_schema(schema);"
        "jsonschema.Draft202012Validator(schema).validate(json.loads(sys.argv[2]))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(schema_path), json.dumps(dict(instance))],
        capture_output=True,
        check=False,
        text=True,
    )
    return completed.returncode


def test_catalog_parses_typed_canonical_metadata_rows() -> None:
    parsed = _parse(catalog_body())
    assert parsed.catalog_version == CATALOG_VERSION
    assert parsed.row_count == "5"
    assert parsed.catalog_digest == parsed.computed_digest()
    kinds = tuple(row.kind for row in parsed.rows)
    assert kinds == ("schema", "table", "column", "constraint", "index")
    schema, table, column, constraint, index = parsed.rows
    assert isinstance(schema, CatalogSchemaRowV1)
    assert schema.schema_name == "public"
    assert schema.schema_oid == "2200"
    assert isinstance(table, CatalogTableRowV1)
    assert table.table_name == "notes"
    assert table.relkind == "r"
    assert isinstance(column, CatalogColumnRowV1)
    assert column.column_name == "id"
    assert column.ordinal == "1"
    assert column.type_name == "int8"
    assert column.not_null == "true"
    assert isinstance(constraint, CatalogConstraintRowV1)
    assert constraint.constraint_type == "p"
    assert isinstance(index, CatalogIndexRowV1)
    assert index.unique == "true"


def test_catalog_rejects_unknown_fields_and_unsupported_version() -> None:
    missing = catalog_body()
    del missing["row_count"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = _parse(missing)
    with pytest.raises(UnknownContractField):
        _ = _parse(catalog_body() | {"extra": "no"})
    with pytest.raises(UnsupportedContractVersion):
        _ = _parse(catalog_body(catalog_version="catalog-v0"))


def test_catalog_rejects_unsupported_metadata_kind() -> None:
    rows = catalog_row_dicts()
    rows.append(
        {
            "kind": "view",
            "schema_name": "public",
            "table_name": "notes_v",
            "table_oid": "16386",
            "relkind": "v",
        }
    )
    with pytest.raises(InvalidContractValue, match="kind"):
        _ = _parse(catalog_body(rows=rows, row_count="6"))


def test_catalog_rejects_unordered_rows() -> None:
    rows = list(reversed(catalog_row_dicts()))
    with pytest.raises(InvalidContractValue, match="sorted"):
        _ = _parse(catalog_body(rows=rows))


def test_catalog_rejects_duplicate_rows() -> None:
    rows = catalog_row_dicts()
    rows.insert(1, dict(rows[0]))
    with pytest.raises(InvalidContractValue, match="duplicate"):
        _ = _parse(catalog_body(rows=rows, row_count="6"))


def test_catalog_rejects_row_and_byte_count_bounds() -> None:
    overflow_rows: list[dict[str, JsonValue]] = [
        {
            "kind": "schema",
            "schema_name": f"s{index:04d}",
            "schema_oid": str(2200 + index),
        }
        for index in range(MAX_CATALOG_ROWS + 1)
    ]
    with pytest.raises(InvalidContractValue, match="bound"):
        _ = _parse(catalog_body(rows=overflow_rows, row_count=str(len(overflow_rows))))
    wrong_count = catalog_body(row_count="4")
    with pytest.raises(InvalidContractValue, match="row_count"):
        _ = _parse(wrong_count)
    wrong_bytes = catalog_body(byte_count=str(MAX_CATALOG_BYTES + 1))
    with pytest.raises(InvalidContractValue, match="byte_count"):
        _ = _parse(wrong_bytes)


def test_catalog_rejects_raw_numeric_payload_values() -> None:
    encoded = json.dumps(catalog_body(), separators=(",", ":"), sort_keys=True)
    numeric = encoded.replace('"2200"', "2200")
    with pytest.raises(UnifiedDbExportError, match="raw numbers"):
        _ = decode_json_object(numeric)


def test_catalog_snapshot_rejects_mutation_after_parse() -> None:
    parsed = _parse(catalog_body())
    first = parsed.rows[0]
    with pytest.raises(AttributeError):
        parsed.__setattr__("rows", ())
    with pytest.raises(AttributeError):
        parsed.__setattr__("catalog_digest", "00" * 32)
    assert isinstance(first, CatalogSchemaRowV1)
    with pytest.raises(AttributeError):
        first.__setattr__("schema_name", "other")


def test_catalog_digest_mismatch_is_rejected() -> None:
    with pytest.raises(InvalidContractValue, match="catalog_digest"):
        _ = _parse(catalog_body(catalog_digest="00" * 32))


def test_parse_catalog_row_rejects_unknown_column_fields() -> None:
    with pytest.raises(UnknownContractField):
        _ = parse_catalog_row(
            {
                "kind": "column",
                "schema_name": "public",
                "table_name": "notes",
                "column_name": "id",
                "ordinal": "1",
                "type_name": "int8",
                "not_null": "true",
                "default": "1",
            }
        )


def test_catalog_schema_is_draft_2020_12_and_rejects_extra() -> None:
    instance = catalog_body()
    assert "https://json-schema.org/draft/2020-12/schema" in CATALOG_SCHEMA.read_text(
        encoding="utf-8"
    )
    assert _draft_status(CATALOG_SCHEMA, instance) == 0
    assert _draft_status(CATALOG_SCHEMA, instance | {"extra": "no"}) != 0
    text = CATALOG_SCHEMA.read_text(encoding="utf-8")
    assert f'"maxItems": {MAX_CATALOG_ROWS}' in text
    assert '"uniqueItems": true' in text
