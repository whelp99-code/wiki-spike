"""Closed query-manifest and conservative SQL denylist tests."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.second_brain.unified_db_postgres_capture_support import (
    APPLICATION_TABLE_SQL,
    QUERY_MANIFEST_SCHEMA,
    QUERY_MANIFEST_VERSION,
    SQL_DENY_FRAGMENTS,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_postgres_capture_query import (
    PostgresCaptureQueryManifestV1,
    inspect_capture_sql,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


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


def test_closed_manifest_binds_only_pg_catalog_metadata_surfaces() -> None:
    manifest = PostgresCaptureQueryManifestV1.closed()
    assert manifest.manifest_version == QUERY_MANIFEST_VERSION
    kinds = tuple(query.query_kind for query in manifest.queries)
    assert kinds == (
        "system_identifier",
        "database_oid",
        "server_version_num",
        "schemas",
        "tables",
        "columns",
        "constraints",
        "indexes",
    )
    assert manifest.manifest_digest == manifest.computed_digest()
    for query in manifest.queries:
        for fragment in SQL_DENY_FRAGMENTS:
            assert fragment not in query.sql
        inspection = inspect_capture_sql(query.sql)
        assert inspection.statement_kind in {"SELECT", "SHOW"}
        assert all(ref.startswith("pg_catalog.") for ref in inspection.relation_refs)
        if inspection.statement_kind == "SHOW":
            assert inspection.show_setting == "server_version_num"
            assert inspection.relation_refs == ()


def test_closed_manifest_has_zero_application_row_query_capability() -> None:
    manifest = PostgresCaptureQueryManifestV1.closed()
    joined = " ".join(query.sql.upper() for query in manifest.queries)
    assert " PUBLIC." not in f" {joined} "
    assert " INFORMATION_SCHEMA." not in f" {joined} "
    for query in manifest.queries:
        inspection = inspect_capture_sql(query.sql)
        for ref in inspection.relation_refs:
            assert ref.startswith("pg_catalog.")
            assert not ref.startswith("public.")
            assert "information_schema" not in ref


@pytest.mark.parametrize("sql", APPLICATION_TABLE_SQL)
def test_inspector_rejects_select_from_application_tables(sql: str) -> None:
    with pytest.raises(InvalidContractValue, match="pg_catalog|forbidden"):
        _ = inspect_capture_sql(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT oid FROM pg_catalog.pg_class, public.notes",
        "SELECT oid FROM pg_catalog.pg_class, notes",
        "SELECT oid FROM pg_catalog.pg_class, information_schema.columns",
        "SELECT oid FROM pg_catalog.pg_class, pg_catalog.pg_authid",
        "SELECT oid FROM pg_catalog.pg_class, pg_shadow",
        "SELECT oid FROM pg_catalog.pg_class, pg_stat_activity",
        "SELECT oid FROM pg_catalog.pg_class AS c, public.notes AS n",
        "SELECT oid FROM pg_catalog.pg_class c, notes n",
        "SELECT oid FROM pg_catalog.pg_class AS c, information_schema.columns AS cols",
        "SELECT oid FROM pg_catalog.pg_class c, pg_catalog.pg_authid a",
        "SELECT oid FROM pg_catalog.pg_class AS c, pg_shadow s",
        "SELECT oid FROM pg_catalog.pg_class c, pg_stat_activity a",
    ],
)
def test_inspector_rejects_comma_join_second_relations(sql: str) -> None:
    with pytest.raises(InvalidContractValue, match="comma|join|forbidden|relation"):
        _ = inspect_capture_sql(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT (SELECT oid FROM pg_catalog.pg_database)",
        "SELECT oid FROM (SELECT oid FROM pg_catalog.pg_database)",
        "SELECT oid FROM (SELECT oid FROM pg_catalog.pg_database) AS derived",
    ],
)
def test_inspector_rejects_subquery_or_derived_relation(sql: str) -> None:
    with pytest.raises(InvalidContractValue, match="subquery|derived|forbidden"):
        _ = inspect_capture_sql(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT oid FROM pg_catalog.pg_database; SELECT 1",
        "SELECT oid FROM pg_catalog.pg_class -- comment",
        "SELECT oid FROM pg_catalog.pg_class /* comment */",
        "SELECT oid FROM pg_catalog.pg_class WHERE nspname = $1",
        "SELECT oid FROM pg_catalog.pg_class WHERE nspname = %s",
        "SELECT oid FROM pg_catalog.pg_class WHERE nspname = '{name}'",
        "SELECT oid FROM pg_catalog.pg_class WHERE nspname = ?",
    ],
)
def test_inspector_rejects_semicolon_comment_parameter_or_interpolation(
    sql: str,
) -> None:
    with pytest.raises(InvalidContractValue):
        _ = inspect_capture_sql(sql)


def test_manifest_rejects_unknown_fields_and_unsupported_version() -> None:
    closed = PostgresCaptureQueryManifestV1.closed().to_mapping()
    with pytest.raises(UnknownContractField):
        _ = PostgresCaptureQueryManifestV1.from_mapping(closed | {"extra": "no"})
    with pytest.raises(UnsupportedContractVersion):
        _ = PostgresCaptureQueryManifestV1.from_mapping(
            closed | {"manifest_version": "capture-query-v0"}
        )


def test_manifest_rejects_non_pg_catalog_or_mutated_sql() -> None:
    closed = PostgresCaptureQueryManifestV1.closed().to_mapping()
    queries = list(closed["queries"]) if isinstance(closed["queries"], list) else []
    first = dict(queries[0]) if queries and isinstance(queries[0], dict) else {}
    first["sql"] = "SELECT id FROM public.notes"
    queries[0] = first
    mutated = dict(closed)
    mutated["queries"] = queries
    with pytest.raises(InvalidContractValue, match="closed"):
        _ = PostgresCaptureQueryManifestV1.from_mapping(mutated)


def test_manifest_rejects_raw_numeric_payload_values() -> None:
    encoded = json.dumps(
        PostgresCaptureQueryManifestV1.closed().to_mapping(),
        separators=(",", ":"),
        sort_keys=True,
    )
    numeric = encoded[:-1] + ',"n":8}'
    with pytest.raises(UnifiedDbExportError, match="raw numbers"):
        _ = decode_json_object(numeric)


def test_query_manifest_schema_is_draft_2020_12_and_rejects_extra() -> None:
    instance = PostgresCaptureQueryManifestV1.closed().to_mapping()
    assert "https://json-schema.org/draft/2020-12/schema" in QUERY_MANIFEST_SCHEMA.read_text(
        encoding="utf-8"
    )
    assert _draft_status(QUERY_MANIFEST_SCHEMA, instance) == 0
    assert _draft_status(QUERY_MANIFEST_SCHEMA, instance | {"extra": "no"}) != 0


def test_query_manifest_schema_pins_closed_ordered_sql_and_digest() -> None:
    closed = PostgresCaptureQueryManifestV1.closed()
    text = QUERY_MANIFEST_SCHEMA.read_text(encoding="utf-8")
    assert '"prefixItems"' in text
    assert '"minItems": 8' in text
    assert '"maxItems": 8' in text
    assert '"items": false' in text
    assert f'"const": "{QUERY_MANIFEST_VERSION}"' in text
    assert closed.manifest_digest in text
    for query in closed.queries:
        assert query.query_kind in text
        assert query.sql in text
    assert _draft_status(QUERY_MANIFEST_SCHEMA, closed.to_mapping()) == 0
    mutated = closed.to_mapping()
    rows = list(mutated["queries"]) if isinstance(mutated["queries"], list) else []
    first = dict(rows[0]) if rows and isinstance(rows[0], dict) else {}
    first["sql"] = "SELECT oid FROM pg_catalog.pg_class, public.notes"
    rows[0] = first
    mutated["queries"] = rows
    assert _draft_status(QUERY_MANIFEST_SCHEMA, mutated) != 0
