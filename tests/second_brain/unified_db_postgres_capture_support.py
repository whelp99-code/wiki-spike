"""Builders and fake ports for body-free PostgreSQL identity/catalog capture."""
from __future__ import annotations

from pathlib import Path

from tests.second_brain.unified_db_live_export_support import (
    CAPTURED_AT,
    DATABASE_OID,
    IDENTITY_DOMAIN,
    NOW,
    SCRIPT,
    SERVER_VERSION_NUM,
    STALE_CAPTURED_AT,
    SYSTEM_IDENTIFIER,
    identity_body,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.unified_db_postgres_capture_catalog import (
    CatalogRowV1,
    PostgresCatalogSnapshotV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_plan import (
    PostgresIdentityInputsV1,
    produce_postgres_identity_receipt,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)

QUERY_MANIFEST_VERSION = "second-brain-unified-db-postgres-capture-query-manifest-v1"
QUERY_MANIFEST_DOMAIN = "unified-db-postgres-capture-query-manifest-v1"
CATALOG_VERSION = "second-brain-unified-db-postgres-catalog-v1"
CATALOG_DOMAIN = "unified-db-postgres-catalog-v1"
CAPTURE_PLAN_VERSION = "second-brain-unified-db-postgres-capture-plan-v1"
CAPTURE_PLAN_DOMAIN = "unified-db-postgres-capture-plan-v1"
FUTURE_CAPTURED_AT = "2026-08-18T12:11:00Z"
QUERY_MANIFEST_SCHEMA = Path(
    "schemas/second-brain/unified-db-postgres-capture-query-manifest-v1.schema.json"
)
CATALOG_SCHEMA = Path("schemas/second-brain/unified-db-postgres-catalog-v1.schema.json")
CAPTURE_PLAN_SCHEMA = Path(
    "schemas/second-brain/unified-db-postgres-capture-plan-v1.schema.json"
)
CONFORMANCE_SCHEMA = Path(
    "schemas/second-brain/unified-db-postgres-capture-conformance-v1.schema.json"
)
CONFORMANCE_EVIDENCE = Path(
    "artifacts/product-release/second-brain-v1/evidence/"
    + "unified-db-postgres-capture-conformance-v1.json"
)
SQL_DENY_FRAGMENTS = (";", "--", "/*", "*/", "$", "%", "{", "}", "?", "`", '"', "\\", "#")
APPLICATION_TABLE_SQL = (
    "SELECT id FROM public.notes",
    "SELECT id FROM notes",
    "SELECT * FROM pg_catalog.pg_class INNER JOIN public.notes ON true",
    "SELECT * FROM information_schema.columns",
    "SELECT * FROM pg_catalog.pg_class UNION SELECT * FROM public.notes",
)


def _digest(domain: str, body: dict[str, JsonValue], field: str) -> dict[str, JsonValue]:
    unsigned = {key: value for key, value in body.items() if key != field}
    return unsigned | {field: canonical_ledger_digest(domain, unsigned)}


def catalog_row_dicts() -> list[dict[str, JsonValue]]:
    return [
        {"kind": "schema", "schema_name": "public", "schema_oid": "2200"},
        {
            "kind": "table",
            "schema_name": "public",
            "table_name": "notes",
            "table_oid": "16385",
            "relkind": "r",
        },
        {
            "kind": "column",
            "schema_name": "public",
            "table_name": "notes",
            "column_name": "id",
            "ordinal": "1",
            "type_name": "int8",
            "not_null": "true",
        },
        {
            "kind": "constraint",
            "schema_name": "public",
            "table_name": "notes",
            "constraint_name": "notes_pkey",
            "constraint_type": "p",
        },
        {
            "kind": "index",
            "schema_name": "public",
            "table_name": "notes",
            "index_name": "notes_pkey",
            "unique": "true",
        },
    ]


def catalog_byte_count(rows: list[dict[str, JsonValue]]) -> str:
    return str(len(canonical_bytes({"rows": rows})))


def catalog_body(
    rows: list[dict[str, JsonValue]] | None = None,
    **overrides: JsonValue,
) -> dict[str, JsonValue]:
    typed_rows = catalog_row_dicts() if rows is None else rows
    payload_rows = list[JsonValue](typed_rows)
    body: dict[str, JsonValue] = {
        "catalog_version": CATALOG_VERSION,
        "rows": payload_rows,
        "row_count": str(len(typed_rows)),
        "byte_count": catalog_byte_count(typed_rows),
    }
    body.update(overrides)
    if "catalog_digest" not in overrides:
        return _digest(CATALOG_DOMAIN, body, "catalog_digest")
    return body


def identity_inputs_body(**overrides: JsonValue) -> dict[str, JsonValue]:
    catalog = catalog_body()
    body: dict[str, JsonValue] = {
        "system_identifier": SYSTEM_IDENTIFIER,
        "database_oid": DATABASE_OID,
        "server_version_num": SERVER_VERSION_NUM,
        "catalog_digest": catalog["catalog_digest"],
        "captured_at": CAPTURED_AT,
    }
    body.update(overrides)
    return body


def bound_identity_body(**overrides: JsonValue) -> dict[str, JsonValue]:
    catalog = catalog_body()
    return identity_body(catalog_digest=catalog["catalog_digest"], **overrides)


def capture_plan_body(
    manifest_digest: str,
    identity: dict[str, JsonValue],
    catalog: dict[str, JsonValue],
    **overrides: JsonValue,
) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "plan_version": CAPTURE_PLAN_VERSION,
        "source_name": "unified-db",
        "query_manifest_digest": manifest_digest,
        "system_identifier": identity["system_identifier"],
        "database_oid": identity["database_oid"],
        "server_version_num": identity["server_version_num"],
        "catalog_digest": catalog["catalog_digest"],
        "captured_at": identity["captured_at"],
    }
    body.update(overrides)
    if "plan_digest" not in overrides:
        return _digest(CAPTURE_PLAN_DOMAIN, body, "plan_digest")
    return body


class FakePostgresIdentityCapture:
    def capture_identity(
        self, inputs: PostgresIdentityInputsV1
    ) -> PostgresIdentityReceiptV1:
        return produce_postgres_identity_receipt(inputs)


class FakePostgresCatalogCapture:
    def capture_catalog(
        self, rows: tuple[CatalogRowV1, ...]
    ) -> PostgresCatalogSnapshotV1:
        return PostgresCatalogSnapshotV1.from_rows(rows)


__all__ = (
    "APPLICATION_TABLE_SQL",
    "CAPTURED_AT",
    "CAPTURE_PLAN_DOMAIN",
    "CAPTURE_PLAN_SCHEMA",
    "CAPTURE_PLAN_VERSION",
    "CATALOG_DOMAIN",
    "CATALOG_SCHEMA",
    "CATALOG_VERSION",
    "CONFORMANCE_EVIDENCE",
    "CONFORMANCE_SCHEMA",
    "DATABASE_OID",
    "FUTURE_CAPTURED_AT",
    "IDENTITY_DOMAIN",
    "NOW",
    "QUERY_MANIFEST_DOMAIN",
    "QUERY_MANIFEST_SCHEMA",
    "QUERY_MANIFEST_VERSION",
    "SCRIPT",
    "SERVER_VERSION_NUM",
    "SQL_DENY_FRAGMENTS",
    "STALE_CAPTURED_AT",
    "SYSTEM_IDENTIFIER",
    "FakePostgresCatalogCapture",
    "FakePostgresIdentityCapture",
    "bound_identity_body",
    "capture_plan_body",
    "catalog_body",
    "catalog_byte_count",
    "catalog_row_dicts",
    "identity_inputs_body",
)
