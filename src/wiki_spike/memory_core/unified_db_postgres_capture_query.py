"""Immutable closed query manifest for body-free PostgreSQL catalog capture."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_postgres_capture_sql import inspect_capture_sql

__all__ = (
    "CLOSED_QUERY_SQL",
    "QUERY_KINDS",
    "QUERY_MANIFEST_DOMAIN",
    "QUERY_MANIFEST_VERSION",
    "CaptureQueryV1",
    "PostgresCaptureQueryManifestV1",
    "inspect_capture_sql",
    "require_closed_capture_queries",
)
QUERY_MANIFEST_VERSION: Final = (
    "second-brain-unified-db-postgres-capture-query-manifest-v1"
)
QUERY_MANIFEST_DOMAIN: Final = "unified-db-postgres-capture-query-manifest-v1"
QUERY_KINDS: Final = (
    "system_identifier",
    "database_oid",
    "server_version_num",
    "schemas",
    "tables",
    "columns",
    "constraints",
    "indexes",
)
CLOSED_QUERY_SQL: Final[tuple[tuple[str, str], ...]] = (
    (
        "system_identifier",
        "SELECT system_identifier FROM pg_catalog.pg_control_system()",
    ),
    (
        "database_oid",
        "SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()",
    ),
    ("server_version_num", "SHOW server_version_num"),
    (
        "schemas",
        "SELECT nspname, oid FROM pg_catalog.pg_namespace ORDER BY nspname, oid",
    ),
    (
        "tables",
        (
            "SELECT n.nspname, c.relname, c.oid, c.relkind FROM pg_catalog.pg_class AS c "
            "INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "WHERE c.relkind = 'r' ORDER BY n.nspname, c.relname, c.oid"
        ),
    ),
    (
        "columns",
        (
            "SELECT n.nspname, c.relname, a.attname, a.attnum, t.typname, a.attnotnull "
            "FROM pg_catalog.pg_attribute AS a "
            "INNER JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid "
            "INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "INNER JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid "
            "WHERE c.relkind = 'r' AND a.attnum > 0 AND a.attisdropped = false "
            "ORDER BY n.nspname, c.relname, a.attnum, a.attname"
        ),
    ),
    (
        "constraints",
        (
            "SELECT n.nspname, c.relname, x.conname, x.contype "
            "FROM pg_catalog.pg_constraint AS x "
            "INNER JOIN pg_catalog.pg_class AS c ON c.oid = x.conrelid "
            "INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "ORDER BY n.nspname, c.relname, x.conname"
        ),
    ),
    (
        "indexes",
        (
            "SELECT n.nspname, c.relname, i.relname, x.indisunique "
            "FROM pg_catalog.pg_index AS x "
            "INNER JOIN pg_catalog.pg_class AS c ON c.oid = x.indrelid "
            "INNER JOIN pg_catalog.pg_class AS i ON i.oid = x.indexrelid "
            "INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "ORDER BY n.nspname, c.relname, i.relname"
        ),
    ),
)
_FIELDS: Final = frozenset({"manifest_version", "queries", "manifest_digest"})
_QUERY_FIELDS: Final = frozenset({"query_kind", "sql"})


@dataclass(frozen=True, slots=True)
class CaptureQueryV1:
    query_kind: str
    sql: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> CaptureQueryV1:
        strict_fields(data, _QUERY_FIELDS)
        return cls(parse_string(data["query_kind"], "query_kind"), parse_string(data["sql"], "sql"))

    def to_mapping(self) -> dict[str, JsonValue]:
        return {"query_kind": self.query_kind, "sql": self.sql}


def require_closed_capture_queries(queries: tuple[CaptureQueryV1, ...]) -> None:
    """Refuse any query tuple that is not the closed ordered SQL set."""
    expected = tuple(CaptureQueryV1(kind, sql) for kind, sql in CLOSED_QUERY_SQL)
    if queries != expected:
        raise InvalidContractValue("query is not in the closed manifest")
    for query in queries:
        _ = inspect_capture_sql(query.sql)


@dataclass(frozen=True, slots=True)
class PostgresCaptureQueryManifestV1:
    manifest_version: str
    queries: tuple[CaptureQueryV1, ...]
    manifest_digest: str

    @classmethod
    def closed(cls) -> PostgresCaptureQueryManifestV1:
        queries = tuple(CaptureQueryV1(kind, sql) for kind, sql in CLOSED_QUERY_SQL)
        provisional = cls(QUERY_MANIFEST_VERSION, queries, "0" * 64)
        return cls.from_mapping(
            provisional.to_mapping()
            | {"manifest_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PostgresCaptureQueryManifestV1:
        strict_fields(data, _FIELDS)
        version = parse_string(data["manifest_version"], "manifest_version")
        if version != QUERY_MANIFEST_VERSION:
            raise UnsupportedContractVersion(f"unsupported manifest_version: {version!r}")
        raw = data["queries"]
        if not isinstance(raw, list) or not raw:
            raise InvalidContractValue("queries must be a non-empty array")
        queries = tuple(
            CaptureQueryV1.from_mapping(item) for item in raw if isinstance(item, Mapping)
        )
        if len(queries) != len(raw):
            raise InvalidContractValue("every query must be an object")
        require_closed_capture_queries(queries)
        parsed = cls(
            version,
            queries,
            parse_digest(data["manifest_digest"], "manifest_digest"),
        )
        if parsed.manifest_digest != parsed.computed_digest():
            raise InvalidContractValue("manifest_digest does not bind query manifest")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["manifest_digest"]
        return canonical_ledger_digest(QUERY_MANIFEST_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "manifest_version": self.manifest_version,
            "queries": [query.to_mapping() for query in self.queries],
            "manifest_digest": self.manifest_digest,
        }
