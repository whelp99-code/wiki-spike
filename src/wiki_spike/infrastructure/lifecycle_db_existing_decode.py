"""Strict SQLite scalar decoding for existing lifecycle admission."""
from __future__ import annotations

import sqlite3
from functools import lru_cache

from wiki_spike.infrastructure.lifecycle_db import SCHEMA, LifecycleDbError

type SqliteScalar = str | bytes | int | float | None
type SchemaColumn = tuple[str, int, str, str, int, int]


def _refuse(message: str) -> LifecycleDbError:
    return LifecycleDbError(f"existing lifecycle database {message}")


def _text(value: SqliteScalar) -> str:
    if isinstance(value, str):
        return value
    raise _refuse("schema contains a non-text value")


def _integer(value: SqliteScalar) -> int:
    if type(value) is int:
        return value
    raise _refuse("schema contains a non-integer value")


class _SchemaSink:
    rows: list[SchemaColumn]

    def __init__(self) -> None:
        self.rows = []

    def capture(
        self,
        table: SqliteScalar,
        cid: SqliteScalar,
        name: SqliteScalar,
        declaration: SqliteScalar,
        notnull: SqliteScalar,
        primary_key: SqliteScalar,
    ) -> str:
        row = (
            _text(table),
            _integer(cid),
            _text(name),
            _text(declaration),
            _integer(notnull),
            _integer(primary_key),
        )
        self.rows.append(row)
        return row[0]


def schema_shape(connection: sqlite3.Connection) -> tuple[SchemaColumn, ...]:
    sink = _SchemaSink()
    _ = connection.create_function("_ws_schema_cap", 6, sink.capture)
    sql = (
        'SELECT _ws_schema_cap(m.name,p.cid,p.name,p.type,p."notnull",p.pk) '
        "FROM sqlite_master AS m JOIN pragma_table_info(m.name) AS p "
        "WHERE m.type='table' AND m.name NOT LIKE 'sqlite_%' "
        "ORDER BY m.name,p.cid"
    )
    _ = connection.execute(sql).fetchall()
    return tuple(sink.rows)


@lru_cache(maxsize=1)
def expected_schema_shape() -> tuple[SchemaColumn, ...]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        _ = connection.executescript(SCHEMA)
        _ = connection.execute(
            "ALTER TABLE ledger_provenance ADD COLUMN provenance_payload_hex TEXT"
        )
        return schema_shape(connection)
    finally:
        connection.close()


class _TextRowSink:
    rows: list[tuple[str, str, str]]

    def __init__(self) -> None:
        self.rows = []

    def capture(
        self, first: SqliteScalar, second: SqliteScalar, third: SqliteScalar
    ) -> str:
        row = (_text(first), _text(second), _text(third))
        self.rows.append(row)
        return row[0]


def query_three(
    connection: sqlite3.Connection,
    function_name: str,
    select_sql: str,
    workspace_ref: str,
) -> tuple[tuple[str, str, str], ...]:
    sink = _TextRowSink()
    _ = connection.create_function(function_name, 3, sink.capture)
    _ = connection.execute(select_sql, (workspace_ref,)).fetchall()
    return tuple(sink.rows)
