"""Parse SQLite scalars at the nonce-store boundary without Any fetches."""
from __future__ import annotations

import sqlite3

from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

type SqliteScalar = str | bytes | int | float | None
_CAP = "_ws_nonce_cap"
_ICAP = "_ws_nonce_icap"


def run_sql(
    connection: sqlite3.Connection, sql: str, params: tuple[str, ...] = ()
) -> None:
    _ = connection.execute(sql, params)


def sqlite_text(value: SqliteScalar) -> str:
    if isinstance(value, str):
        return value
    raise UnifiedDbExportError("authorization nonce store is corrupt")


def sqlite_int(value: SqliteScalar) -> int:
    if type(value) is int:
        return value
    raise UnifiedDbExportError("authorization nonce store is corrupt")


class _TextSink:
    """Accumulator written by a SQLite function. Mutation is the purpose."""

    cells: list[str]

    def __init__(self) -> None:
        self.cells = []

    def capture(self, value: SqliteScalar) -> str:
        text = sqlite_text(value)
        self.cells.append(text)
        return text


class _IntSink:
    """Integer accumulator written by a SQLite function. Mutation is the purpose."""

    cells: list[int]

    def __init__(self) -> None:
        self.cells = []

    def capture(self, value: SqliteScalar) -> int:
        number = sqlite_int(value)
        self.cells.append(number)
        return number


def _drive_select(
    connection: sqlite3.Connection, select_sql: str, *, all_rows: bool
) -> None:
    if not select_sql.startswith("SELECT "):
        raise UnifiedDbExportError("authorization nonce store is corrupt")
    if all_rows:
        run_sql(connection, "DROP TABLE IF EXISTS temp._ws_nonce_sink")
        run_sql(connection, "CREATE TEMP TABLE _ws_nonce_sink AS " + select_sql)
        return
    run_sql(connection, select_sql)


def query_texts(
    connection: sqlite3.Connection, select_sql: str, *, all_rows: bool = True
) -> tuple[str, ...]:
    sink = _TextSink()
    connection.create_function(_CAP, 1, sink.capture)
    _drive_select(connection, select_sql, all_rows=all_rows)
    return tuple(sink.cells)


def query_ints(
    connection: sqlite3.Connection, select_sql: str, *, all_rows: bool = True
) -> tuple[int, ...]:
    sink = _IntSink()
    connection.create_function(_ICAP, 1, sink.capture)
    _drive_select(connection, select_sql, all_rows=all_rows)
    return tuple(sink.cells)


class _TripleSink:
    """Triple accumulator written by a SQLite function. Mutation is the purpose."""

    rows: list[tuple[str, str, str]]

    def __init__(self) -> None:
        self.rows = []

    def capture(self, first: SqliteScalar, second: SqliteScalar, third: SqliteScalar) -> str:
        row = (sqlite_text(first), sqlite_text(second), sqlite_text(third))
        self.rows.append(row)
        return row[0]


def query_text_triples(
    connection: sqlite3.Connection, select_sql: str, *, all_rows: bool = True
) -> tuple[tuple[str, str, str], ...]:
    sink = _TripleSink()
    connection.create_function("_ws_nonce_tcap", 3, sink.capture)
    _drive_select(connection, select_sql, all_rows=all_rows)
    return tuple(sink.rows)
