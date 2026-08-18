"""Versioned two-table schema for the private export nonce store."""
from __future__ import annotations

import sqlite3
from enum import StrEnum, unique
from typing import Final

from wiki_spike.infrastructure.export_authorization_nonce_decode import (
    query_ints,
    query_text_triples,
    query_texts,
    run_sql,
)
from wiki_spike.memory_core.unified_db_export_authorization import parse_utc
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

STORE_KIND: Final = "export-authorization-nonce-store-v1"
SCHEMA_VERSION: Final = "1"
FLOOR_ORIGIN: Final = "0001-01-01T00:00:00Z"
METADATA_TABLE: Final = "export_nonce_store_metadata"
CONSUMPTION_TABLE: Final = "export_nonce_consumption"
CONSUMED: Final = "CONSUMED"
_CAP: Final = "_ws_nonce_cap"
_ICAP: Final = "_ws_nonce_icap"
CREATE_METADATA: Final = (
    "CREATE TABLE export_nonce_store_metadata (store_kind TEXT NOT NULL, "
    + "schema_version TEXT NOT NULL, store_state TEXT NOT NULL, "
    + "authorization_floor_at TEXT NOT NULL, PRIMARY KEY (store_kind)) WITHOUT ROWID"
)
CREATE_CONSUMPTION: Final = (
    "CREATE TABLE export_nonce_consumption (nonce_digest TEXT NOT NULL, "
    + "authorization_id TEXT NOT NULL, authorization_digest TEXT NOT NULL, "
    + "authorization_issued_at TEXT NOT NULL, consumption_state TEXT NOT NULL, "
    + "PRIMARY KEY (nonce_digest)) WITHOUT ROWID"
)
TRIGGER_CONS_UPDATE: Final = (
    "CREATE TRIGGER export_nonce_consumption_block_update BEFORE UPDATE ON "
    + "export_nonce_consumption BEGIN SELECT RAISE(ABORT, "
    + "'export nonce consumption is append-only'); END"
)
TRIGGER_CONS_DELETE: Final = (
    "CREATE TRIGGER export_nonce_consumption_block_delete BEFORE DELETE ON "
    + "export_nonce_consumption BEGIN SELECT RAISE(ABORT, "
    + "'export nonce consumption is append-only'); END"
)
TRIGGER_META_DELETE: Final = (
    "CREATE TRIGGER export_nonce_store_metadata_block_delete BEFORE DELETE ON "
    + "export_nonce_store_metadata BEGIN SELECT RAISE(ABORT, "
    + "'export nonce metadata cannot be deleted'); END"
)
_MASTER: Final = (
    ("table", CONSUMPTION_TABLE, CREATE_CONSUMPTION),
    ("table", METADATA_TABLE, CREATE_METADATA),
    ("trigger", "export_nonce_consumption_block_delete", TRIGGER_CONS_DELETE),
    ("trigger", "export_nonce_consumption_block_update", TRIGGER_CONS_UPDATE),
    ("trigger", "export_nonce_store_metadata_block_delete", TRIGGER_META_DELETE),
)


@unique
class NonceStoreState(StrEnum):
    ACTIVE = "ACTIVE"
    RESTORE_QUARANTINED = "RESTORE_QUARANTINED"


def apply_connection_pragmas(connection: sqlite3.Connection) -> None:
    run_sql(connection, "PRAGMA foreign_keys=ON")
    run_sql(connection, "PRAGMA busy_timeout=5000")
    run_sql(connection, "PRAGMA trusted_schema=OFF")


def apply_created_pragmas(connection: sqlite3.Connection) -> None:
    run_sql(connection, "PRAGMA journal_mode=WAL")
    run_sql(connection, "PRAGMA synchronous=FULL")
    apply_connection_pragmas(connection)
    require_pragmas(connection)


def require_pragmas(connection: sqlite3.Connection) -> None:
    if query_texts(
        connection,
        f"SELECT {_CAP}(journal_mode) FROM pragma_journal_mode",
        all_rows=False,
    ) != ("wal",):
        raise UnifiedDbExportError("authorization nonce store is corrupt")
    if query_ints(
        connection,
        f"SELECT {_ICAP}(synchronous) FROM pragma_synchronous",
        all_rows=False,
    ) != (2,):
        raise UnifiedDbExportError("authorization nonce store is corrupt")
    if query_ints(
        connection,
        f"SELECT {_ICAP}(foreign_keys) FROM pragma_foreign_keys",
        all_rows=False,
    ) != (1,):
        raise UnifiedDbExportError("authorization nonce store is corrupt")
    if query_ints(
        connection,
        f"SELECT {_ICAP}(timeout) FROM pragma_busy_timeout",
        all_rows=False,
    ) != (5000,):
        raise UnifiedDbExportError("authorization nonce store is corrupt")
    if query_ints(
        connection,
        f"SELECT {_ICAP}(trusted_schema) FROM pragma_trusted_schema",
        all_rows=False,
    ) != (0,):
        raise UnifiedDbExportError("authorization nonce store is corrupt")


def quick_check(connection: sqlite3.Connection) -> None:
    if query_texts(
        connection,
        f"SELECT {_CAP}(quick_check) FROM pragma_quick_check",
        all_rows=False,
    ) != ("ok",):
        raise UnifiedDbExportError("authorization nonce store is corrupt")


def apply_v1(connection: sqlite3.Connection) -> None:
    run_sql(connection, CREATE_METADATA)
    run_sql(connection, CREATE_CONSUMPTION)
    run_sql(connection, TRIGGER_CONS_UPDATE)
    run_sql(connection, TRIGGER_CONS_DELETE)
    run_sql(connection, TRIGGER_META_DELETE)
    run_sql(
        connection,
        (
            "INSERT INTO export_nonce_store_metadata ("
            + "store_kind, schema_version, store_state, authorization_floor_at) "
            + "VALUES (?, ?, ?, ?)"
        ),
        (STORE_KIND, SCHEMA_VERSION, NonceStoreState.ACTIVE.value, FLOOR_ORIGIN),
    )


def _require_pk(connection: sqlite3.Connection, table: str, column: str) -> None:
    origins = query_texts(
        connection, f"SELECT {_CAP}(origin) FROM pragma_index_list('{table}')"
    )
    names = query_texts(
        connection, f"SELECT {_CAP}(name) FROM pragma_index_list('{table}')"
    )
    if origins != ("pk",) or len(names) != 1:
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    columns = query_texts(
        connection, f"SELECT {_CAP}(name) FROM pragma_index_info('{names[0]}')"
    )
    if columns != (column,):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")


def validate_schema(connection: sqlite3.Connection) -> None:
    master = query_text_triples(
        connection,
        "SELECT _ws_nonce_tcap(type, name, sql) FROM sqlite_master",
    )
    if frozenset(master) != frozenset(_MASTER):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    if query_texts(
        connection, f"SELECT {_CAP}(name) FROM pragma_table_info('{METADATA_TABLE}')"
    ) != ("store_kind", "schema_version", "store_state", "authorization_floor_at"):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    if query_texts(
        connection, f"SELECT {_CAP}(type) FROM pragma_table_info('{METADATA_TABLE}')"
    ) != ("TEXT", "TEXT", "TEXT", "TEXT"):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    if query_ints(
        connection,
        f"SELECT {_ICAP}(\"notnull\") FROM pragma_table_info('{METADATA_TABLE}')",
    ) != (1, 1, 1, 1):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    if query_ints(
        connection, f"SELECT {_ICAP}(pk) FROM pragma_table_info('{METADATA_TABLE}')"
    ) != (1, 0, 0, 0):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    if query_texts(
        connection, f"SELECT {_CAP}(name) FROM pragma_table_info('{CONSUMPTION_TABLE}')"
    ) != (
        "nonce_digest",
        "authorization_id",
        "authorization_digest",
        "authorization_issued_at",
        "consumption_state",
    ):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    if query_texts(
        connection, f"SELECT {_CAP}(type) FROM pragma_table_info('{CONSUMPTION_TABLE}')"
    ) != ("TEXT", "TEXT", "TEXT", "TEXT", "TEXT"):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    if query_ints(
        connection,
        f"SELECT {_ICAP}(\"notnull\") FROM pragma_table_info('{CONSUMPTION_TABLE}')",
    ) != (1, 1, 1, 1, 1):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    if query_ints(
        connection, f"SELECT {_ICAP}(pk) FROM pragma_table_info('{CONSUMPTION_TABLE}')"
    ) != (1, 0, 0, 0, 0):
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    _require_pk(connection, METADATA_TABLE, "store_kind")
    _require_pk(connection, CONSUMPTION_TABLE, "nonce_digest")


def read_metadata(connection: sqlite3.Connection) -> tuple[NonceStoreState, str]:
    cells = query_texts(
        connection,
        (
            f"SELECT {_CAP}(store_kind), {_CAP}(schema_version), "
            + f"{_CAP}(store_state), {_CAP}(authorization_floor_at) "
            + "FROM export_nonce_store_metadata"
        ),
        all_rows=False,
    )
    if len(cells) != 4:
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    kind, version, state, floor = cells
    if kind != STORE_KIND or version != SCHEMA_VERSION:
        raise UnifiedDbExportError("authorization nonce store schema is unknown")
    parsed_floor = parse_utc(floor, "authorization_floor_at").strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        parsed_state = NonceStoreState(state)
    except ValueError as exc:
        raise UnifiedDbExportError("authorization nonce store schema is unknown") from exc
    return parsed_state, parsed_floor
