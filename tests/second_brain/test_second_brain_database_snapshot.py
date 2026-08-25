"""Allowlist, schema, version, fingerprint, privacy, and source-write contracts."""

from __future__ import annotations

import json
import socket
import sqlite3
import stat
import urllib.request
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import assert_never

from wiki_spike.connectors.database_snapshot import (
    SNAPSHOT_VERSION,
    DatabaseSnapshotAcceptedScan,
    DatabaseSnapshotAdapter,
    DatabaseSnapshotQuarantineReason,
    DatabaseSnapshotReadResult,
    DatabaseSnapshotRowV1,
    DatabaseSnapshotScopeDisabled,
    DatabaseSnapshotStoreQuarantined,
    Fingerprint,
    NativeId,
    TableName,
)

FORBIDDEN = (
    "FORBIDDEN_CREDENTIAL",
    "FORBIDDEN_API_KEY",
    "FORBIDDEN_PASSWORD",
    "access_token",
    "api_key",
)
ALLOWLIST: dict[str, tuple[str, ...]] = {
    "notes": ("id", "title", "body"),
    "tags": ("id", "note_id", "name"),
}
type _Json = str | int | float | bool | None | list[_Json] | dict[str, _Json]


def _read(store: Path, *, scope_enabled: bool = True):
    return DatabaseSnapshotAdapter().read(store, scope_enabled=scope_enabled)


def _ok(result: DatabaseSnapshotReadResult) -> DatabaseSnapshotAcceptedScan:
    match result:
        case DatabaseSnapshotAcceptedScan():
            return result
        case DatabaseSnapshotStoreQuarantined() | DatabaseSnapshotScopeDisabled() as failure:
            raise AssertionError(failure)
        case unreachable:
            assert_never(unreachable)


def _quarantine(result: DatabaseSnapshotReadResult) -> DatabaseSnapshotQuarantineReason:
    match result:
        case DatabaseSnapshotStoreQuarantined(reason=reason):
            return reason
        case DatabaseSnapshotAcceptedScan() | DatabaseSnapshotScopeDisabled():
            raise AssertionError("snapshot must quarantine")
        case unreachable:
            assert_never(unreachable)


def _projection(items: tuple[DatabaseSnapshotRowV1, ...]) -> list[tuple[str, str, dict[str, str]]]:
    return [(item.table, item.native_id, dict(item.fields)) for item in items]


def _fingerprint(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write_snapshot(
    root: Path,
    *,
    version: str = SNAPSHOT_VERSION,
    allowlist: Mapping[str, Sequence[str]] = ALLOWLIST,
    rows: Mapping[str, Sequence[Mapping[str, str]]] | None = None,
    extra_tables: Mapping[str, Sequence[Mapping[str, str]]] | None = None,
    immutable: bool = True,
    database: str = "snapshot.sqlite",
    fingerprint: str | None = None,
    source_profile: str = "Database snapshot",
) -> Path:
    root.mkdir(parents=True)
    database_path = root / database
    connection = sqlite3.connect(database_path)
    try:
        _create(connection, rows or _golden_rows(), extra_tables or {})
        connection.commit()
    finally:
        connection.close()
    manifest = {
        "allowlist": {table: list(columns) for table, columns in allowlist.items()},
        "database": database,
        "fingerprint": fingerprint or _fingerprint(database_path),
        "immutable": immutable,
        "snapshot_version": version,
        "source_profile": source_profile,
    }
    (root / "snapshot.json").write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    return root


def _create(
    connection: sqlite3.Connection,
    rows: Mapping[str, Sequence[Mapping[str, str]]],
    extra_tables: Mapping[str, Sequence[Mapping[str, str]]],
) -> None:
    for table, table_rows in {**dict(rows), **dict(extra_tables)}.items():
        first = table_rows[0]
        connection.execute(f"CREATE TABLE {table} ({', '.join(f'{column} TEXT' for column in first)})")
        for row in table_rows:
            columns = tuple(row)
            connection.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                tuple(row[column] for column in columns),
            )


def _golden_rows() -> dict[str, tuple[dict[str, str], ...]]:
    return {
        "notes": (
            {"id": "note-1", "title": "VISIBLE_TITLE", "body": "VISIBLE_BODY", "password": "FORBIDDEN_PASSWORD"},
        ),
        "tags": ({"id": "tag-1", "note_id": "note-1", "name": "VISIBLE_TAG"},),
    }


def _secrets() -> dict[str, tuple[dict[str, str], ...]]:
    return {
        "credentials": (
            {"id": "cred-1", "access_token": "FORBIDDEN_CREDENTIAL", "api_key": "FORBIDDEN_API_KEY"},
        ),
    }


def test_reads_only_allowlisted_tables_and_columns(tmp_path: Path) -> None:
    # Given: an owner snapshot whose allowlist excludes extra columns and a secrets table.
    store = _write_snapshot(tmp_path / "allowlist", extra_tables=_secrets())

    # When: the adapter reads the immutable snapshot.
    scan = _ok(_read(store))

    # Then: only allowlisted tables and columns are imported.
    assert scan.snapshot_version == SNAPSHOT_VERSION
    assert scan.source_profile == "Database snapshot"
    assert scan.fingerprint == Fingerprint(_fingerprint(store / "snapshot.sqlite"))
    assert _projection(scan.items) == [
        (TableName("notes"), NativeId("note-1"), {"id": "note-1", "title": "VISIBLE_TITLE", "body": "VISIBLE_BODY"}),
        (TableName("tags"), NativeId("tag-1"), {"id": "tag-1", "note_id": "note-1", "name": "VISIBLE_TAG"}),
    ]
    assert scan.proof.tables_read == (TableName("notes"), TableName("tags"))


def test_quarantines_when_schema_is_missing_allowlisted_column(tmp_path: Path) -> None:
    # Given: an allowlist that names a column the snapshot table does not have.
    store = _write_snapshot(
        tmp_path / "schema",
        allowlist={"notes": ("id", "title", "missing_body")},
        rows={"notes": ({"id": "note-1", "title": "VISIBLE_TITLE"},)},
    )

    # When: the adapter checks the declared schema.
    result = _read(store)

    # Then: the snapshot is quarantined before any row is emitted.
    assert _quarantine(result) is DatabaseSnapshotQuarantineReason.UNSUPPORTED_SCHEMA


def test_quarantines_unsupported_snapshot_version(tmp_path: Path) -> None:
    # Given: a snapshot whose version is not the supported decoder.
    store = _write_snapshot(tmp_path / "version", version="database-snapshot-v0")

    # When: the adapter reads the unsupported snapshot.
    result = _read(store)

    # Then: the whole store is quarantined before any visible item is emitted.
    assert _quarantine(result) is DatabaseSnapshotQuarantineReason.UNSUPPORTED_VERSION


def test_quarantines_when_snapshot_fingerprint_does_not_match(tmp_path: Path) -> None:
    # Given: a manifest fingerprint that does not match the snapshot bytes.
    store = _write_snapshot(tmp_path / "fingerprint", fingerprint="0" * 64)

    # When: the adapter verifies the snapshot fingerprint.
    result = _read(store)

    # Then: the mutated or misbound snapshot is quarantined.
    assert _quarantine(result) is DatabaseSnapshotQuarantineReason.SOURCE_MUTATED


def test_quarantines_when_snapshot_bytes_are_mutated(tmp_path: Path) -> None:
    # Given: a valid snapshot whose SQLite bytes are later rewritten in place.
    store = _write_snapshot(tmp_path / "mutated")
    database = store / "snapshot.sqlite"
    payload = bytearray(database.read_bytes())
    payload[-1] = payload[-1] ^ 0xFF
    database.write_bytes(bytes(payload))

    # When: the adapter reads the rewritten snapshot.
    result = _read(store)

    # Then: mutation is explicit and no row is claimed.
    assert _quarantine(result) is DatabaseSnapshotQuarantineReason.SOURCE_MUTATED


def test_does_not_persist_credential_tables_or_secret_columns(tmp_path: Path) -> None:
    # Given: a snapshot that also contains a credential table and a secret column.
    store = _write_snapshot(tmp_path / "privacy", extra_tables=_secrets())

    # When: the adapter decodes the approved snapshot.
    scan = _ok(_read(store))

    # Then: no forbidden marker persists in imported fields.
    dumped = json.dumps(
        [{"fields": dict(item.fields), "native_id": item.native_id, "table": item.table} for item in scan.items],
        separators=(",", ":"),
        sort_keys=True,
    )
    assert all(marker not in dumped for marker in FORBIDDEN)
    assert all(marker not in value for item in scan.items for value in dict(item.fields).values() for marker in FORBIDDEN)


def test_denied_table_causes_zero_row_reads(tmp_path: Path) -> None:
    # Given: a snapshot whose owner allowlist names a credential table beside notes.
    store = _write_snapshot(
        tmp_path / "denied",
        allowlist={"notes": ("id", "title", "body"), "credentials": ("id", "access_token", "api_key")},
        extra_tables=_secrets(),
    )

    # When: the adapter reads the snapshot.
    scan = _ok(_read(store))

    # Then: the denied table is never selected and contributes zero row reads.
    assert TableName("credentials") not in scan.proof.tables_read
    assert dict(scan.proof.row_reads).get(TableName("credentials"), 0) == 0
    assert all("credentials" not in statement.casefold() for statement in scan.proof.statements)
    assert all(item.table != TableName("credentials") for item in scan.items)
    assert _projection(scan.items) == [
        (TableName("notes"), NativeId("note-1"), {"id": "note-1", "title": "VISIBLE_TITLE", "body": "VISIBLE_BODY"}),
    ]


def test_leaves_snapshot_bytes_unchanged(tmp_path: Path) -> None:
    # Given: a materialized immutable snapshot database.
    store = _write_snapshot(tmp_path / "conserved")
    database = store / "snapshot.sqlite"
    before_stat, before_bytes = database.stat(), database.read_bytes()
    manifest_before = (store / "snapshot.json").read_bytes()

    # When: the adapter reads the snapshot.
    result = _read(store)

    # Then: source bytes, inode, and mode are unchanged.
    after_stat = database.stat()
    assert isinstance(result, DatabaseSnapshotAcceptedScan)
    assert database.read_bytes() == before_bytes
    assert (store / "snapshot.json").read_bytes() == manifest_before
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_ino == before_stat.st_ino
    assert stat.S_IMODE(after_stat.st_mode) == stat.S_IMODE(before_stat.st_mode)


def test_refuses_live_database_paths_and_dsns(tmp_path: Path) -> None:
    # Given: live database files, WAL sidecars, and a connection URI rather than a snapshot.
    live = tmp_path / "live-app"
    live.mkdir()
    (live / "app.db-wal").write_bytes(b"wal")
    (live / "app.db-shm").write_bytes(b"shm")
    sqlite3.connect(live / "app.db").close()
    bare = tmp_path / "notes.sqlite"
    bare.write_bytes(b"SQLite format 3\x00")

    # When: the adapter is pointed at those live stores.
    results = (
        _read(live),
        _read(bare),
        _read(Path("postgresql://localhost/app")),
        _read(Path("mysql://localhost/app")),
    )

    # Then: each live path is refused before any row is imported.
    for result in results:
        assert _quarantine(result) is DatabaseSnapshotQuarantineReason.LIVE_STORE


def test_rejects_arbitrary_sql_identifiers(tmp_path: Path) -> None:
    # Given: a snapshot whose allowlist smuggles SQL instead of a table name.
    store = _write_snapshot(
        tmp_path / "sql",
        allowlist={"notes; DROP TABLE notes": ("id", "title", "body")},
    )
    before = (store / "snapshot.sqlite").read_bytes()

    # When: the adapter parses the allowlist.
    result = _read(store)

    # Then: arbitrary SQL is refused and the snapshot bytes are untouched.
    assert _quarantine(result) is DatabaseSnapshotQuarantineReason.INVALID_FORMAT
    assert (store / "snapshot.sqlite").read_bytes() == before


def test_fails_before_open_when_scope_disabled(tmp_path: Path) -> None:
    # Given: a missing snapshot and a disabled Database snapshot scope.
    missing = tmp_path / "absent-snapshot"

    # When: the adapter is invoked with the scope disabled.
    result = _read(missing, scope_enabled=False)

    # Then: it fails before the path is opened.
    match result:
        case DatabaseSnapshotScopeDisabled(source_profile=profile):
            assert profile == "Database snapshot"
            assert missing.exists() is False
        case DatabaseSnapshotAcceptedScan() | DatabaseSnapshotStoreQuarantined():
            raise AssertionError("disabled scope must fail before opening the snapshot")
        case unreachable:
            assert_never(unreachable)


def test_does_not_open_network_when_reading_local_snapshot(tmp_path: Path, monkeypatch) -> None:
    # Given: a local immutable snapshot and blocked network primitives.
    store = _write_snapshot(tmp_path / "local")

    def forbidden(*_args: str, **_kwargs: str) -> None:
        raise AssertionError("database snapshot reader attempted live I/O")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    # When: the adapter reads the local snapshot.
    result = _read(store)

    # Then: the read completes from local bytes only.
    assert isinstance(result, DatabaseSnapshotAcceptedScan)
