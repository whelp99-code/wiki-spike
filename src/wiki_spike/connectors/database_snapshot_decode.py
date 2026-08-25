"""Parse and read an owner-created immutable SQLite snapshot."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final, assert_never
from urllib.parse import quote

from wiki_spike.connectors.database_snapshot_types import (
    MAX_SNAPSHOT_BYTES,
    SNAPSHOT_VERSION,
    SOURCE_PROFILE,
    DatabaseSnapshotAcceptedScan,
    DatabaseSnapshotQuarantineReason,
    DatabaseSnapshotReadProofV1,
    DatabaseSnapshotReadResult,
    DatabaseSnapshotRowV1,
    DatabaseSnapshotStoreQuarantined,
    Fingerprint,
    JsonValue,
    NativeId,
    TableName,
)

_OPEN_FLAGS: Final = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_IDENT: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_DB_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.(?:sqlite|db)$")
_HEX64: Final = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST: Final = frozenset({"allowlist", "database", "fingerprint", "immutable", "snapshot_version", "source_profile"})
_DENIED_TABLES: Final = frozenset({
    "api_key", "api_keys", "auth", "authorization", "cookie", "cookies", "credential", "credentials",
    "keychain", "password", "passwords", "secret", "secrets", "token", "tokens",
})
_DENIED_COLUMNS: Final = frozenset({
    "access_token", "api_key", "auth_token", "authorization", "cookie", "credential",
    "passwd", "password", "private_key", "pwd", "refresh_token", "secret", "token",
})


@dataclass(frozen=True, slots=True)
class ParsedSnapshotV1:
    database: Path
    fingerprint: str
    allowlist: tuple[tuple[str, tuple[str, ...]], ...]


def fail(reason: DatabaseSnapshotQuarantineReason) -> DatabaseSnapshotStoreQuarantined:
    return DatabaseSnapshotStoreQuarantined(reason)


def parse_manifest(store: Path) -> ParsedSnapshotV1 | DatabaseSnapshotStoreQuarantined:
    path = store / "snapshot.json"
    if path.is_symlink() or not path.is_file():
        return fail(DatabaseSnapshotQuarantineReason.UNREADABLE)
    try:
        loaded: JsonValue = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return fail(DatabaseSnapshotQuarantineReason.UNREADABLE)
    if not isinstance(loaded, dict) or set(loaded) != _MANIFEST:
        return fail(DatabaseSnapshotQuarantineReason.INVALID_FORMAT)
    if loaded["immutable"] is not True or loaded["source_profile"] != SOURCE_PROFILE:
        return fail(DatabaseSnapshotQuarantineReason.INVALID_FORMAT)
    if loaded["snapshot_version"] != SNAPSHOT_VERSION:
        return fail(DatabaseSnapshotQuarantineReason.UNSUPPORTED_VERSION)
    name, digest, allowlist = loaded["database"], loaded["fingerprint"], _allowlist(loaded["allowlist"])
    if not isinstance(name, str) or _DB_NAME.fullmatch(name) is None or not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        return fail(DatabaseSnapshotQuarantineReason.INVALID_FORMAT)
    if allowlist is None:
        return fail(DatabaseSnapshotQuarantineReason.INVALID_FORMAT)
    database = store / name
    if database.is_symlink() or not database.is_file():
        return fail(DatabaseSnapshotQuarantineReason.UNREADABLE)
    return ParsedSnapshotV1(database, digest, allowlist)


def materialize(parsed: ParsedSnapshotV1) -> DatabaseSnapshotReadResult:
    digest = _digest(parsed.database)
    if digest is None:
        return fail(DatabaseSnapshotQuarantineReason.UNREADABLE)
    if digest != parsed.fingerprint:
        return fail(DatabaseSnapshotQuarantineReason.SOURCE_MUTATED)
    approved = _approved(parsed.allowlist)
    if not approved:
        return _scan(digest, (), DatabaseSnapshotReadProofV1((), (), ()))
    return _read_database(parsed.database, digest, approved)


def _allowlist(raw: JsonValue) -> tuple[tuple[str, tuple[str, ...]], ...] | None:
    if not isinstance(raw, dict) or not raw:
        return None
    accepted: list[tuple[str, tuple[str, ...]]] = []
    for table, columns in raw.items():
        if _IDENT.fullmatch(table) is None or not isinstance(columns, list) or not columns:
            return None
        names: list[str] = []
        for column in columns:
            if not isinstance(column, str) or _IDENT.fullmatch(column) is None or column in names:
                return None
            names.append(column)
        accepted.append((table, tuple(names)))
    return tuple(accepted)


def _approved(allowlist: tuple[tuple[str, tuple[str, ...]], ...]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    approved: list[tuple[str, tuple[str, ...]]] = []
    for table, columns in allowlist:
        if table.casefold() in _DENIED_TABLES or table.casefold().startswith("sqlite_"):
            continue
        kept = tuple(column for column in columns if column.casefold() not in _DENIED_COLUMNS)
        if kept:
            approved.append((table, kept))
    return tuple(approved)


def _digest(path: Path) -> str | None:
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > MAX_SNAPSHOT_BYTES:
            return None
        hasher = sha256()
        remaining = info.st_size
        while remaining:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                return None
            hasher.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if after.st_mtime_ns != info.st_mtime_ns or after.st_size != info.st_size:
            return None
        return hasher.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def _read_database(
    database: Path,
    digest: str,
    approved: tuple[tuple[str, tuple[str, ...]], ...],
) -> DatabaseSnapshotReadResult:
    uri = f"file:{quote(database.resolve().as_posix(), safe='/')}?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return fail(DatabaseSnapshotQuarantineReason.UNREADABLE)
    statements: list[str] = []
    try:
        connection.set_trace_callback(statements.append)
        items, tables_read, row_reads = _select(connection, approved)
    except sqlite3.Error:
        return fail(DatabaseSnapshotQuarantineReason.UNREADABLE)
    finally:
        connection.close()
    if items is None:
        return fail(DatabaseSnapshotQuarantineReason.UNSUPPORTED_SCHEMA)
    return _scan(digest, items, DatabaseSnapshotReadProofV1(tables_read, row_reads, tuple(statements)))


def _scan(
    digest: str,
    items: tuple[DatabaseSnapshotRowV1, ...],
    proof: DatabaseSnapshotReadProofV1,
) -> DatabaseSnapshotAcceptedScan:
    return DatabaseSnapshotAcceptedScan(SNAPSHOT_VERSION, SOURCE_PROFILE, Fingerprint(digest), items, proof)


def _select(
    connection: sqlite3.Connection,
    approved: tuple[tuple[str, tuple[str, ...]], ...],
) -> tuple[tuple[DatabaseSnapshotRowV1, ...] | None, tuple[TableName, ...], tuple[tuple[TableName, int], ...]]:
    items: list[DatabaseSnapshotRowV1] = []
    tables_read: list[TableName] = []
    row_reads: list[tuple[TableName, int]] = []
    for table, columns in approved:
        present = {str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')}
        if not present or not set(columns) <= present:
            return None, (), ()
        quoted = ", ".join(f'"{column}"' for column in columns)
        rows = connection.execute(f'SELECT {quoted} FROM "{table}" ORDER BY "{columns[0]}"').fetchall()
        name = TableName(table)
        tables_read.append(name)
        row_reads.append((name, len(rows)))
        items.extend(_row(table, columns, tuple(row)) for row in rows)
    return tuple(items), tuple(tables_read), tuple(row_reads)


def _row(table: str, columns: tuple[str, ...], row: Sequence[str | int | float | bytes | None]) -> DatabaseSnapshotRowV1:
    fields = tuple((column, _cell(value)) for column, value in zip(columns, row, strict=True))
    native = next((value for name, value in fields if name == "id"), "")
    native_id = NativeId(native if native else sha256(_canonical(table, "", fields).encode()).hexdigest())
    return DatabaseSnapshotRowV1(
        TableName(table),
        native_id,
        fields,
        sha256(_canonical(table, native_id, fields).encode()).hexdigest(),
    )


def _canonical(table: str, native_id: str, fields: tuple[tuple[str, str], ...]) -> str:
    return json.dumps({"fields": dict(fields), "native_id": native_id, "table": table}, separators=(",", ":"), sort_keys=True)


def _cell(value: str | int | float | bytes | None) -> str:
    match value:
        case None:
            return ""
        case str() as text:
            return text
        case bool() as flag:
            return "true" if flag else "false"
        case int() as number:
            return str(number)
        case float() as number:
            return str(number)
        case bytes() as raw:
            return raw.decode("utf-8", "replace")
        case unreachable:
            assert_never(unreachable)
