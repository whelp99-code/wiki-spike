"""Existing-only LifecycleDatabase admission and serving-readiness inspection."""
from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, LifecycleDbError
from wiki_spike.infrastructure.lifecycle_db_existing import (
    inspect_existing_serving_ready,
    open_existing_lifecycle_database,
)

_WORKSPACE = "workspace:" + "ab" * 32


def _create_database(
    path: Path,
    *,
    authority_state: str | None = "ACTIVE",
    migration_state: str | None = "SERVING_READY",
) -> None:
    database = LifecycleDatabase(path)
    database.initialize()
    assert database.con is not None
    if authority_state is not None:
        _ = database.con.execute(
            "INSERT INTO ledger_authority VALUES(?,?,?,?,?)",
            (_WORKSPACE, "capability:test", "1", authority_state, "2026-08-21T00:00:00Z"),
        )
    if migration_state is not None:
        _ = database.con.execute(
            "INSERT INTO ledger_migration VALUES(?,?,?,?,?)",
            (
                "migration:test",
                _WORKSPACE,
                migration_state,
                "cd" * 32,
                "2026-08-21T00:00:01Z",
            ),
        )
    database.close()
    path.chmod(0o600)


def _snapshot(root: Path) -> dict[str, tuple[str, int, bytes | None]]:
    result: dict[str, tuple[str, int, bytes | None]] = {}
    for path in sorted(root.iterdir()):
        metadata = os.lstat(path)
        kind = "file" if stat.S_ISREG(metadata.st_mode) else "other"
        payload = path.read_bytes() if kind == "file" else None
        result[path.name] = (kind, stat.S_IMODE(metadata.st_mode), payload)
    return result


def test_open_existing_reads_ready_state_without_writes(tmp_path: Path) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    _create_database(path)
    before = _snapshot(tmp_path)

    database = open_existing_lifecycle_database(path)
    try:
        status = inspect_existing_serving_ready(database, _WORKSPACE)
    finally:
        database.close()

    assert status.ready is True
    assert status.authority_state == "ACTIVE"
    assert status.migration_state == "SERVING_READY"
    assert _snapshot(tmp_path) == before


def test_open_existing_close_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    _create_database(path)
    database = open_existing_lifecycle_database(path)

    database.close()
    database.close()

    assert database.con is None


def test_inspection_refuses_database_changed_since_open(tmp_path: Path) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    _create_database(path)
    database = open_existing_lifecycle_database(path)
    metadata = path.stat()
    os.utime(
        path,
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
    )
    try:
        with pytest.raises(LifecycleDbError, match="changed since open"):
            _ = inspect_existing_serving_ready(database, _WORKSPACE)
    finally:
        database.close()


@pytest.mark.parametrize("kind", ["missing", "directory", "empty", "symlink"])
def test_open_existing_refuses_invalid_path_without_mutation(
    tmp_path: Path,
    kind: str,
) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    if kind == "directory":
        path.mkdir(mode=0o700)
    elif kind == "empty":
        path.touch(mode=0o600)
    elif kind == "symlink":
        target = tmp_path / "target.sqlite3"
        _create_database(target)
        _ = path.symlink_to(target)
    before = _snapshot(tmp_path)

    with pytest.raises(LifecycleDbError, match="existing lifecycle"):
        _ = open_existing_lifecycle_database(path)

    assert _snapshot(tmp_path) == before


def test_open_existing_refuses_bad_mode_without_repair(tmp_path: Path) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    _create_database(path)
    path.chmod(0o644)
    before = _snapshot(tmp_path)

    with pytest.raises(LifecycleDbError, match="mode"):
        _ = open_existing_lifecycle_database(path)

    assert _snapshot(tmp_path) == before


def test_open_existing_refuses_schema_drift_without_migration(tmp_path: Path) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    connection = sqlite3.connect(path)
    _ = connection.execute(
        "CREATE TABLE ledger_authority(workspace_ref TEXT PRIMARY KEY)"
    )
    connection.close()
    path.chmod(0o600)
    before = _snapshot(tmp_path)

    with pytest.raises(LifecycleDbError, match="schema"):
        _ = open_existing_lifecycle_database(path)

    assert _snapshot(tmp_path) == before


def test_open_existing_refuses_nonempty_wal_without_checkpoint(
    tmp_path: Path,
) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    database = LifecycleDatabase(path)
    database.initialize()
    assert database.con is not None
    _ = database.con.execute("PRAGMA wal_autocheckpoint=0")
    _ = database.con.execute(
        "INSERT INTO ledger_authority VALUES(?,?,?,?,?)",
        (_WORKSPACE, "capability:test", "1", "ACTIVE", "2026-08-21T00:00:00Z"),
    )
    path.chmod(0o600)
    wal_path = Path(f"{path}-wal")
    assert wal_path.stat().st_size > 0
    before = _snapshot(tmp_path)
    try:
        with pytest.raises(LifecycleDbError, match="clean WAL"):
            _ = open_existing_lifecycle_database(path)
        assert _snapshot(tmp_path) == before
    finally:
        database.close()


@pytest.mark.parametrize(
    ("authority_state", "migration_state", "message"),
    [
        (None, "SERVING_READY", "authority is absent"),
        ("INACTIVE", "SERVING_READY", "authority is not ACTIVE"),
        ("ACTIVE", None, "migration is absent"),
        ("ACTIVE", "READY_NON_SERVING", "migration is not SERVING_READY"),
    ],
)
def test_inspection_refuses_non_serving_state_without_writes(
    tmp_path: Path,
    authority_state: str | None,
    migration_state: str | None,
    message: str,
) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    _create_database(
        path,
        authority_state=authority_state,
        migration_state=migration_state,
    )
    before = _snapshot(tmp_path)
    database = open_existing_lifecycle_database(path)
    try:
        with pytest.raises(LifecycleDbError, match=message):
            _ = inspect_existing_serving_ready(database, _WORKSPACE)
    finally:
        database.close()

    assert _snapshot(tmp_path) == before
