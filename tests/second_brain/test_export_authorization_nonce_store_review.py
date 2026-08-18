"""Security-review probes: refuse-without-mutate, restore publish, backup race."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from tests.second_brain.export_authorization_nonce_store_support import (
    DIGEST,
    ISSUED,
    NONCE,
    attempt,
    private_store_path,
)
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    export_authorization_nonce_digest,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def _chmod_store(path: Path) -> None:
    os.chmod(path, 0o600)


def _refuse_open(path: Path) -> None:
    with pytest.raises(UnifiedDbExportError):
        _ = SqliteExportAuthorizationNonceStore(path)


def test_existing_empty_file_is_refused_and_byte_identical(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    _ = path.write_bytes(b"")
    _chmod_store(path)
    before = path.read_bytes()
    _refuse_open(path)
    assert path.read_bytes() == before
    _refuse_open(path)
    assert path.read_bytes() == before


def test_header_only_store_is_refused_and_byte_identical(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    connection = sqlite3.connect(path)
    _ = connection.execute("PRAGMA user_version=0")
    connection.commit()
    connection.close()
    _chmod_store(path)
    before = path.read_bytes()
    assert before.startswith(b"SQLite format 3\x00")
    with pytest.raises(UnifiedDbExportError, match="schema"):
        _ = SqliteExportAuthorizationNonceStore(path)
    assert path.read_bytes() == before


def test_truncated_store_is_refused_and_byte_identical(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    planted = b"SQLite format 3\x00" + b"\x00" * 20
    _ = path.write_bytes(planted)
    _chmod_store(path)
    _refuse_open(path)
    assert path.read_bytes() == planted


def test_wrong_consumption_pk_is_refused_and_byte_identical(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    digest = export_authorization_nonce_digest(NONCE)
    connection = sqlite3.connect(path)
    _ = connection.executescript(
        "CREATE TABLE export_nonce_store_metadata ("
        + "store_kind TEXT NOT NULL, schema_version TEXT NOT NULL, "
        + "store_state TEXT NOT NULL, authorization_floor_at TEXT NOT NULL, "
        + "PRIMARY KEY (store_kind)) WITHOUT ROWID;"
        + "CREATE TABLE export_nonce_consumption ("
        + "nonce_digest TEXT NOT NULL, authorization_id TEXT NOT NULL, "
        + "authorization_digest TEXT NOT NULL, authorization_issued_at TEXT NOT NULL, "
        + "consumption_state TEXT NOT NULL, "
        + "PRIMARY KEY (nonce_digest, authorization_id)) WITHOUT ROWID;"
        + "INSERT INTO export_nonce_store_metadata VALUES ("
        + "'export-authorization-nonce-store-v1','1','ACTIVE',"
        + "'0001-01-01T00:00:00Z');"
        + f"INSERT INTO export_nonce_consumption VALUES ('{digest}','export-auth-aaa',"
        + f"'{DIGEST}','{ISSUED}','CONSUMED');"
        + f"INSERT INTO export_nonce_consumption VALUES ('{digest}','export-auth-bbb',"
        + f"'{DIGEST}','{ISSUED}','CONSUMED');"
    )
    connection.commit()
    connection.close()
    _chmod_store(path)
    before = path.read_bytes()
    with pytest.raises(UnifiedDbExportError, match="schema"):
        _ = SqliteExportAuthorizationNonceStore(path)
    assert path.read_bytes() == before


def test_extra_index_or_view_is_refused_and_byte_identical(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    store = SqliteExportAuthorizationNonceStore(path)
    store.close()
    connection = sqlite3.connect(path)
    _ = connection.execute(
        "CREATE INDEX extra_nonce_idx ON export_nonce_consumption (authorization_id)"
    )
    connection.commit()
    connection.close()
    before = path.read_bytes()
    with pytest.raises(UnifiedDbExportError, match="schema"):
        _ = SqliteExportAuthorizationNonceStore(path)
    assert path.read_bytes() == before
    connection = sqlite3.connect(path)
    _ = connection.execute("DROP INDEX extra_nonce_idx")
    _ = connection.execute(
        "CREATE VIEW extra_nonce_view AS SELECT nonce_digest FROM export_nonce_consumption"
    )
    connection.commit()
    connection.close()
    before = path.read_bytes()
    with pytest.raises(UnifiedDbExportError, match="schema"):
        _ = SqliteExportAuthorizationNonceStore(path)
    assert path.read_bytes() == before


def test_legitimate_fresh_and_reopened_store_works(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    store = SqliteExportAuthorizationNonceStore(path)
    store.reserve_and_consume(**attempt())
    store.close()
    reopened = SqliteExportAuthorizationNonceStore(path)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        reopened.reserve_and_consume(**attempt())
    reopened.close()


def test_restore_pause_before_publish_does_not_see_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = private_store_path(tmp_path / "src")
    store = SqliteExportAuthorizationNonceStore(source)
    store.reserve_and_consume(**attempt())
    backup = tmp_path / "backup.sqlite3"
    store.backup(backup)
    store.close()
    dest = private_store_path(tmp_path / "dst")
    real_link = os.link
    seen: dict[str, bool] = {}

    def probe(src: str, dst: str) -> None:
        seen["exists"] = Path(dst).exists()
        real_link(src, dst)

    monkeypatch.setattr(os, "link", probe)
    SqliteExportAuthorizationNonceStore.restore(backup, dest)
    assert seen == {"exists": False}
    restored = SqliteExportAuthorizationNonceStore(dest)
    with pytest.raises(UnifiedDbExportError, match="quarantine"):
        restored.reserve_and_consume(**attempt(nonce="22" * 32))
    restored.close()


def test_backup_failure_does_not_unlink_competitor_sentinel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = private_store_path(tmp_path)
    store = SqliteExportAuthorizationNonceStore(source)
    store.reserve_and_consume(**attempt())
    dest = tmp_path / "backup.sqlite3"
    sentinel = b"competitor-sentinel-bytes"

    def raced(_src: str, dst: str) -> None:
        _ = Path(dst).write_bytes(sentinel)
        os.chmod(dst, 0o600)
        raise FileExistsError

    monkeypatch.setattr(os, "link", raced)
    with pytest.raises(UnifiedDbExportError, match="exists|overwrite"):
        store.backup(dest)
    store.close()
    assert dest.read_bytes() == sentinel


@pytest.mark.parametrize(
    "issued",
    [
        "2026-08-18T12:00:00",
        "2026-08-18T12:00:00z",
        "2026-08-18T12:00:00.000Z",
    ],
)
def test_store_rejects_noncanonical_issued_at(tmp_path: Path, issued: str) -> None:
    store = SqliteExportAuthorizationNonceStore(private_store_path(tmp_path))
    with pytest.raises((InvalidContractValue, UnifiedDbExportError), match="timestamp|UTC"):
        store.reserve_and_consume(**attempt(authorization_issued_at=issued))
    store.reserve_and_consume(**attempt())
    store.close()
