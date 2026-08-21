"""Backup, restore quarantine, and explicit activate probes."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from tests.second_brain.export_authorization_nonce_store_support import (
    OTHER_NONCE,
    attempt,
    private_store_path,
)
from wiki_spike.infrastructure.export_authorization_nonce_decode import query_texts
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

FLOOR = "2026-08-18T12:00:00Z"
BEFORE = "2026-08-18T11:59:59Z"
AFTER = "2026-08-18T12:00:01Z"


def test_backup_restore_quarantine_consumes_without_admit(tmp_path: Path) -> None:
    source = private_store_path(tmp_path / "src")
    store = SqliteExportAuthorizationNonceStore(source)
    store.reserve_and_consume(**attempt())
    backup = tmp_path / "backup.sqlite3"
    store.backup(backup)
    store.close()
    dest = private_store_path(tmp_path / "dst")
    SqliteExportAuthorizationNonceStore.restore(backup, dest)
    restored = SqliteExportAuthorizationNonceStore(dest)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        restored.reserve_and_consume(**attempt())
    with pytest.raises(UnifiedDbExportError, match="quarantine"):
        restored.reserve_and_consume(**attempt(nonce=OTHER_NONCE))
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        restored.reserve_and_consume(**attempt(nonce=OTHER_NONCE))
    restored.close()


def test_activate_restored_admits_only_at_or_after_floor(tmp_path: Path) -> None:
    source = private_store_path(tmp_path / "src")
    store = SqliteExportAuthorizationNonceStore(source)
    store.reserve_and_consume(**attempt())
    backup = tmp_path / "backup.sqlite3"
    store.backup(backup)
    store.close()
    dest = private_store_path(tmp_path / "dst")
    SqliteExportAuthorizationNonceStore.restore(backup, dest)
    restored = SqliteExportAuthorizationNonceStore(dest)
    restored.activate_restored(FLOOR)
    early = "22" * 32
    late = "33" * 32
    with pytest.raises(UnifiedDbExportError, match="floor|admit"):
        restored.reserve_and_consume(
            **attempt(nonce=early, authorization_issued_at=BEFORE)
        )
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        restored.reserve_and_consume(
            **attempt(nonce=early, authorization_issued_at=AFTER)
        )
    restored.reserve_and_consume(**attempt(nonce=late, authorization_issued_at=AFTER))
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        restored.reserve_and_consume(**attempt())
    restored.close()


def test_activate_restored_preserves_canonical_floor_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PlatformFormatted:
        @staticmethod
        def strftime(_format: str) -> str:
            return "1-01-01T00:00:00Z"

    def platform_parse(
        _value: JsonValue,
        _field: str,
    ) -> PlatformFormatted:
        return PlatformFormatted()

    source = private_store_path(tmp_path / "src")
    store = SqliteExportAuthorizationNonceStore(source)
    backup = tmp_path / "backup.sqlite3"
    store.backup(backup)
    store.close()
    dest = private_store_path(tmp_path / "dst")
    SqliteExportAuthorizationNonceStore.restore(backup, dest)
    restored = SqliteExportAuthorizationNonceStore(dest)
    monkeypatch.setattr(
        "wiki_spike.infrastructure.export_authorization_nonce_store.parse_utc",
        platform_parse,
    )

    restored.activate_restored(FLOOR)
    restored.close()

    connection = sqlite3.connect(dest)
    floors = query_texts(
        connection,
        "SELECT _ws_nonce_cap(authorization_floor_at) "
        + "FROM export_nonce_store_metadata",
    )
    connection.close()
    assert floors == (FLOOR,)


def test_restore_refuses_existing_destination(tmp_path: Path) -> None:
    source = private_store_path(tmp_path / "src")
    store = SqliteExportAuthorizationNonceStore(source)
    store.reserve_and_consume(**attempt())
    backup = tmp_path / "backup.sqlite3"
    store.backup(backup)
    store.close()
    dest = private_store_path(tmp_path / "dst")
    SqliteExportAuthorizationNonceStore.restore(backup, dest)
    with pytest.raises(UnifiedDbExportError, match="exists|overwrite"):
        SqliteExportAuthorizationNonceStore.restore(backup, dest)
