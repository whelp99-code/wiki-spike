"""Backup, restore quarantine, and explicit activate probes."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.second_brain.export_authorization_nonce_store_support import (
    OTHER_NONCE,
    attempt,
    private_store_path,
)
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
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
