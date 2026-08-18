"""Private pre-DSN composition for refused live unified-db export."""
from __future__ import annotations

from pathlib import Path

from wiki_spike.infrastructure.export_authorization_nonce_fs import ensure_private_dir
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

_PRODUCTION_RELATIVE = (
    "Library/Application Support/wiki-spike/export-authority-v1/nonces.sqlite3"
)


def open_production_export_authorization_nonce_store() -> (
    SqliteExportAuthorizationNonceStore
):
    path = Path.home() / _PRODUCTION_RELATIVE
    support = Path.home() / "Library" / "Application Support"
    if not support.exists():
        support.mkdir(parents=True)
    ensure_private_dir(support / "wiki-spike")
    ensure_private_dir(path.parent)
    return SqliteExportAuthorizationNonceStore(path)


def refuse_live_unified_db_export(*, dsn_fd: int | None = None) -> None:
    _ = dsn_fd
    store = open_production_export_authorization_nonce_store()
    store.close()
    raise UnifiedDbExportError(
        "live export refused: executable mapping and signed authority are absent"
    )
