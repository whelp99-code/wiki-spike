"""Capture-domain adapter over the existing physical export nonce SQLite DB."""
from __future__ import annotations

from pathlib import Path
from typing import final

from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_nonce import (
    metadata_capture_nonce_digest,
)


@final
class SqliteMetadataCaptureNonceStore:
    """Existing-store-only capture adapter. Never creates or repairs."""

    _store: SqliteExportAuthorizationNonceStore

    def __init__(self, path: Path) -> None:
        self._store = SqliteExportAuthorizationNonceStore(
            path,
            digest_nonce=metadata_capture_nonce_digest,
            allow_create=False,
        )

    def close(self) -> None:
        self._store.close()

    def reserve_and_consume(
        self,
        *,
        authorization_id: str,
        nonce: str,
        authorization_digest: str,
        authorization_issued_at: str,
    ) -> None:
        """Insert the capture-domain nonce as CONSUMED or refuse a replay."""
        self._store.reserve_and_consume(
            authorization_id=authorization_id,
            nonce=nonce,
            authorization_digest=authorization_digest,
            authorization_issued_at=authorization_issued_at,
        )
