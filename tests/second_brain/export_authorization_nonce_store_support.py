"""Temp canonical paths and attempt payloads for the durable nonce store."""
from __future__ import annotations

import os
from pathlib import Path

from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    InMemoryExportAuthorizationNonceStore,
)

ISSUED = "2026-08-18T12:00:00Z"
DIGEST = "cd" * 32
NONCE = "ab" * 32
OTHER_NONCE = "11" * 32


def private_store_path(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    directory = root / "export-authority-v1"
    os.mkdir(directory, 0o700)
    os.chmod(directory, 0o700)
    return directory / "nonces.sqlite3"


def attempt(
    *,
    nonce: str = NONCE,
    authorization_id: str = "export-auth-001",
    authorization_digest: str = DIGEST,
    authorization_issued_at: str = ISSUED,
) -> dict[str, str]:
    return {
        "authorization_id": authorization_id,
        "nonce": nonce,
        "authorization_digest": authorization_digest,
        "authorization_issued_at": authorization_issued_at,
    }


def in_memory() -> InMemoryExportAuthorizationNonceStore:
    return InMemoryExportAuthorizationNonceStore()
