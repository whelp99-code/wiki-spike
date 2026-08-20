"""Production PostgreSQL identity capture remains refused without owner approval."""
from __future__ import annotations

import os
import pwd
from pathlib import Path
from typing import NoReturn

from wiki_spike.infrastructure.export_authorization_nonce_capture import (
    SqliteMetadataCaptureNonceStore,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

_PRODUCTION_RELATIVE = (
    "Library/Application Support/wiki-spike/export-authority-v1/nonces.sqlite3"
)


def open_production_metadata_capture_nonce_store() -> SqliteMetadataCaptureNonceStore:
    """Open the passwd-home nonce DB. Missing or corrupt state is never created."""
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    return SqliteMetadataCaptureNonceStore(home / _PRODUCTION_RELATIVE)


def refuse_postgres_identity_capture(*, dsn_fd: int | None = None) -> NoReturn:
    """Refuse before opening or reading any DSN. Owner approval is not supplied."""
    _ = dsn_fd
    raise UnifiedDbExportError("owner approval required")
