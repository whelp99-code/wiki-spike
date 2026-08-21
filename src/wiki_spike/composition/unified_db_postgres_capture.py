"""Production PostgreSQL identity capture remains refused without owner approval."""
from __future__ import annotations

import os
import pwd
from pathlib import Path
from typing import NoReturn

from wiki_spike.applications.unified_db_postgres_capture_authorization_types import (
    MetadataCaptureVerifyRequestV1,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_verify import (
    VerifiedUnifiedDbMetadataCaptureAuthorityV1,
    verify_metadata_capture_authorization,
)
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


def verify_production_metadata_capture_authorization(
    request: MetadataCaptureVerifyRequestV1,
    *,
    dsn_fd: int | None = None,
) -> VerifiedUnifiedDbMetadataCaptureAuthorityV1:
    """Parse body, consume the passwd-home nonce, then bind digest/time/signatures.

    ``dsn_fd`` is ignored and never read. Failures after consume stay consumed.
    """
    _ = dsn_fd
    store = open_production_metadata_capture_nonce_store()
    try:
        return verify_metadata_capture_authorization(request, store)
    finally:
        store.close()


def refuse_postgres_identity_capture(*, dsn_fd: int | None = None) -> NoReturn:
    """Refuse before opening or reading any DSN. Owner approval is not supplied."""
    _ = dsn_fd
    raise UnifiedDbExportError("owner approval required")
