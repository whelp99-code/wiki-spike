"""Production PostgreSQL identity capture remains refused without owner approval."""
from __future__ import annotations

from typing import NoReturn

from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def refuse_postgres_identity_capture(*, dsn_fd: int | None = None) -> NoReturn:
    """Refuse before opening or reading any DSN. Owner approval is not supplied."""
    _ = dsn_fd
    raise UnifiedDbExportError("owner approval required")
