"""Typed adapter for owner-created immutable database snapshots. Isolated: not registered."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Final, assert_never

from wiki_spike.connectors.database_snapshot_decode import ParsedSnapshotV1, materialize, parse_manifest
from wiki_spike.connectors.database_snapshot_types import (
    SNAPSHOT_VERSION,
    SOURCE_PROFILE,
    DatabaseSnapshotAcceptedScan,
    DatabaseSnapshotQuarantineReason,
    DatabaseSnapshotReadProofV1,
    DatabaseSnapshotReadResult,
    DatabaseSnapshotRowV1,
    DatabaseSnapshotScopeDisabled,
    DatabaseSnapshotStoreQuarantined,
    Fingerprint,
    NativeId,
    TableName,
)

_LIVE_URI: Final = re.compile(r"^(?:postgres(?:ql)?|mysql|mariadb|mssql|mongodb|redis|sqlite)://", re.IGNORECASE)


class DatabaseSnapshotAdapter:
    """Read-only decoder for one explicit immutable snapshot. Isolated: not registered."""

    source_profile: Final = SOURCE_PROFILE

    def read(self, store: Path, *, scope_enabled: bool = True) -> DatabaseSnapshotReadResult:
        """Parse one owner snapshot, or refuse before I/O when the scope is disabled."""
        if not scope_enabled:
            return DatabaseSnapshotScopeDisabled()
        classified = _classify(store)
        if classified is not None:
            return DatabaseSnapshotStoreQuarantined(classified)
        parsed = parse_manifest(store)
        match parsed:
            case DatabaseSnapshotStoreQuarantined():
                return parsed
            case ParsedSnapshotV1():
                return materialize(parsed)
            case unreachable:
                assert_never(unreachable)


def _classify(store: Path) -> DatabaseSnapshotQuarantineReason | None:
    if _LIVE_URI.match(os.fspath(store)) is not None or not store.is_absolute():
        return DatabaseSnapshotQuarantineReason.LIVE_STORE
    try:
        names = tuple(path.name for path in store.iterdir()) if store.is_dir() else None
    except OSError:
        return DatabaseSnapshotQuarantineReason.UNREADABLE
    if names is None or any(name.endswith(("-wal", "-shm")) for name in names) or "snapshot.json" not in names:
        return DatabaseSnapshotQuarantineReason.LIVE_STORE
    return None


__all__ = (
    "SNAPSHOT_VERSION",
    "SOURCE_PROFILE",
    "DatabaseSnapshotAcceptedScan",
    "DatabaseSnapshotAdapter",
    "DatabaseSnapshotQuarantineReason",
    "DatabaseSnapshotReadProofV1",
    "DatabaseSnapshotReadResult",
    "DatabaseSnapshotRowV1",
    "DatabaseSnapshotScopeDisabled",
    "DatabaseSnapshotStoreQuarantined",
    "Fingerprint",
    "NativeId",
    "TableName",
)
