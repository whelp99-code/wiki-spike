"""Typed decoder for supported GJC public session/export records."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Final

from wiki_spike.connectors.gjc_decode import parse_gjc_export
from wiki_spike.connectors.gjc_types import (
    EXPORT_VERSION,
    SOURCE_PROFILE,
    GjcAcceptedItem,
    GjcAcceptedScan,
    GjcCursorV1,
    GjcItemKind,
    GjcQuarantineReason,
    GjcReadResult,
    GjcScopeDisabled,
    GjcStoreQuarantined,
    ItemId,
    SessionId,
)

MAX_EXPORT_BYTES: Final = 67_108_864
_OPEN_FLAGS: Final = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_PRIVATE_NAMES: Final = frozenset({"auth.json", "credentials.json", "pending-approval.md"})


def _classify_path(store: Path) -> GjcQuarantineReason | None:
    if not store.is_absolute():
        return GjcQuarantineReason.INVALID_FORMAT
    if store.name in _PRIVATE_NAMES or "plans" in store.parts or "ralplan" in store.parts:
        return GjcQuarantineReason.PRIVATE_STATE
    try:
        directory = store.is_dir()
    except OSError:
        return GjcQuarantineReason.UNREADABLE
    if directory and (store.name == ".gjc" or store.name.startswith("_session-")):
        return GjcQuarantineReason.PRIVATE_STATE
    if directory:
        return GjcQuarantineReason.INVALID_FORMAT
    return None


def _read_local_bytes(path: Path) -> bytes | None:
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > MAX_EXPORT_BYTES:
            return None
        payload = os.read(fd, info.st_size)
        after = os.fstat(fd)
        if len(payload) != info.st_size or after.st_mtime_ns != info.st_mtime_ns or after.st_size != info.st_size:
            return None
        return payload
    except OSError:
        return None
    finally:
        os.close(fd)


class GjcSessionAdapter:
    """Read-only public GJC export decoder. Isolated: not registered or networked."""

    source_profile: Final = SOURCE_PROFILE

    def read(
        self,
        store: Path,
        *,
        cursor: GjcCursorV1 | None = None,
        scope_enabled: bool = True,
    ) -> GjcReadResult:
        """Parse one explicit public export, or refuse before I/O when the scope is disabled."""
        if not scope_enabled:
            return GjcScopeDisabled()
        classified = _classify_path(store)
        if classified is not None:
            return GjcStoreQuarantined(classified)
        payload = _read_local_bytes(store)
        if payload is None:
            return GjcStoreQuarantined(GjcQuarantineReason.UNREADABLE)
        return parse_gjc_export(payload, cursor)


__all__ = (
    "EXPORT_VERSION",
    "SOURCE_PROFILE",
    "GjcAcceptedItem",
    "GjcAcceptedScan",
    "GjcCursorV1",
    "GjcItemKind",
    "GjcQuarantineReason",
    "GjcReadResult",
    "GjcScopeDisabled",
    "GjcSessionAdapter",
    "GjcStoreQuarantined",
    "ItemId",
    "SessionId",
)
