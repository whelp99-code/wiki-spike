"""Typed adapter for user-approved Orca exported records. Isolated: not registered."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, NewType

ItemId = NewType("ItemId", str)
WorktreeId = NewType("WorktreeId", str)

EXPORT_VERSION: Final = "orca-exported-records-v1"
SOURCE_PROFILE: Final = "Orca exported records"
MAX_EXPORT_BYTES: Final = 67_108_864
_OPEN_FLAGS: Final = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_PRIVATE_NAMES: Final = frozenset({"auth.json", "cookies", "cookies.json", "credentials.json"})
_LIVE_SUFFIXES: Final = frozenset({".db", ".sock", ".sqlite"})


class OrcaItemKind(StrEnum):
    WORKTREE_COMMENT = "worktree_comment"
    TERMINAL_SUMMARY = "terminal_summary"
    ARTIFACT = "artifact"


class OrcaQuarantineReason(StrEnum):
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    INVALID_FORMAT = "INVALID_FORMAT"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    PRIVATE_STATE = "PRIVATE_STATE"
    LIVE_APP_STORE = "LIVE_APP_STORE"
    UNREADABLE = "UNREADABLE"


@dataclass(frozen=True, slots=True)
class OrcaCursorV1:
    next_line: int
    prefix_digest: str


@dataclass(frozen=True, slots=True)
class OrcaAcceptedItem:
    item_id: ItemId
    worktree_id: WorktreeId
    parent_id: ItemId | None
    kind: OrcaItemKind
    text: str
    revision: str
    tombstone: bool
    artifact_name: str | None


@dataclass(frozen=True, slots=True)
class OrcaAcceptedScan:
    export_version: str
    source_profile: str
    worktree_id: WorktreeId
    items: tuple[OrcaAcceptedItem, ...]
    cursor: OrcaCursorV1


@dataclass(frozen=True, slots=True)
class OrcaStoreQuarantined:
    reason: OrcaQuarantineReason


@dataclass(frozen=True, slots=True)
class OrcaScopeDisabled:
    source_profile: str = SOURCE_PROFILE


type OrcaReadResult = OrcaAcceptedScan | OrcaStoreQuarantined | OrcaScopeDisabled


def _classify_path(store: Path) -> OrcaQuarantineReason | None:
    if not store.is_absolute():
        return OrcaQuarantineReason.INVALID_FORMAT
    if store.name.casefold() in _PRIVATE_NAMES:
        return OrcaQuarantineReason.PRIVATE_STATE
    if store.suffix.casefold() in _LIVE_SUFFIXES:
        return OrcaQuarantineReason.LIVE_APP_STORE
    try:
        directory = store.is_dir()
    except OSError:
        return OrcaQuarantineReason.UNREADABLE
    if directory:
        return OrcaQuarantineReason.INVALID_FORMAT
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


class OrcaRecordsAdapter:
    """Read-only decoder for one explicit Orca export. Isolated: not registered or networked."""

    source_profile: Final = SOURCE_PROFILE

    def read(
        self,
        store: Path,
        *,
        cursor: OrcaCursorV1 | None = None,
        scope_enabled: bool = True,
    ) -> OrcaReadResult:
        """Parse one explicit public export, or refuse before I/O when the scope is disabled."""
        if not scope_enabled:
            return OrcaScopeDisabled()
        classified = _classify_path(store)
        if classified is not None:
            return OrcaStoreQuarantined(classified)
        payload = _read_local_bytes(store)
        if payload is None:
            return OrcaStoreQuarantined(OrcaQuarantineReason.UNREADABLE)
        from wiki_spike.connectors.orca_records_decode import parse_orca_export

        return parse_orca_export(payload, cursor)


__all__ = (
    "EXPORT_VERSION",
    "SOURCE_PROFILE",
    "ItemId",
    "OrcaAcceptedItem",
    "OrcaAcceptedScan",
    "OrcaCursorV1",
    "OrcaItemKind",
    "OrcaQuarantineReason",
    "OrcaReadResult",
    "OrcaRecordsAdapter",
    "OrcaScopeDisabled",
    "OrcaStoreQuarantined",
    "WorktreeId",
)
