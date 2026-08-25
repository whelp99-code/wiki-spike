"""Typed adapter for registered Markdown/JSON records and JARVIS exports."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, NewType

ItemId = NewType("ItemId", str)
ProjectId = NewType("ProjectId", str)

EXPORT_VERSION: Final = "project-jarvis-records-v1"
SOURCE_PROFILE: Final = "Project/JARVIS records"
MAX_EXPORT_BYTES: Final = 67_108_864
_OPEN_FLAGS: Final = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_PRIVATE_NAMES: Final = frozenset({"auth.json", "cookies", "cookies.json", "credentials.json", "secrets.json", ".env"})
_LIVE_SUFFIXES: Final = frozenset({".db", ".plist", ".sock", ".sqlite"})


class ProjectRecordKind(StrEnum):
    OPERATIONAL_MARKDOWN = "operational_markdown"
    OPERATIONAL_JSON = "operational_json"
    CONTROL_TOWER_ARTIFACT = "control_tower_artifact"


class ProjectQuarantineReason(StrEnum):
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNKNOWN_SCHEMA = "UNKNOWN_SCHEMA"
    INVALID_FORMAT = "INVALID_FORMAT"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    PRIVATE_STATE = "PRIVATE_STATE"
    LIVE_CONTROL = "LIVE_CONTROL"
    UNREADABLE = "UNREADABLE"
    UNRESTRICTED_TRAVERSAL = "UNRESTRICTED_TRAVERSAL"


@dataclass(frozen=True, slots=True)
class ProjectCursorV1:
    next_line: int
    prefix_digest: str


@dataclass(frozen=True, slots=True)
class ProjectAcceptedItem:
    item_id: ItemId
    project_id: ProjectId
    parent_id: ItemId | None
    kind: ProjectRecordKind
    text: str
    revision: str
    tombstone: bool
    artifact_name: str | None


@dataclass(frozen=True, slots=True)
class ProjectAcceptedScan:
    export_version: str
    source_profile: str
    project_id: ProjectId
    items: tuple[ProjectAcceptedItem, ...]
    cursor: ProjectCursorV1


@dataclass(frozen=True, slots=True)
class ProjectStoreQuarantined:
    reason: ProjectQuarantineReason


@dataclass(frozen=True, slots=True)
class ProjectScopeDisabled:
    source_profile: str = SOURCE_PROFILE


type ProjectReadResult = ProjectAcceptedScan | ProjectStoreQuarantined | ProjectScopeDisabled


def _classify_path(store: Path) -> ProjectQuarantineReason | None:
    if not store.is_absolute():
        return ProjectQuarantineReason.INVALID_FORMAT
    if store.name.casefold() in _PRIVATE_NAMES:
        return ProjectQuarantineReason.PRIVATE_STATE
    if store.suffix.casefold() in _LIVE_SUFFIXES:
        return ProjectQuarantineReason.LIVE_CONTROL
    try:
        directory = store.is_dir()
    except OSError:
        return ProjectQuarantineReason.UNREADABLE
    if directory:
        return ProjectQuarantineReason.UNRESTRICTED_TRAVERSAL
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


class ProjectRecordAdapter:
    """Read-only decoder for one explicit project/JARVIS export. Isolated: not registered."""

    source_profile: Final = SOURCE_PROFILE

    def read(
        self,
        store: Path,
        *,
        cursor: ProjectCursorV1 | None = None,
        scope_enabled: bool = True,
    ) -> ProjectReadResult:
        """Parse one registered export, or refuse before I/O when the scope is disabled."""
        if not scope_enabled:
            return ProjectScopeDisabled()
        classified = _classify_path(store)
        if classified is not None:
            return ProjectStoreQuarantined(classified)
        payload = _read_local_bytes(store)
        if payload is None:
            return ProjectStoreQuarantined(ProjectQuarantineReason.UNREADABLE)
        from wiki_spike.connectors.project_records_decode import parse_project_export

        return parse_project_export(payload, cursor)


__all__ = (
    "EXPORT_VERSION",
    "SOURCE_PROFILE",
    "ItemId",
    "ProjectAcceptedItem",
    "ProjectAcceptedScan",
    "ProjectCursorV1",
    "ProjectId",
    "ProjectQuarantineReason",
    "ProjectReadResult",
    "ProjectRecordAdapter",
    "ProjectRecordKind",
    "ProjectScopeDisabled",
    "ProjectStoreQuarantined",
)
