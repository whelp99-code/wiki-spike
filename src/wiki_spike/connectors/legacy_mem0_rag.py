"""Typed canonical reader for explicit immutable local legacy Mem0/RAG exports."""
from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, NewType, assert_never

NativeId = NewType("NativeId", str)
Revision = NewType("Revision", str)
Watermark = NewType("Watermark", str)
type JsonNode = str | int | float | bool | None | list[JsonNode] | dict[str, JsonNode]

EXPORT_VERSION: Final = "legacy-mem0-rag-export-v1"
MIGRATION_SOURCE: Final = "legacy Mem0/RAG"
MAX_EXPORT_BYTES: Final = 67_108_864
_EXPORT_FIELDS: Final = frozenset({"export_version", "immutable", "migration_source", "records"})
_RECORD_FIELDS: Final = frozenset({"citations", "kind", "native_id", "revision", "text", "tombstone", "watermark"})
_FORBIDDEN_FIELDS: Final = frozenset({
    "api_key", "cache", "credential", "credentials", "embedding", "embeddings",
    "hidden_prompt", "hidden_reasoning", "model_cache", "model_caches", "password",
    "prompt", "prompts", "secret", "system_prompt", "token", "vector", "vector_index", "vectors",
})
_OPEN_FLAGS: Final = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


class LegacyMem0RagItemKind(StrEnum):
    MEMORY = "memory"
    DOCUMENT = "document"


class LegacyMem0RagQuarantineReason(StrEnum):
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    NOT_IMMUTABLE = "NOT_IMMUTABLE"
    NOT_LOCAL = "NOT_LOCAL"
    UNREADABLE = "UNREADABLE"
    INVALID_FORMAT = "INVALID_FORMAT"
    FORBIDDEN_FIELD = "FORBIDDEN_FIELD"
    FORBIDDEN_KIND = "FORBIDDEN_KIND"
    IDENTITY_COLLISION = "IDENTITY_COLLISION"
    WRONG_SOURCE = "WRONG_SOURCE"


@dataclass(frozen=True, slots=True)
class LegacyMem0RagAcceptedItem:
    native_id: NativeId
    revision: Revision
    watermark: Watermark
    tombstone: bool
    kind: LegacyMem0RagItemKind
    text: str | None
    citations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LegacyMem0RagQuarantinedItem:
    native_id: NativeId | None
    reason: LegacyMem0RagQuarantineReason


@dataclass(frozen=True, slots=True)
class LegacyMem0RagAcceptedExport:
    export_version: str
    migration_source: str
    items: tuple[LegacyMem0RagAcceptedItem, ...]
    quarantined: tuple[LegacyMem0RagQuarantinedItem, ...]


@dataclass(frozen=True, slots=True)
class LegacyMem0RagExportQuarantined:
    reason: LegacyMem0RagQuarantineReason


@dataclass(frozen=True, slots=True)
class LegacyMem0RagScopeDisabled:
    migration_source: str = MIGRATION_SOURCE


type LegacyMem0RagReadResult = (
    LegacyMem0RagAcceptedExport | LegacyMem0RagExportQuarantined | LegacyMem0RagScopeDisabled
)
type _RecordResult = LegacyMem0RagAcceptedItem | LegacyMem0RagQuarantinedItem


def _text(value: JsonNode) -> str | None:
    if isinstance(value, str) and value and "\x00" not in value:
        return value
    return None


def _native_id(raw: Mapping[str, JsonNode]) -> NativeId | None:
    value = _text(raw.get("native_id"))
    return None if value is None else NativeId(value)


def _citations(value: JsonNode) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = _text(item)
        if text is None or text in seen:
            return None
        seen.add(text)
        items.append(text)
    return tuple(items)


def _kind(value: JsonNode) -> LegacyMem0RagItemKind | LegacyMem0RagQuarantineReason:
    if not isinstance(value, str):
        return LegacyMem0RagQuarantineReason.INVALID_FORMAT
    match value:  # noqa: MATCH_OK
        case "memory":
            return LegacyMem0RagItemKind.MEMORY
        case "document":
            return LegacyMem0RagItemKind.DOCUMENT
        case _:
            return LegacyMem0RagQuarantineReason.FORBIDDEN_KIND


def _quarantine(native_id: NativeId | None, reason: LegacyMem0RagQuarantineReason) -> LegacyMem0RagQuarantinedItem:
    return LegacyMem0RagQuarantinedItem(native_id, reason)


def _parse_record(raw: JsonNode) -> _RecordResult:
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        return _quarantine(None, LegacyMem0RagQuarantineReason.INVALID_FORMAT)
    keys = set(raw)
    native_id = _native_id(raw)
    if keys & _FORBIDDEN_FIELDS:
        return _quarantine(native_id, LegacyMem0RagQuarantineReason.FORBIDDEN_FIELD)
    if keys != _RECORD_FIELDS:
        return _quarantine(native_id, LegacyMem0RagQuarantineReason.INVALID_FORMAT)
    revision = _text(raw["revision"])
    watermark = _text(raw["watermark"])
    tombstone = raw["tombstone"]
    if native_id is None or revision is None or watermark is None or not isinstance(tombstone, bool):
        return _quarantine(native_id, LegacyMem0RagQuarantineReason.INVALID_FORMAT)
    kind = _kind(raw["kind"])
    match kind:
        case LegacyMem0RagItemKind() as item_kind:
            pass
        case LegacyMem0RagQuarantineReason() as reason:
            return _quarantine(native_id, reason)
        case unreachable:
            assert_never(unreachable)
    citations = _citations(raw["citations"])
    if citations is None:
        return _quarantine(native_id, LegacyMem0RagQuarantineReason.INVALID_FORMAT)
    if tombstone:
        if raw["text"] is not None or citations:
            return _quarantine(native_id, LegacyMem0RagQuarantineReason.INVALID_FORMAT)
        return LegacyMem0RagAcceptedItem(
            native_id, Revision(revision), Watermark(watermark), True, item_kind, None, (),
        )
    text = _text(raw["text"])
    if text is None:
        return _quarantine(native_id, LegacyMem0RagQuarantineReason.INVALID_FORMAT)
    return LegacyMem0RagAcceptedItem(
        native_id, Revision(revision), Watermark(watermark), False, item_kind, text, citations,
    )


def _parse_records(raw: JsonNode) -> tuple[tuple[LegacyMem0RagAcceptedItem, ...], tuple[LegacyMem0RagQuarantinedItem, ...]] | LegacyMem0RagQuarantineReason:
    if not isinstance(raw, list):
        return LegacyMem0RagQuarantineReason.INVALID_FORMAT
    accepted: list[LegacyMem0RagAcceptedItem] = []
    quarantined: list[LegacyMem0RagQuarantinedItem] = []
    seen: set[tuple[NativeId, Revision]] = set()
    for item in raw:
        parsed = _parse_record(item)
        match parsed:
            case LegacyMem0RagQuarantinedItem():
                quarantined.append(parsed)
            case LegacyMem0RagAcceptedItem() as record:
                identity = (record.native_id, record.revision)
                if identity in seen:
                    quarantined.append(_quarantine(record.native_id, LegacyMem0RagQuarantineReason.IDENTITY_COLLISION))
                else:
                    seen.add(identity)
                    accepted.append(record)
            case unreachable:
                assert_never(unreachable)
    return tuple(accepted), tuple(quarantined)


def _parse_export(raw: JsonNode) -> LegacyMem0RagReadResult:
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.INVALID_FORMAT)
    keys = set(raw)
    if keys & _FORBIDDEN_FIELDS:
        return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.FORBIDDEN_FIELD)
    if keys != _EXPORT_FIELDS:
        return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.INVALID_FORMAT)
    version = raw["export_version"]
    if not isinstance(version, str):
        return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.INVALID_FORMAT)
    if version != EXPORT_VERSION:
        return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.UNSUPPORTED_VERSION)
    if raw["migration_source"] != MIGRATION_SOURCE:
        return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.WRONG_SOURCE)
    if raw["immutable"] is not True:
        return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.NOT_IMMUTABLE)
    parsed = _parse_records(raw["records"])
    match parsed:
        case LegacyMem0RagQuarantineReason() as reason:
            return LegacyMem0RagExportQuarantined(reason)
        case (items, quarantined):
            return LegacyMem0RagAcceptedExport(EXPORT_VERSION, MIGRATION_SOURCE, items, quarantined)
        case unreachable:
            assert_never(unreachable)


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


class LegacyMem0RagConnector:
    """Read-only local export connector. Isolated: not registered or networked."""

    migration_source: Final = MIGRATION_SOURCE
    source_domain: Final = "legacy-mem0-rag"

    def read_export(self, export_path: Path, *, scope_enabled: bool) -> LegacyMem0RagReadResult:
        """Parse one explicit local export, or refuse before I/O when the scope is disabled."""
        if not scope_enabled:
            return LegacyMem0RagScopeDisabled()
        if not export_path.is_absolute():
            return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.NOT_LOCAL)
        payload = _read_local_bytes(export_path)
        if payload is None:
            return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.UNREADABLE)
        try:
            raw = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return LegacyMem0RagExportQuarantined(LegacyMem0RagQuarantineReason.INVALID_FORMAT)
        return _parse_export(raw)


__all__ = (
    "EXPORT_VERSION",
    "MIGRATION_SOURCE",
    "LegacyMem0RagAcceptedExport",
    "LegacyMem0RagAcceptedItem",
    "LegacyMem0RagConnector",
    "LegacyMem0RagExportQuarantined",
    "LegacyMem0RagItemKind",
    "LegacyMem0RagQuarantineReason",
    "LegacyMem0RagQuarantinedItem",
    "LegacyMem0RagReadResult",
    "LegacyMem0RagScopeDisabled",
    "NativeId",
    "Revision",
    "Watermark",
)
