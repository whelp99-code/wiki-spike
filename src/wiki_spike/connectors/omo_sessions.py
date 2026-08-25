"""Typed decoder for supported OMO/Senpi/pi JSONL session event versions."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, NewType

ItemId = NewType("ItemId", str)
SessionId = NewType("SessionId", str)
type JsonNode = str | int | float | bool | None | list[JsonNode] | dict[str, JsonNode]
type JsonObject = dict[str, JsonNode]

SOURCE_PROFILE: Final = "OMO/Senpi/pi"
LEGACY_EXPORT_VERSION: Final = "omo-senpi-session-v1"
CURRENT_EXPORT_VERSION: Final = "omo-senpi-session-v3"
MAX_STORE_BYTES: Final = 67_108_864
_OPEN_FLAGS: Final = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_ALLOWED: Final = frozenset({"assistant_message", "message", "session", "tool_execution"})
_DENIED: Final = frozenset({
    "cancelled", "child_error", "compaction", "custom", "custom_message", "destroyed", "evicted",
    "late_transition_ignored", "model_change", "reconcile_reattached", "retry_fallback_applied",
    "retry_fallback_exhausted", "revived", "steered", "suspended", "team_message_delivered",
    "team_message_sent", "thinking_level_change", "transition_applied",
})


class OmoItemKind(StrEnum):
    USER_TEXT = "user_text"
    ASSISTANT_TEXT = "assistant_text"
    TOOL_OUTCOME = "tool_outcome"
    TODO_COMPLETION = "todo_completion"
    ARTIFACT = "artifact"


class OmoQuarantineReason(StrEnum):
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNKNOWN_EVENT = "UNKNOWN_EVENT"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    UNREADABLE = "UNREADABLE"
    INVALID_FORMAT = "INVALID_FORMAT"


@dataclass(frozen=True, slots=True)
class OmoCursorV1:
    next_line: int
    prefix_digest: str


@dataclass(frozen=True, slots=True)
class OmoAcceptedItem:
    item_id: ItemId
    session_id: SessionId
    parent_id: ItemId | None
    kind: OmoItemKind
    text: str


@dataclass(frozen=True, slots=True)
class OmoAcceptedScan:
    export_version: str
    source_profile: str
    session_id: SessionId
    parent_session_id: SessionId | None
    items: tuple[OmoAcceptedItem, ...]
    cursor: OmoCursorV1


@dataclass(frozen=True, slots=True)
class OmoStoreQuarantined:
    reason: OmoQuarantineReason


@dataclass(frozen=True, slots=True)
class OmoScopeDisabled:
    source_profile: str = SOURCE_PROFILE


type OmoReadResult = OmoAcceptedScan | OmoStoreQuarantined | OmoScopeDisabled
type _Parsed = list[OmoAcceptedItem] | OmoQuarantineReason


def _text(value: JsonNode) -> str | None:
    return value if isinstance(value, str) and value and "\x00" not in value else None


def _id(value: JsonNode) -> ItemId | None:
    text = _text(value)
    return None if text is None else ItemId(text)


def _obj(value: JsonNode) -> JsonObject | None:
    return value if isinstance(value, dict) else None


def _digest(parts: tuple[bytes, ...]) -> str:
    return hashlib.sha256(b"".join(parts)).hexdigest()


def _tool_kind(name: str) -> OmoItemKind:
    match name:  # noqa: MATCH_OK
        case "todo":
            return OmoItemKind.TODO_COMPLETION
        case "write":
            return OmoItemKind.ARTIFACT
        case _:
            return OmoItemKind.TOOL_OUTCOME


def _tool_text(name: str, arguments: JsonNode) -> str:
    fields = _obj(arguments) or {}
    match name:  # noqa: MATCH_OK
        case "todo":
            return _text(fields.get("task")) or name
        case "write":
            return _text(fields.get("content")) or name
        case _:
            path = _text(fields.get("path"))
            return f"{name}\t{path}" if path is not None else name


def _parts(parts: JsonNode, message_id: ItemId, parent: ItemId | None, session_id: SessionId, role: str) -> _Parsed:
    if not isinstance(parts, list):
        return OmoQuarantineReason.INVALID_FORMAT
    items: list[OmoAcceptedItem] = []
    for part in parts:
        fields = _obj(part)
        if fields is None:
            return OmoQuarantineReason.INVALID_FORMAT
        match _text(fields.get("type")):  # noqa: MATCH_OK
            case "text":
                text = _text(fields.get("text"))
                if text is None:
                    return OmoQuarantineReason.INVALID_FORMAT
                kind = OmoItemKind.USER_TEXT if role == "user" else OmoItemKind.ASSISTANT_TEXT
                items.append(OmoAcceptedItem(message_id, session_id, parent, kind, text))
            case "toolCall":
                call_id, name, args = _id(fields.get("id")), _text(fields.get("name")), _obj(fields.get("arguments")) or {}
                if call_id is None or name is None:
                    return OmoQuarantineReason.INVALID_FORMAT
                if name == "todo" and _text(args.get("op")) != "done":
                    continue
                items.append(OmoAcceptedItem(call_id, session_id, message_id, _tool_kind(name), _tool_text(name, args)))
            case "thinking" | "image":
                continue
            case _:
                return OmoQuarantineReason.UNKNOWN_EVENT
    return items


def _message(raw: JsonObject, session_id: SessionId) -> _Parsed:
    message_id, body = _id(raw.get("id")), _obj(raw.get("message"))
    if message_id is None or body is None:
        return OmoQuarantineReason.INVALID_FORMAT
    role, parent = _text(body.get("role")), _id(raw.get("parentId"))
    match role:  # noqa: MATCH_OK
        case "user" | "assistant":
            return _parts(body.get("content"), message_id, parent, session_id, role)
        case "toolResult":
            parsed = _parts(body.get("content"), message_id, _id(body.get("toolCallId")) or parent, session_id, "assistant")
            if isinstance(parsed, list):
                return [OmoAcceptedItem(item.item_id, item.session_id, item.parent_id, OmoItemKind.TOOL_OUTCOME, item.text) for item in parsed]
            return parsed
        case _:
            return OmoQuarantineReason.INVALID_FORMAT


def _legacy(event_type: str, raw: JsonObject, session_id: SessionId, line_no: int, last_id: ItemId | None) -> _Parsed:
    item_id, payload = ItemId(f"evt-{line_no}"), _obj(raw.get("payload")) or {}
    match event_type:  # noqa: MATCH_OK
        case "assistant_message":
            text = _text(payload.get("text"))
            return OmoQuarantineReason.INVALID_FORMAT if text is None else [OmoAcceptedItem(item_id, session_id, last_id, OmoItemKind.ASSISTANT_TEXT, text)]
        case "tool_execution":
            name = _text(payload.get("tool"))
            if name is None or not isinstance(payload.get("is_error"), bool):
                return OmoQuarantineReason.INVALID_FORMAT
            status = "error" if payload["is_error"] is True else "ok"
            return [OmoAcceptedItem(item_id, session_id, last_id, _tool_kind(name), f"{name}\t{status}")]
        case _:
            return OmoQuarantineReason.INVALID_FORMAT


def _header(raw: JsonObject) -> tuple[str, SessionId, SessionId | None] | OmoQuarantineReason:
    version, session_id = raw.get("version"), _text(raw.get("id"))
    if _text(raw.get("type")) != "session" or isinstance(version, bool) or not isinstance(version, int) or session_id is None:
        return OmoQuarantineReason.INVALID_FORMAT
    if version not in {1, 3}:
        return OmoQuarantineReason.UNSUPPORTED_VERSION
    parent = _id(raw.get("parentId"))
    export = LEGACY_EXPORT_VERSION if version == 1 else CURRENT_EXPORT_VERSION
    return export, SessionId(session_id), None if parent is None else SessionId(parent)


def _line(line: bytes) -> JsonObject | OmoQuarantineReason:
    stripped = line.strip()
    if not stripped:
        return OmoQuarantineReason.INVALID_FORMAT
    try:
        decoded = json.loads(stripped)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return OmoQuarantineReason.INVALID_FORMAT
    mapped = _obj(decoded)
    return OmoQuarantineReason.INVALID_FORMAT if mapped is None else mapped


def _parse_store(payload: bytes, cursor: OmoCursorV1 | None) -> OmoReadResult:
    lines = tuple(payload.splitlines(keepends=True))
    if not lines:
        return OmoStoreQuarantined(OmoQuarantineReason.INVALID_FORMAT)
    start = 0
    if cursor is not None:
        if cursor.next_line < 1 or cursor.next_line > len(lines) or _digest(lines[: cursor.next_line]) != cursor.prefix_digest:
            return OmoStoreQuarantined(OmoQuarantineReason.SOURCE_MUTATED)
        start = cursor.next_line
    header_raw = _line(lines[0])
    if isinstance(header_raw, OmoQuarantineReason):
        return OmoStoreQuarantined(header_raw)
    header = _header(header_raw)
    if isinstance(header, OmoQuarantineReason):
        return OmoStoreQuarantined(header)
    export_version, session_id, parent_session_id = header
    items: list[OmoAcceptedItem] = []
    last_id: ItemId | None = None
    for index in range(max(start, 1), len(lines)):
        raw = _line(lines[index])
        if isinstance(raw, OmoQuarantineReason):
            return OmoStoreQuarantined(raw)
        event_type = _text(raw.get("type"))
        if event_type is None:
            return OmoStoreQuarantined(OmoQuarantineReason.INVALID_FORMAT)
        if event_type in _DENIED or event_type.startswith("dag."):
            continue
        if event_type not in _ALLOWED:
            return OmoStoreQuarantined(OmoQuarantineReason.UNKNOWN_EVENT)
        parsed = _message(raw, session_id) if event_type == "message" else _legacy(event_type, raw, session_id, index + 1, last_id)
        if isinstance(parsed, OmoQuarantineReason):
            return OmoStoreQuarantined(parsed)
        items.extend(parsed)
        if parsed:
            last_id = parsed[-1].item_id
    return OmoAcceptedScan(export_version, SOURCE_PROFILE, session_id, parent_session_id, tuple(items), OmoCursorV1(len(lines), _digest(lines)))


def _read_local_bytes(path: Path) -> bytes | None:
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > MAX_STORE_BYTES:
            return None
        payload = os.read(fd, info.st_size)
        after = os.fstat(fd)
        return None if len(payload) != info.st_size or after.st_mtime_ns != info.st_mtime_ns or after.st_size != info.st_size else payload
    except OSError:
        return None
    finally:
        os.close(fd)


class OmoSessionAdapter:
    """Read-only OMO/Senpi/pi JSONL decoder. Isolated: not registered or networked."""

    source_profile: Final = SOURCE_PROFILE

    def read(self, store: Path, *, cursor: OmoCursorV1 | None = None, scope_enabled: bool = True) -> OmoReadResult:
        """Parse one explicit local JSONL store, or refuse before I/O when the scope is disabled."""
        if not scope_enabled:
            return OmoScopeDisabled()
        payload = _read_local_bytes(store) if store.is_absolute() else None
        return OmoStoreQuarantined(OmoQuarantineReason.UNREADABLE) if payload is None else _parse_store(payload, cursor)


__all__ = (
    "CURRENT_EXPORT_VERSION",
    "LEGACY_EXPORT_VERSION",
    "SOURCE_PROFILE",
    "ItemId",
    "OmoAcceptedItem",
    "OmoAcceptedScan",
    "OmoCursorV1",
    "OmoItemKind",
    "OmoQuarantineReason",
    "OmoReadResult",
    "OmoScopeDisabled",
    "OmoSessionAdapter",
    "OmoStoreQuarantined",
    "SessionId",
)
