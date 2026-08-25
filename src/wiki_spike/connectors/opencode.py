"""Read-only decoder for an immutable OpenCode messages/parts snapshot."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Final, NewType, assert_never

ItemId = NewType("ItemId", str)
SessionId = NewType("SessionId", str)
Revision = NewType("Revision", str)
type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
type OpenCodeReadResult = OpenCodeAcceptedScan | OpenCodeStoreQuarantined | OpenCodeScopeDisabled

SNAPSHOT_VERSION: Final = "opencode-messages-parts-v1"
SOURCE_PROFILE: Final = "OpenCode"
_MSG_COLS: Final = ("id", "session_id", "time_created", "time_updated", "data")
_PART_COLS: Final = ("id", "message_id", "session_id", "time_created", "time_updated", "data")
_MANIFEST: Final = frozenset({"database", "immutable", "schema", "snapshot_version", "source_profile"})
_LIVE: Final = frozenset({"auth.json", "opencode.db-wal", "opencode.db-shm"})
_FORBIDDEN: Final = frozenset({"access_token", "api_key", "authorization", "credential", "refresh_token", "secret"})


class OpenCodeItemKind(StrEnum):
    USER_TEXT = "user_text"
    ASSISTANT_TEXT = "assistant_text"
    TOOL_OUTCOME = "tool_outcome"


class OpenCodeQuarantineReason(StrEnum):
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    LIVE_STORE = "LIVE_STORE"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    UNREADABLE = "UNREADABLE"
    INVALID_FORMAT = "INVALID_FORMAT"


class _Role(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"


class _PartType(StrEnum):
    TEXT = "text"
    TOOL = "tool"


@dataclass(frozen=True, slots=True)
class OpenCodeCursorV1:
    next_ordinal: int
    prefix_digest: str


@dataclass(frozen=True, slots=True)
class OpenCodeAcceptedItem:
    item_id: ItemId
    session_id: SessionId
    parent_id: ItemId | None
    kind: OpenCodeItemKind
    text: str
    revision: Revision


@dataclass(frozen=True, slots=True)
class OpenCodeAcceptedScan:
    snapshot_version: str
    source_profile: str
    session_id: SessionId
    parent_session_id: SessionId | None
    items: tuple[OpenCodeAcceptedItem, ...]
    cursor: OpenCodeCursorV1


@dataclass(frozen=True, slots=True)
class OpenCodeStoreQuarantined:
    reason: OpenCodeQuarantineReason


@dataclass(frozen=True, slots=True)
class OpenCodeScopeDisabled:
    source_profile: str = SOURCE_PROFILE


class OpenCodeSessionAdapter:
    """Decode a pinned, immutable OpenCode messages/parts snapshot. Isolated: not registered."""

    source_profile: Final = SOURCE_PROFILE
    source_domain: Final = "opencode"

    def read(self, store: Path, *, cursor: OpenCodeCursorV1 | None = None, scope_enabled: bool = True) -> OpenCodeReadResult:
        """Parse one snapshot directory, or refuse before I/O when the scope is disabled."""
        if not scope_enabled:
            return OpenCodeScopeDisabled()
        resolved = _resolve(store)
        match resolved:
            case OpenCodeStoreQuarantined():
                return resolved
            case (database, parent_session_id):
                return _read_database(database, parent_session_id, cursor)
            case unreachable:
                assert_never(unreachable)


def _fail(reason: OpenCodeQuarantineReason) -> OpenCodeStoreQuarantined:
    return OpenCodeStoreQuarantined(reason)


def _resolve(store: Path) -> tuple[Path, SessionId | None] | OpenCodeStoreQuarantined:
    try:
        names = {path.name for path in store.iterdir()} if store.is_dir() else None
    except OSError:
        return _fail(OpenCodeQuarantineReason.UNREADABLE)
    if names is None or names & _LIVE or "snapshot.json" not in names:
        return _fail(OpenCodeQuarantineReason.LIVE_STORE)
    path = store / "snapshot.json"
    if path.is_symlink() or not path.is_file():
        return _fail(OpenCodeQuarantineReason.UNREADABLE)
    try:
        loaded = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return _fail(OpenCodeQuarantineReason.UNREADABLE)
    return _manifest(store, loaded)


def _manifest(store: Path, loaded: JsonValue) -> tuple[Path, SessionId | None] | OpenCodeStoreQuarantined:
    if not isinstance(loaded, dict) or not _MANIFEST <= set(loaded) <= _MANIFEST | {"parent_session_id"}:
        return _fail(OpenCodeQuarantineReason.INVALID_FORMAT)
    if loaded["immutable"] is not True or loaded["source_profile"] != SOURCE_PROFILE:
        return _fail(OpenCodeQuarantineReason.INVALID_FORMAT)
    if loaded["snapshot_version"] != SNAPSHOT_VERSION or not _schema_pinned(loaded["schema"]):
        return _fail(OpenCodeQuarantineReason.UNSUPPORTED_SCHEMA)
    name = loaded["database"]
    if not isinstance(name, str) or "/" in name or name in {".", ".."}:
        return _fail(OpenCodeQuarantineReason.LIVE_STORE)
    database = store / name
    if database.is_symlink() or not database.is_file():
        return _fail(OpenCodeQuarantineReason.UNREADABLE)
    parent = loaded.get("parent_session_id")
    if parent is not None and (not isinstance(parent, str) or not parent):
        return _fail(OpenCodeQuarantineReason.INVALID_FORMAT)
    return database, None if parent is None else SessionId(parent)


def _schema_pinned(raw: JsonValue) -> bool:
    if not isinstance(raw, dict) or set(raw) != {"message", "part"}:
        return False
    return _names(raw["message"]) == _MSG_COLS and _names(raw["part"]) == _PART_COLS


def _names(raw: JsonValue) -> tuple[str, ...] | None:
    if not isinstance(raw, list):
        return None
    names: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            return None
        names.append(item)
    return tuple(names)


def _read_database(database: Path, parent: SessionId | None, cursor: OpenCodeCursorV1 | None) -> OpenCodeReadResult:
    try:
        connection = sqlite3.connect(f"file:{database.resolve().as_posix()}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error:
        return _fail(OpenCodeQuarantineReason.UNREADABLE)
    try:
        if _pragma(connection, "message") != _MSG_COLS or _pragma(connection, "part") != _PART_COLS:
            return _fail(OpenCodeQuarantineReason.UNSUPPORTED_SCHEMA)
        rows = connection.execute("SELECT id, session_id, data FROM message ORDER BY time_created, id").fetchall()
        parts = connection.execute("SELECT id, message_id, session_id, data FROM part ORDER BY time_created, id").fetchall()
    except sqlite3.Error:
        return _fail(OpenCodeQuarantineReason.UNREADABLE)
    finally:
        connection.close()
    messages = _messages(rows)
    if messages is None:
        return _fail(OpenCodeQuarantineReason.INVALID_FORMAT)
    first = next(iter(messages.values()), None)
    if first is None:
        return _fail(OpenCodeQuarantineReason.INVALID_FORMAT)
    items = _items(messages, parts)
    visible = _resume(items, cursor)
    match visible:
        case OpenCodeStoreQuarantined():
            return visible
        case tuple():
            return OpenCodeAcceptedScan(
                SNAPSHOT_VERSION, SOURCE_PROFILE, first[0], parent, visible, OpenCodeCursorV1(len(items), _digest(items))
            )
        case unreachable:
            assert_never(unreachable)


def _pragma(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))


def _messages(rows: Sequence[tuple[str, str, str]]) -> dict[str, tuple[SessionId, _Role]] | None:
    accepted: dict[str, tuple[SessionId, _Role]] = {}
    for message_id, session_id, data in rows:
        if not isinstance(data, str) or not isinstance(message_id, str) or not isinstance(session_id, str):
            return None
        parsed = _object(data)
        if parsed is None:
            return None
        role = None if _blocked(parsed) else _enum(_Role, parsed.get("role"))
        if role is not None:
            accepted[message_id] = (SessionId(session_id), role)
    return accepted


def _items(messages: Mapping[str, tuple[SessionId, _Role]], parts: Sequence[tuple[str, str, str, str]]) -> tuple[OpenCodeAcceptedItem, ...]:
    items: list[OpenCodeAcceptedItem] = []
    parent: ItemId | None = None
    for part_id, message_id, session_id, data in parts:
        if not isinstance(data, str) or not isinstance(part_id, str) or not isinstance(message_id, str) or not isinstance(session_id, str):
            continue
        parsed, bound = _object(data), messages.get(message_id)
        pending = None if parsed is None or bound is None or _blocked(parsed) else _part(part_id, SessionId(session_id), bound[1], parsed)
        if pending is None:
            continue
        items.append(_bind(pending, parent))
        parent = pending[0]
    return tuple(items)


def _part(part_id: str, session_id: SessionId, role: _Role, data: Mapping[str, JsonValue]) -> tuple[ItemId, SessionId, OpenCodeItemKind, str] | None:
    kind = _enum(_PartType, data.get("type"))
    if kind is None:
        return None
    match kind:
        case _PartType.TEXT:
            text = data.get("text")
            if not isinstance(text, str) or not text:
                return None
            match role:
                case _Role.USER:
                    item_kind = OpenCodeItemKind.USER_TEXT
                case _Role.ASSISTANT:
                    item_kind = OpenCodeItemKind.ASSISTANT_TEXT
                case unreachable:
                    assert_never(unreachable)
            return ItemId(part_id), session_id, item_kind, text
        case _PartType.TOOL:
            name, state = data.get("tool"), data.get("state")
            if not isinstance(name, str) or not name or not isinstance(state, dict) or _blocked(state):
                return None
            output = state.get("output")
            if state.get("status") != "completed" or not isinstance(output, str) or not output:
                return None
            return ItemId(part_id), session_id, OpenCodeItemKind.TOOL_OUTCOME, f"{name}\t{output}"
        case unreachable:
            assert_never(unreachable)


def _bind(pending: tuple[ItemId, SessionId, OpenCodeItemKind, str], parent: ItemId | None) -> OpenCodeAcceptedItem:
    item_id, session_id, kind, text = pending
    payload = {"id": item_id, "kind": kind.value, "parent_id": parent, "session_id": session_id, "text": text}
    revision = Revision(sha256(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).hexdigest())
    return OpenCodeAcceptedItem(item_id, session_id, parent, kind, text, revision)


def _resume(items: tuple[OpenCodeAcceptedItem, ...], cursor: OpenCodeCursorV1 | None) -> tuple[OpenCodeAcceptedItem, ...] | OpenCodeStoreQuarantined:
    if cursor is None:
        return items
    prefix = items[: cursor.next_ordinal]
    if cursor.next_ordinal < 0 or cursor.next_ordinal > len(items) or _digest(prefix) != cursor.prefix_digest:
        return _fail(OpenCodeQuarantineReason.SOURCE_MUTATED)
    return items[cursor.next_ordinal :]


def _digest(items: Sequence[OpenCodeAcceptedItem]) -> str:
    hasher = sha256()
    for item in items:
        hasher.update(f"{item.item_id}\0{item.kind.value}\0{item.text}\n".encode())
    return hasher.hexdigest()


def _object(raw: str) -> dict[str, JsonValue] | None:
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _blocked(data: Mapping[str, JsonValue]) -> bool:
    return bool(_FORBIDDEN & set(data))


def _enum[T: StrEnum](cls: type[T], raw: JsonValue) -> T | None:
    if not isinstance(raw, str):
        return None
    try:
        return cls(raw)
    except ValueError:
        return None


__all__ = [
    "SNAPSHOT_VERSION", "SOURCE_PROFILE", "ItemId", "OpenCodeAcceptedItem", "OpenCodeAcceptedScan",
    "OpenCodeCursorV1", "OpenCodeItemKind", "OpenCodeQuarantineReason", "OpenCodeReadResult",
    "OpenCodeScopeDisabled", "OpenCodeSessionAdapter", "OpenCodeStoreQuarantined", "Revision", "SessionId",
]
