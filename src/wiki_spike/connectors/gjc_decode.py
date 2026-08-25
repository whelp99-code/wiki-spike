"""Parse GJC public-export JSONL into typed scan or quarantine outcomes."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from typing import assert_never

from wiki_spike.connectors.gjc_types import (
    EXPORT_VERSION,
    SOURCE_PROFILE,
    GjcAcceptedItem,
    GjcAcceptedScan,
    GjcCursorV1,
    GjcItemKind,
    GjcQuarantineReason,
    GjcReadResult,
    GjcStoreQuarantined,
    ItemId,
    SessionId,
)

type JsonNode = str | int | float | bool | None | list[JsonNode] | dict[str, JsonNode]
type _LineResult = GjcAcceptedItem | GjcQuarantineReason | None
type _HeaderResult = tuple[SessionId, SessionId | None] | GjcStoreQuarantined

_FORBIDDEN_FIELDS = frozenset({
    "access_token", "api_key", "auth", "credential", "encrypted_content",
    "hidden_reasoning", "provider", "provider_payload", "system_prompt", "thinking",
})
_DENIED_TYPES = frozenset({"auth", "hidden_reasoning", "provider", "reasoning", "system", "thinking"})
_CONVERSATION_FIELDS = frozenset({"id", "parent_id", "role", "text", "type"})
_TOOL_CALL_FIELDS = frozenset({"arguments", "id", "name", "parent_id", "phase", "type"})
_TOOL_RESULT_FIELDS = frozenset({"id", "parent_id", "phase", "text", "type"})
_ARTIFACT_FIELDS = frozenset({"id", "name", "parent_id", "text", "type"})


def _text(value: JsonNode) -> str | None:
    if isinstance(value, str) and value and "\x00" not in value:
        return value
    return None


def _parent_id(value: JsonNode) -> ItemId | None | GjcQuarantineReason:
    if value is None:
        return None
    text = _text(value)
    return GjcQuarantineReason.INVALID_FORMAT if text is None else ItemId(text)


def _cursor_mutated(lines: tuple[str, ...], cursor: GjcCursorV1) -> GjcStoreQuarantined | None:
    if cursor.next_line < 0 or cursor.next_line > len(lines):
        return GjcStoreQuarantined(GjcQuarantineReason.SOURCE_MUTATED)
    prefix = "".join(lines[: cursor.next_line]).encode("utf-8")
    if sha256(prefix).hexdigest() != cursor.prefix_digest:
        return GjcStoreQuarantined(GjcQuarantineReason.SOURCE_MUTATED)
    return None


def _header(lines: tuple[str, ...]) -> _HeaderResult:
    seen: list[dict[str, JsonNode]] = []
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
            return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
        seen.append(value)
        if len(seen) == 2:
            break
    if not seen:
        return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
    first = seen[0]
    if first.get("type") != "export_meta":
        return GjcStoreQuarantined(GjcQuarantineReason.LIVE_SESSION_STORE)
    version = first.get("export_version")
    if not isinstance(version, str):
        return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
    if version != EXPORT_VERSION:
        return GjcStoreQuarantined(GjcQuarantineReason.UNSUPPORTED_VERSION)
    if set(first) != {"export_version", "source_profile", "type"} or first.get("source_profile") != SOURCE_PROFILE:
        return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
    if len(seen) < 2:
        return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
    second = seen[1]
    keys = set(second)
    session_id = _text(second.get("session_id"))
    if second.get("type") != "session_meta" or session_id is None or "session_id" not in keys:
        return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
    if keys - {"parent_session_id", "session_id", "type"}:
        return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
    parent_raw = second.get("parent_session_id") if "parent_session_id" in keys else None
    if parent_raw is None:
        return SessionId(session_id), None
    parent = _text(parent_raw)
    if parent is None:
        return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
    return SessionId(session_id), SessionId(parent)


def _conversation(raw: Mapping[str, JsonNode], session_id: SessionId) -> _LineResult:
    if set(raw) != _CONVERSATION_FIELDS:
        return GjcQuarantineReason.INVALID_FORMAT
    item_id = _text(raw["id"])
    text = _text(raw["text"])
    parent = _parent_id(raw["parent_id"])
    if item_id is None or text is None:
        return GjcQuarantineReason.INVALID_FORMAT
    match parent:
        case GjcQuarantineReason():
            return GjcQuarantineReason.INVALID_FORMAT
        case None | str() as bound:
            pass
        case unreachable:
            assert_never(unreachable)
    match raw["role"]:  # noqa: MATCH_OK
        case "user":
            return GjcAcceptedItem(ItemId(item_id), session_id, bound, GjcItemKind.USER_TEXT, text, item_id)
        case "assistant":
            return GjcAcceptedItem(ItemId(item_id), session_id, bound, GjcItemKind.ASSISTANT_TEXT, text, item_id)
        case "developer" | "system":
            return None
        case _:
            return GjcQuarantineReason.INVALID_FORMAT


def _tool(raw: Mapping[str, JsonNode], session_id: SessionId) -> _LineResult:
    item_id = _text(raw.get("id"))
    parent = _parent_id(raw.get("parent_id"))
    if item_id is None:
        return GjcQuarantineReason.INVALID_FORMAT
    match parent:
        case GjcQuarantineReason():
            return GjcQuarantineReason.INVALID_FORMAT
        case None | str() as bound:
            pass
        case unreachable:
            assert_never(unreachable)
    match raw.get("phase"):  # noqa: MATCH_OK
        case "call":
            name = _text(raw.get("name"))
            arguments = _text(raw.get("arguments"))
            if name is None or arguments is None or set(raw) != _TOOL_CALL_FIELDS:
                return GjcQuarantineReason.INVALID_FORMAT
            return GjcAcceptedItem(ItemId(item_id), session_id, bound, GjcItemKind.TOOL_CALL, f"{name}\t{arguments}", item_id)
        case "result":
            text = _text(raw.get("text"))
            if text is None or set(raw) != _TOOL_RESULT_FIELDS:
                return GjcQuarantineReason.INVALID_FORMAT
            return GjcAcceptedItem(ItemId(item_id), session_id, bound, GjcItemKind.TOOL_RESULT, text, item_id)
        case _:
            return GjcQuarantineReason.INVALID_FORMAT


def _artifact(raw: Mapping[str, JsonNode], session_id: SessionId) -> _LineResult:
    if set(raw) != _ARTIFACT_FIELDS:
        return GjcQuarantineReason.INVALID_FORMAT
    item_id = _text(raw["id"])
    text = _text(raw["text"])
    parent = _parent_id(raw["parent_id"])
    if item_id is None or text is None or _text(raw["name"]) is None:
        return GjcQuarantineReason.INVALID_FORMAT
    match parent:
        case GjcQuarantineReason():
            return GjcQuarantineReason.INVALID_FORMAT
        case None | str() as bound:
            return GjcAcceptedItem(ItemId(item_id), session_id, bound, GjcItemKind.ARTIFACT, text, item_id)
        case unreachable:
            assert_never(unreachable)


def _parse_line(raw: JsonNode, session_id: SessionId) -> _LineResult:
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        return GjcQuarantineReason.INVALID_FORMAT
    record_type = raw.get("type")
    if not isinstance(record_type, str):
        return GjcQuarantineReason.INVALID_FORMAT
    if record_type in _DENIED_TYPES or set(raw) & _FORBIDDEN_FIELDS:
        return None
    match record_type:  # noqa: MATCH_OK
        case "export_meta" | "session_meta":
            return None
        case "conversation":
            return _conversation(raw, session_id)
        case "tool":
            return _tool(raw, session_id)
        case "artifact":
            return _artifact(raw, session_id)
        case _:
            return GjcQuarantineReason.INVALID_FORMAT


def parse_gjc_export(payload: bytes, cursor: GjcCursorV1 | None) -> GjcReadResult:
    """Decode one public GJC export body. Caller already classified the path."""
    try:
        lines = tuple(payload.decode("utf-8").splitlines(keepends=True))
    except UnicodeDecodeError:
        return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
    if cursor is not None:
        mutated = _cursor_mutated(lines, cursor)
        if mutated is not None:
            return mutated
        start = cursor.next_line
    else:
        start = 0
    header = _header(lines)
    match header:
        case GjcStoreQuarantined():
            return header
        case (session_id, parent_session_id):
            pass
        case unreachable:
            assert_never(unreachable)
    items: list[GjcAcceptedItem] = []
    for index, line in enumerate(lines):
        raw = line.strip()
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return GjcStoreQuarantined(GjcQuarantineReason.INVALID_FORMAT)
        parsed = _parse_line(value, session_id)
        match parsed:
            case None:
                continue
            case GjcQuarantineReason() as reason:
                return GjcStoreQuarantined(reason)
            case GjcAcceptedItem() as item:
                if index >= start:
                    items.append(item)
            case unreachable:
                assert_never(unreachable)
    return GjcAcceptedScan(
        EXPORT_VERSION,
        SOURCE_PROFILE,
        session_id,
        parent_session_id,
        tuple(items),
        GjcCursorV1(len(lines), sha256(payload).hexdigest()),
    )
