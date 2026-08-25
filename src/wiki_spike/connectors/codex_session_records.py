"""Typed interpretation of one Codex JSONL record."""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import assert_never

from wiki_spike.connectors.codex_session_types import (
    EXPORT_VERSION,
    SOURCE_PROFILE,
    CodexAcceptedItem,
    CodexItemKind,
    CodexQuarantineReason,
    CodexStoreQuarantined,
    ItemId,
    Revision,
    SessionId,
)

type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]


class _EventType(StrEnum):
    EXPORT_META = "export_meta"
    SESSION_META = "session_meta"
    RESPONSE_ITEM = "response_item"
    EVENT_MSG = "event_msg"
    TURN_CONTEXT = "turn_context"
    WORLD_STATE = "world_state"
    INTER_AGENT = "inter_agent_communication_metadata"
    AUTH = "auth"


class _PayloadType(StrEnum):
    MESSAGE = "message"
    FUNCTION_CALL = "function_call"
    FUNCTION_CALL_OUTPUT = "function_call_output"
    CUSTOM_TOOL_CALL = "custom_tool_call"
    CUSTOM_TOOL_CALL_OUTPUT = "custom_tool_call_output"
    ARTIFACT = "artifact"
    REASONING = "reasoning"


class _Role(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"
    DEVELOPER = "developer"
    SYSTEM = "system"


class _PartType(StrEnum):
    INPUT_TEXT = "input_text"
    OUTPUT_TEXT = "output_text"
    ENCRYPTED_CONTENT = "encrypted_content"


@dataclass(frozen=True, slots=True)
class PendingItem:
    item_id: str
    parent_id: str | None
    kind: CodexItemKind
    text: str


@dataclass(frozen=True, slots=True)
class SessionBound:
    session_id: SessionId
    parent_session_id: SessionId | None


type InterpretedRecord = CodexStoreQuarantined | SessionBound | PendingItem | None


def parse_object(raw: bytes) -> dict[str, JsonValue] | None:
    try:
        loaded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def interpret(index: int, record: Mapping[str, JsonValue]) -> InterpretedRecord:
    raw_type = record.get("type")
    if not isinstance(raw_type, str):
        return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
    try:
        event = _EventType(raw_type)
    except ValueError:
        return None
    match event:
        case _EventType.EXPORT_META:
            return _export_meta(index, record)
        case _EventType.SESSION_META:
            return _session_meta(record.get("payload"))
        case _EventType.RESPONSE_ITEM:
            return _response_item(record.get("payload"))
        case _EventType.AUTH | _EventType.EVENT_MSG | _EventType.TURN_CONTEXT | _EventType.WORLD_STATE | _EventType.INTER_AGENT:
            return None
        case unreachable:
            assert_never(unreachable)


def bind_item(pending: PendingItem, session_id: SessionId) -> CodexAcceptedItem:
    parent = None if pending.parent_id is None else ItemId(pending.parent_id)
    revision = Revision(
        sha256(
            json.dumps(
                {
                    "id": pending.item_id,
                    "kind": pending.kind.value,
                    "parent_id": pending.parent_id,
                    "session_id": session_id,
                    "text": pending.text,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
    )
    return CodexAcceptedItem(ItemId(pending.item_id), session_id, parent, pending.kind, pending.text, revision)


def _export_meta(index: int, record: Mapping[str, JsonValue]) -> CodexStoreQuarantined | None:
    if index != 0:
        return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
    if record.get("export_version") != EXPORT_VERSION:
        return CodexStoreQuarantined(CodexQuarantineReason.UNSUPPORTED_VERSION)
    if record.get("source_profile") != SOURCE_PROFILE:
        return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
    return None


def _session_meta(payload: JsonValue) -> SessionBound | CodexStoreQuarantined:
    if not isinstance(payload, dict):
        return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
    session = payload.get("session_id")
    if not isinstance(session, str) or not session:
        return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
    parent = payload.get("parent_session_id")
    if parent is None:
        parent = payload.get("parent_thread_id")
    if parent is not None and (not isinstance(parent, str) or not parent):
        return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
    return SessionBound(SessionId(session), None if parent is None else SessionId(parent))


def _response_item(payload: JsonValue) -> PendingItem | None:
    if not isinstance(payload, dict) or "encrypted_content" in payload:
        return None
    raw_type = payload.get("type")
    if not isinstance(raw_type, str):
        return None
    try:
        kind = _PayloadType(raw_type)
    except ValueError:
        return None
    match kind:
        case _PayloadType.REASONING:
            return None
        case _PayloadType.MESSAGE:
            return _message(payload)
        case _PayloadType.FUNCTION_CALL:
            return _tool_call(payload, payload.get("arguments"))
        case _PayloadType.CUSTOM_TOOL_CALL:
            return _tool_call(payload, payload.get("input"))
        case _PayloadType.FUNCTION_CALL_OUTPUT | _PayloadType.CUSTOM_TOOL_CALL_OUTPUT:
            return _named(payload, CodexItemKind.TOOL_RESULT, payload.get("output"))
        case _PayloadType.ARTIFACT:
            return _named(payload, CodexItemKind.ARTIFACT, payload.get("text"))
        case unreachable:
            assert_never(unreachable)


def _message(payload: Mapping[str, JsonValue]) -> PendingItem | None:
    raw_role = payload.get("role")
    if not isinstance(raw_role, str):
        return None
    try:
        role = _Role(raw_role)
    except ValueError:
        return None
    match role:
        case _Role.DEVELOPER | _Role.SYSTEM:
            return None
        case _Role.USER:
            kind = CodexItemKind.USER_TEXT
        case _Role.ASSISTANT:
            kind = CodexItemKind.ASSISTANT_TEXT
        case unreachable:
            assert_never(unreachable)
    text = _visible_text(payload.get("content"))
    return None if text is None else _named(payload, kind, text)


def _tool_call(payload: Mapping[str, JsonValue], argument: JsonValue) -> PendingItem | None:
    name = payload.get("name")
    if not isinstance(name, str) or not name or not isinstance(argument, str):
        return None
    return _named(payload, CodexItemKind.TOOL_CALL, f"{name}\t{argument}")


def _named(payload: Mapping[str, JsonValue], kind: CodexItemKind, text: JsonValue) -> PendingItem | None:
    item_id = payload.get("id")
    parent = payload.get("parent_id")
    if not isinstance(item_id, str) or not item_id or not isinstance(text, str):
        return None
    if parent is not None and (not isinstance(parent, str) or not parent):
        return None
    return PendingItem(item_id, parent, kind, text)


def _visible_text(content: JsonValue) -> str | None:
    if not isinstance(content, list):
        return None
    parts: list[str] = []
    for part in content:
        if not isinstance(part, dict):
            return None
        raw_type = part.get("type")
        if not isinstance(raw_type, str):
            return None
        try:
            kind = _PartType(raw_type)
        except ValueError:
            continue
        match kind:
            case _PartType.ENCRYPTED_CONTENT:
                continue
            case _PartType.INPUT_TEXT | _PartType.OUTPUT_TEXT:
                text = part.get("text")
                if not isinstance(text, str):
                    return None
                parts.append(text)
            case unreachable:
                assert_never(unreachable)
    return None if not parts else "\n".join(parts)
