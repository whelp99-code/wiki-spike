"""Read-only decoder for versioned Claude project JSONL."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final, assert_never

from wiki_spike.connectors.claude_memory_bank_models import (
    EXPORT_VERSION,
    SOURCE_PROFILE,
    ClaudeAcceptedItem,
    ClaudeAcceptedScan,
    ClaudeCitationV1,
    ClaudeCursorV1,
    ClaudeItemKind,
    ClaudeQuarantineReason,
    ClaudeReadResult,
    ItemId,
    JsonNode,
    ProjectId,
    SessionId,
    json_text,
    memory_citation,
    quarantine,
    with_tombstones,
)

_DENIED: Final = frozenset({"auth", "cookie", "credentials", "private_config", "system", "thinking"})
_OPEN_FLAGS: Final = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_MAX_BYTES: Final = 67_108_864


@dataclass(frozen=True, slots=True)
class _Meta:
    project_id: ProjectId | None = None
    session_id: SessionId | None = None


type _LineResult = ClaudeAcceptedItem | ClaudeQuarantineReason | _Meta | None


def read_export_bytes(path: Path) -> bytes | None:
    """Read a regular file without following links or writing."""
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > _MAX_BYTES:
            return None
        return os.read(fd, info.st_size)
    except OSError:
        return None
    finally:
        os.close(fd)


def load_object(line: str) -> dict[str, JsonNode] | None:
    try:
        loaded: JsonNode = json.loads(line)
    except json.JSONDecodeError:
        return None
    if isinstance(loaded, dict) and all(isinstance(key, str) for key in loaded):
        return loaded
    return None


def prefix_digest(raw: bytes, next_line: int) -> str:
    if next_line <= 0:
        return sha256(b"").hexdigest()
    consumed = 0
    offset = 0
    while consumed < next_line:
        idx = raw.find(b"\n", offset)
        if idx < 0:
            return sha256(raw).hexdigest() if consumed + 1 == next_line else ""
        offset = idx + 1
        consumed += 1
    return sha256(raw[:offset]).hexdigest()


def decode_jsonl_file(path: Path, cursor: ClaudeCursorV1 | None, previous: tuple[ItemId, ...]) -> ClaudeReadResult:
    raw = read_export_bytes(path)
    return quarantine(ClaudeQuarantineReason.INVALID_FORMAT) if raw is None else decode_jsonl(raw, cursor, previous)


def decode_jsonl(raw: bytes, cursor: ClaudeCursorV1 | None, previous: tuple[ItemId, ...]) -> ClaudeReadResult:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    start = 0 if cursor is None else cursor.next_line
    if cursor is not None and (start < 0 or start > len(lines) or prefix_digest(raw, start) != cursor.prefix_digest):
        return quarantine(ClaudeQuarantineReason.SOURCE_MUTATED)
    project_id: ProjectId | None = None
    session_id: SessionId | None = None
    items: list[ClaudeAcceptedItem] = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        parsed = _parse_record(line, project_id, session_id)
        match parsed:
            case ClaudeQuarantineReason() as reason:
                return quarantine(reason)
            case _Meta(project_id=meta_project, session_id=meta_session):
                project_id = meta_project or project_id
                session_id = meta_session or session_id
            case ClaudeAcceptedItem() as item:
                if index >= start:
                    items.append(item)
            case None:
                continue
            case unreachable:
                assert_never(unreachable)
    if project_id is None:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    accepted = items if cursor is not None else list(with_tombstones(items, previous, (project_id, session_id)))
    return ClaudeAcceptedScan(
        EXPORT_VERSION,
        SOURCE_PROFILE,
        project_id,
        session_id,
        tuple(accepted),
        ClaudeCursorV1(len(lines), prefix_digest(raw, len(lines))),
    )


def _parse_record(line: str, project_id: ProjectId | None, session_id: SessionId | None) -> _LineResult:
    raw = load_object(line)
    if raw is None:
        return ClaudeQuarantineReason.INVALID_FORMAT
    record_type = raw.get("type")
    if not isinstance(record_type, str):
        return ClaudeQuarantineReason.INVALID_FORMAT
    if record_type in _DENIED:
        return None
    match record_type:  # noqa: MATCH_OK — open wire tag; unknown types quarantine
        case "export_meta":
            return _parse_export_meta(raw)
        case "project_meta":
            project = json_text(raw.get("project_id"))
            return _Meta(ProjectId(project)) if project else ClaudeQuarantineReason.INVALID_FORMAT
        case "session_meta":
            session = json_text(raw.get("session_id"))
            return _Meta(session_id=SessionId(session)) if session else ClaudeQuarantineReason.INVALID_FORMAT
        case "message" | "tool_use" | "tool_result":
            return _parse_visible(record_type, raw, _Meta(project_id, session_id))
        case _:
            return ClaudeQuarantineReason.INVALID_FORMAT


def _parse_export_meta(raw: dict[str, JsonNode]) -> _LineResult:
    version = raw.get("export_version")
    if not isinstance(version, str):
        return ClaudeQuarantineReason.INVALID_FORMAT
    if version != EXPORT_VERSION:
        return ClaudeQuarantineReason.UNSUPPORTED_VERSION
    if raw.get("source_profile") != SOURCE_PROFILE:
        return ClaudeQuarantineReason.INVALID_FORMAT
    return _Meta()


def _parse_visible(record_type: str, raw: dict[str, JsonNode], meta: _Meta) -> _LineResult:
    project_id = meta.project_id
    session_id = meta.session_id
    if project_id is None or session_id is None:
        return ClaudeQuarantineReason.INVALID_FORMAT
    item_id = json_text(raw.get("id"))
    parent = raw.get("parent_id")
    parent_id = None if parent is None else json_text(parent)
    if item_id is None or (parent is not None and parent_id is None):
        return ClaudeQuarantineReason.INVALID_FORMAT
    parsed = _visible_payload(record_type, raw, project_id)
    match parsed:
        case ClaudeQuarantineReason() as reason:
            return reason
        case tuple() as payload:
            kind, text, citations = payload
        case unreachable:
            assert_never(unreachable)
    return ClaudeAcceptedItem(
        ItemId(item_id),
        project_id,
        session_id,
        None,
        None if parent_id is None else ItemId(parent_id),
        kind,
        text,
        sha256(text.encode()).hexdigest(),
        False,
        citations,
    )


def _visible_payload(
    record_type: str, raw: dict[str, JsonNode], project_id: ProjectId
) -> tuple[ClaudeItemKind, str, tuple[ClaudeCitationV1, ...]] | ClaudeQuarantineReason:
    match record_type:  # noqa: MATCH_OK — closed by caller
        case "message":
            return _message_payload(raw, project_id)
        case "tool_use":
            name = json_text(raw.get("name"))
            payload = _tool_input(raw.get("input"))
            if name is None or payload is None:
                return ClaudeQuarantineReason.INVALID_FORMAT
            return ClaudeItemKind.TOOL_CALL, f"{name}\t{payload}", ()
        case "tool_result":
            output = json_text(raw.get("output"))
            if output is None:
                return ClaudeQuarantineReason.INVALID_FORMAT
            return ClaudeItemKind.TOOL_RESULT, output, ()
        case _:
            return ClaudeQuarantineReason.INVALID_FORMAT


def _message_payload(
    raw: dict[str, JsonNode], project_id: ProjectId
) -> tuple[ClaudeItemKind, str, tuple[ClaudeCitationV1, ...]] | ClaudeQuarantineReason:
    role = raw.get("role")
    text = json_text(raw.get("text"))
    if text is None:
        return ClaudeQuarantineReason.INVALID_FORMAT
    match role:  # noqa: MATCH_OK — open wire role; unknown values quarantine
        case "user":
            kind = ClaudeItemKind.USER_TEXT
        case "assistant":
            kind = ClaudeItemKind.ASSISTANT_TEXT
        case "system":
            return ClaudeQuarantineReason.INVALID_FORMAT
        case _:
            return ClaudeQuarantineReason.INVALID_FORMAT
    citations = _message_citations(raw.get("citations"), project_id)
    if citations is None:
        return ClaudeQuarantineReason.INVALID_FORMAT
    return kind, text, citations


def _message_citations(value: JsonNode | None, project_id: ProjectId) -> tuple[ClaudeCitationV1, ...] | None:
    if value is None:
        return ()
    if not isinstance(value, list):
        return None
    citations: list[ClaudeCitationV1] = []
    for item in value:
        memory_id = json_text(item)
        if memory_id is None:
            return None
        citations.append(memory_citation(project_id, memory_id))
    return tuple(citations)


def _tool_input(value: JsonNode | None) -> str | None:
    if isinstance(value, str) and value and "\x00" not in value:
        return value
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    return None


__all__ = ["decode_jsonl", "decode_jsonl_file", "load_object", "prefix_digest", "read_export_bytes"]
