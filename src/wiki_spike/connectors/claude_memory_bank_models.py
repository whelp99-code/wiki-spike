"""Typed Claude/Memory Bank scan records and closed identities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NewType

ItemId = NewType("ItemId", str)
MemoryId = NewType("MemoryId", str)
ProjectId = NewType("ProjectId", str)
SessionId = NewType("SessionId", str)
type JsonNode = str | int | float | bool | None | list[JsonNode] | dict[str, JsonNode]

EXPORT_VERSION: Final = "claude-project-jsonl-v1"
MEMORY_BANK_VERSION: Final = "claude-memory-bank-md-v1"
SOURCE_PROFILE: Final = "Claude/Memory Bank"


class ClaudeItemKind(StrEnum):
    USER_TEXT = "user_text"
    ASSISTANT_TEXT = "assistant_text"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    MEMORY = "memory"


class ClaudeQuarantineReason(StrEnum):
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    LIVE_AUTH_STORE = "LIVE_AUTH_STORE"
    INVALID_FORMAT = "INVALID_FORMAT"


@dataclass(frozen=True, slots=True)
class ClaudeCitationV1:
    citation_ref: str
    project_id: ProjectId
    session_id: SessionId | None
    memory_id: MemoryId | None
    item_id: ItemId
    locator: str


@dataclass(frozen=True, slots=True)
class ClaudeCursorV1:
    next_line: int
    prefix_digest: str


@dataclass(frozen=True, slots=True)
class ClaudeAcceptedItem:
    item_id: ItemId
    project_id: ProjectId
    session_id: SessionId | None
    memory_id: MemoryId | None
    parent_id: ItemId | None
    kind: ClaudeItemKind
    text: str
    revision: str
    tombstone: bool
    citations: tuple[ClaudeCitationV1, ...]


@dataclass(frozen=True, slots=True)
class ClaudeAcceptedScan:
    export_version: str
    source_profile: str
    project_id: ProjectId
    session_id: SessionId | None
    items: tuple[ClaudeAcceptedItem, ...]
    cursor: ClaudeCursorV1


@dataclass(frozen=True, slots=True)
class ClaudeStoreQuarantined:
    reason: ClaudeQuarantineReason


@dataclass(frozen=True, slots=True)
class ClaudeScopeDisabled:
    source_profile: str = SOURCE_PROFILE


type ClaudeReadResult = ClaudeAcceptedScan | ClaudeStoreQuarantined | ClaudeScopeDisabled


def quarantine(reason: ClaudeQuarantineReason) -> ClaudeStoreQuarantined:
    return ClaudeStoreQuarantined(reason)


def json_text(value: JsonNode | None) -> str | None:
    if isinstance(value, str) and value and "\x00" not in value:
        return value
    return None


def memory_citation(project_id: ProjectId, memory_id: str) -> ClaudeCitationV1:
    locator = f"project/{project_id}/memory/{memory_id}"
    return ClaudeCitationV1(f"cite:{locator}", project_id, None, MemoryId(memory_id), ItemId(memory_id), locator)


def tombstone_item(item_id: ItemId, project_id: ProjectId, session_id: SessionId | None) -> ClaudeAcceptedItem:
    return ClaudeAcceptedItem(item_id, project_id, session_id, None, None, ClaudeItemKind.USER_TEXT, "", "", True, ())


def with_tombstones(
    items: list[ClaudeAcceptedItem],
    previous: tuple[ItemId, ...],
    identity: tuple[ProjectId, SessionId | None],
) -> tuple[ClaudeAcceptedItem, ...]:
    project_id, session_id = identity
    present = {item.item_id for item in items}
    extra = (
        tombstone_item(item_id, project_id, session_id)
        for item_id in previous
        if item_id not in present
    )
    return (*items, *extra)


__all__ = [
    "EXPORT_VERSION",
    "MEMORY_BANK_VERSION",
    "SOURCE_PROFILE",
    "ClaudeAcceptedItem",
    "ClaudeAcceptedScan",
    "ClaudeCitationV1",
    "ClaudeCursorV1",
    "ClaudeItemKind",
    "ClaudeQuarantineReason",
    "ClaudeReadResult",
    "ClaudeScopeDisabled",
    "ClaudeStoreQuarantined",
    "ItemId",
    "JsonNode",
    "MemoryId",
    "ProjectId",
    "SessionId",
    "json_text",
    "memory_citation",
    "quarantine",
    "tombstone_item",
    "with_tombstones",
]
