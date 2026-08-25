"""Public value objects for the Codex session adapter."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NewType

ItemId = NewType("ItemId", str)
SessionId = NewType("SessionId", str)
Revision = NewType("Revision", str)

EXPORT_VERSION: Final = "codex-session-jsonl-v1"
SOURCE_PROFILE: Final = "Codex"


class CodexItemKind(StrEnum):
    USER_TEXT = "user_text"
    ASSISTANT_TEXT = "assistant_text"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    ARTIFACT = "artifact"


class CodexQuarantineReason(StrEnum):
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    INVALID_FORMAT = "INVALID_FORMAT"
    LIVE_AUTH_STORE = "LIVE_AUTH_STORE"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    UNREADABLE = "UNREADABLE"


@dataclass(frozen=True, slots=True)
class CodexCursorV1:
    file_name: str
    next_line: int
    prefix_digest: str


@dataclass(frozen=True, slots=True)
class CodexAcceptedItem:
    item_id: ItemId
    session_id: SessionId
    parent_id: ItemId | None
    kind: CodexItemKind
    text: str
    revision: Revision


@dataclass(frozen=True, slots=True)
class CodexAcceptedScan:
    export_version: str
    source_profile: str
    session_id: SessionId
    parent_session_id: SessionId | None
    items: tuple[CodexAcceptedItem, ...]
    cursor: CodexCursorV1


@dataclass(frozen=True, slots=True)
class CodexStoreQuarantined:
    reason: CodexQuarantineReason


@dataclass(frozen=True, slots=True)
class CodexScopeDisabled:
    source_profile: str = SOURCE_PROFILE


type CodexReadResult = CodexAcceptedScan | CodexStoreQuarantined | CodexScopeDisabled

__all__ = [
    "EXPORT_VERSION",
    "SOURCE_PROFILE",
    "CodexAcceptedItem",
    "CodexAcceptedScan",
    "CodexCursorV1",
    "CodexItemKind",
    "CodexQuarantineReason",
    "CodexReadResult",
    "CodexScopeDisabled",
    "CodexStoreQuarantined",
    "ItemId",
    "Revision",
    "SessionId",
]
