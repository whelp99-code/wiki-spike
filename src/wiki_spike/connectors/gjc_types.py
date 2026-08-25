"""Public contracts for GJC session/export decoding."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NewType

ItemId = NewType("ItemId", str)
SessionId = NewType("SessionId", str)

EXPORT_VERSION: Final = "gjc-public-session-v1"
SOURCE_PROFILE: Final = "GJC"


class GjcItemKind(StrEnum):
    USER_TEXT = "user_text"
    ASSISTANT_TEXT = "assistant_text"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    ARTIFACT = "artifact"


class GjcQuarantineReason(StrEnum):
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    INVALID_FORMAT = "INVALID_FORMAT"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    PRIVATE_STATE = "PRIVATE_STATE"
    LIVE_SESSION_STORE = "LIVE_SESSION_STORE"
    UNREADABLE = "UNREADABLE"


@dataclass(frozen=True, slots=True)
class GjcCursorV1:
    next_line: int
    prefix_digest: str


@dataclass(frozen=True, slots=True)
class GjcAcceptedItem:
    item_id: ItemId
    session_id: SessionId
    parent_id: ItemId | None
    kind: GjcItemKind
    text: str
    revision: str


@dataclass(frozen=True, slots=True)
class GjcAcceptedScan:
    export_version: str
    source_profile: str
    session_id: SessionId
    parent_session_id: SessionId | None
    items: tuple[GjcAcceptedItem, ...]
    cursor: GjcCursorV1


@dataclass(frozen=True, slots=True)
class GjcStoreQuarantined:
    reason: GjcQuarantineReason


@dataclass(frozen=True, slots=True)
class GjcScopeDisabled:
    source_profile: str = SOURCE_PROFILE


type GjcReadResult = GjcAcceptedScan | GjcStoreQuarantined | GjcScopeDisabled
