"""Typed Codex session adapter plus the Stage-2 fixture connector."""
from __future__ import annotations

from . import FixtureConnectorReader
from .codex_session_jsonl import CodexSessionAdapter
from .codex_session_types import (
    EXPORT_VERSION,
    SOURCE_PROFILE,
    CodexAcceptedItem,
    CodexAcceptedScan,
    CodexCursorV1,
    CodexItemKind,
    CodexQuarantineReason,
    CodexReadResult,
    CodexScopeDisabled,
    CodexStoreQuarantined,
    ItemId,
    Revision,
    SessionId,
)


class CodexFixtureConnector(FixtureConnectorReader):
    """Stage-2 fixture reader for the closed Codex profile."""


setattr(CodexFixtureConnector, "source_profile", "Codex")
setattr(CodexFixtureConnector, "source_domain", "codex")

__all__ = [
    "EXPORT_VERSION",
    "SOURCE_PROFILE",
    "CodexAcceptedItem",
    "CodexAcceptedScan",
    "CodexCursorV1",
    "CodexFixtureConnector",
    "CodexItemKind",
    "CodexQuarantineReason",
    "CodexReadResult",
    "CodexScopeDisabled",
    "CodexSessionAdapter",
    "CodexStoreQuarantined",
    "ItemId",
    "Revision",
    "SessionId",
]
