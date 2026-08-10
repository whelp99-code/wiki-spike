"""Claude/Memory Bank fixture connector and typed inert source adapter."""
from __future__ import annotations

from . import FixtureConnectorReader
from .codex import _ReadOnlySourceAdapter


class ClaudeMemoryBankFixtureConnector(FixtureConnectorReader):
    source_profile = "Claude/Memory Bank"
    source_domain = "claude-memory-bank"


class ClaudeMemoryBankLiveSourceAdapter(_ReadOnlySourceAdapter):
    source_profile = "Claude/Memory Bank"


ClaudeMemoryBankSourceReader = ClaudeMemoryBankLiveSourceAdapter


__all__ = ["ClaudeMemoryBankFixtureConnector", "ClaudeMemoryBankLiveSourceAdapter", "ClaudeMemoryBankSourceReader"]
