"""Fixture-only connector for the closed Claude/Memory Bank source profile."""
from __future__ import annotations

from . import FixtureConnectorReader


class ClaudeMemoryBankFixtureConnector(FixtureConnectorReader):
    source_profile = "Claude/Memory Bank"
    source_domain = "claude-memory-bank"


__all__ = ["ClaudeMemoryBankFixtureConnector"]
