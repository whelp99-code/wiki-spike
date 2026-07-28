"""Fixture-only connector for the closed Codex source profile."""
from __future__ import annotations

from . import FixtureConnectorReader


class CodexFixtureConnector(FixtureConnectorReader):
    source_profile = "Codex"
    source_domain = "codex"


__all__ = ["CodexFixtureConnector"]
