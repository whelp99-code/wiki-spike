"""Fixture-only connector for the closed Markdown source profile."""
from __future__ import annotations

from . import FixtureConnectorReader


class MarkdownFixtureConnector(FixtureConnectorReader):
    source_profile = "Markdown"
    source_domain = "markdown"


__all__ = ["MarkdownFixtureConnector"]
