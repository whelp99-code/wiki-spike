"""Markdown fixture connector and typed inert filesystem source adapter."""
from __future__ import annotations

from . import FixtureConnectorReader
from .codex import _ReadOnlySourceAdapter


class MarkdownFixtureConnector(FixtureConnectorReader):
    source_profile = "Markdown"
    source_domain = "markdown"


class MarkdownLiveSourceAdapter(_ReadOnlySourceAdapter):
    source_profile = "Markdown"
    uses_filesystem = True


MarkdownSourceReader = MarkdownLiveSourceAdapter


__all__ = ["MarkdownFixtureConnector", "MarkdownLiveSourceAdapter", "MarkdownSourceReader"]
