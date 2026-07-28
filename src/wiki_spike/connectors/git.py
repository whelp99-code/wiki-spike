"""Fixture-only connector for the closed Git source profile."""
from __future__ import annotations

from . import FixtureConnectorReader


class GitFixtureConnector(FixtureConnectorReader):
    source_profile = "Git"
    source_domain = "git"


__all__ = ["GitFixtureConnector"]
