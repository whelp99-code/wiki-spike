"""Git fixture connector and typed inert filesystem source adapter."""
from __future__ import annotations

from . import FixtureConnectorReader
from .codex import _ReadOnlySourceAdapter


class GitFixtureConnector(FixtureConnectorReader):
    source_profile = "Git"
    source_domain = "git"


class GitLiveSourceAdapter(_ReadOnlySourceAdapter):
    source_profile = "Git"
    uses_filesystem = True


GitSourceReader = GitLiveSourceAdapter


__all__ = ["GitFixtureConnector", "GitLiveSourceAdapter", "GitSourceReader"]
