"""Tracked retention schedule is non-destructive and does not delete sources."""
from __future__ import annotations

import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_CERT = (
    _ROOT
    / "artifacts/product-release/second-brain-v1/retention/retention-certificate-v1.json"
)
_ME_WIKI = Path("/Volumes/DevSpace/me-wiki")


def test_tracked_retention_certificate_is_non_destructive() -> None:
    payload = json.loads(_CERT.read_text(encoding="utf-8"))
    assert payload["destructive_action_authorized"] == "false"
    assert payload["source_deletion_authorized"] == "false"
    assert payload["key_deletion_authorized"] == "false"
    assert payload["retention_hours"] == "2160"
    assert isinstance(payload["retention_hours"], str)
    assert "signatures" not in payload
    assert payload["certificate_kind"] == "second-brain-retention-certificate-v1"


def test_me_wiki_source_was_not_deleted_by_retention_certificate() -> None:
    assert _ME_WIKI.is_dir()
    assert not _ME_WIKI.is_symlink()
