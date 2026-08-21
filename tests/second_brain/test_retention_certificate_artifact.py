"""Tracked retention schedule is non-destructive and does not delete sources."""
from __future__ import annotations

from pathlib import Path

from wiki_spike.memory_core.unified_db_snapshot_export_json import (
    decode_json_object,
)

_ROOT = Path(__file__).resolve().parents[2]
_CERT = (
    _ROOT
    / "artifacts/product-release/second-brain-v1/retention/retention-certificate-v1.json"
)


def test_tracked_retention_certificate_is_non_destructive() -> None:
    payload = decode_json_object(_CERT.read_text(encoding="utf-8"))
    assert payload["destructive_action_authorized"] == "false"
    assert payload["source_deletion_authorized"] == "false"
    assert payload["key_deletion_authorized"] == "false"
    assert payload["retention_hours"] == "2160"
    assert isinstance(payload["retention_hours"], str)
    assert "signatures" not in payload
    assert payload["certificate_kind"] == "second-brain-retention-certificate-v1"


def test_certificate_contains_no_source_deletion_target() -> None:
    payload = decode_json_object(_CERT.read_text(encoding="utf-8"))
    assert "source_path" not in payload
    assert "source_root" not in payload
    assert "/Volumes/DevSpace/me-wiki" not in _CERT.read_text(encoding="utf-8")
