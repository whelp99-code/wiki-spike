"""Installed deletion-state schema is packaged, not repo-root relative."""
from __future__ import annotations

from pathlib import Path

from wiki_spike.resources import load_deletion_state_schema_bytes

_COMMITTED = (
    Path(__file__).resolve().parents[2]
    / "schemas/encrypted-lifecycle/deletion-state-v1.schema.json"
)


def test_packaged_deletion_state_schema_matches_committed_bytes() -> None:
    packaged = load_deletion_state_schema_bytes()
    assert packaged == _COMMITTED.read_bytes()
    assert b"wiki-deletion-state-v1" in packaged or b"type" in packaged
