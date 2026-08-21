"""Installed StateDelta schema is packaged, not repo-root relative."""
from __future__ import annotations

from pathlib import Path

from wiki_spike.resources import load_state_delta_schema_bytes

_COMMITTED = (
    Path(__file__).resolve().parents[2]
    / "schemas/encrypted-lifecycle/state-delta-v1.schema.json"
)


def test_packaged_state_delta_schema_matches_committed_bytes() -> None:
    packaged = load_state_delta_schema_bytes()
    assert packaged == _COMMITTED.read_bytes()
    assert b"type" in packaged
