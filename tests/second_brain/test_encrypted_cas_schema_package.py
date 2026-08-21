"""Installed Encrypted CAS envelope schema is packaged, not repo-root relative."""
from __future__ import annotations

from pathlib import Path

from wiki_spike.resources import load_encrypted_cas_envelope_schema_bytes

_COMMITTED = (
    Path(__file__).resolve().parents[2]
    / "schemas/encrypted-lifecycle/envelope-v1.schema.json"
)


def test_packaged_envelope_schema_matches_committed_bytes() -> None:
    packaged = load_encrypted_cas_envelope_schema_bytes()
    assert packaged == _COMMITTED.read_bytes()
    assert b'"$id"' in packaged or b'"type"' in packaged
