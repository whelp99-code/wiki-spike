"""Owner-approved DB-01 GO body binds fixture evidence before role signing."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.second_brain_decision import BODY_FIELDS
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import (
    DECISION_SIGNING_DOMAIN,
    DecisionRecordV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_ROOT = Path(__file__).resolve().parents[2]
_BODY = (
    _ROOT / "artifacts/product-release/second-brain-v1/decision-signing/DB-01.body.json"
)
_BUNDLE = (
    _ROOT
    / "artifacts/product-release/second-brain-v1/evidence"
    / "db-01-identity-auth-evidence-bundle-v1.json"
)
_DECISIONS = _ROOT / "artifacts/product-release/second-brain-v1/decisions"
_FORBIDDEN = ("BEGIN ", "PRIVATE KEY", "private_key", "signature_b64")


def _load(path: Path) -> dict[str, JsonValue]:
    return decode_json_object(path.read_text(encoding="utf-8"))


def test_unsigned_body_binds_owner_approved_go_without_signatures() -> None:
    raw = _BODY.read_bytes()
    body = _load(_BODY)
    assert raw == canonical_bytes(body) + b"\n"
    assert set(body) == set(BODY_FIELDS)
    assert "signatures" not in body
    assert body["decision_id"] == "DB-01"
    assert body["scope_kind"] == "global"
    assert body["scope_name"] is None
    assert body["evidence_digest"] == sha256(_BUNDLE.read_bytes()).hexdigest()
    assert body["evidence_refs"] == [_BUNDLE.relative_to(_ROOT).as_posix()]
    assert body["decided_at"] == "2026-08-21T22:18:10Z"
    assert body["expires_at"] == "2027-08-21T22:18:10Z"
    assert body["outcome"] == "GO"
    serialized = json.dumps(body, sort_keys=True)
    assert '"outcome": "GO"' in serialized
    assert '"outcome":"GO"' in raw.decode("utf-8")
    for token in _FORBIDDEN:
        assert token not in serialized
        assert token.encode("ascii") not in raw
    with pytest.raises(InvalidContractValue):
        _ = DecisionRecordV1.from_mapping(body)


def test_signed_owner_approved_record_is_authority() -> None:
    assert _BODY.parent.name == "decision-signing"
    record = DecisionRecordV1.from_mapping(_load(_DECISIONS / "DB-01.json"))
    assert record.decision_id == "DB-01"
    assert record.outcome == "GO"
    assert tuple(signature.role for signature in record.signatures) == (
        "approver",
        "owner",
    )
    assert all(
        signature.verify(DECISION_SIGNING_DOMAIN, record.signing_payload())
        for signature in record.signatures
    )
