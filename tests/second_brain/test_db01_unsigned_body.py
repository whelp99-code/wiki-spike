"""Unsigned DB-01 body binds fixture evidence without GO or signatures."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.second_brain_decision import BODY_FIELDS
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import DecisionRecordV1

_ROOT = Path(__file__).resolve().parents[2]
_BODY = (
    _ROOT
    / "artifacts/product-release/second-brain-v1/decision-signing/DB-01.body.json"
)
_BUNDLE = (
    _ROOT
    / "artifacts/product-release/second-brain-v1/evidence"
    / "db-01-identity-auth-evidence-bundle-v1.json"
)
_DECISIONS = _ROOT / "artifacts/product-release/second-brain-v1/decisions"
_FORBIDDEN = ("BEGIN ", "PRIVATE KEY", "private_key", "signature_b64")


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return value


def test_unsigned_body_binds_raw_bundle_digest_without_go_or_signatures() -> None:
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
    assert body["outcome"] not in {"GO", "NO_GO"}
    serialized = json.dumps(body, sort_keys=True)
    assert '"outcome": "GO"' not in serialized
    assert '"outcome":"GO"' not in raw.decode("utf-8")
    assert '"decision": "GO"' not in serialized
    for token in _FORBIDDEN:
        assert token not in serialized
        assert token.encode("ascii") not in raw
    with pytest.raises(InvalidContractValue):
        _ = DecisionRecordV1.from_mapping(body)


def test_unsigned_body_is_not_authority_and_current_decisions_stay_fail_closed() -> None:
    assert _BODY.parent.name == "decision-signing"
    assert not (_DECISIONS / "DB-01.json").exists()
    names = {path.name for path in _DECISIONS.glob("*.json")}
    assert names == {"DB-04.json", "DB-06-model-a.json", "DB-08-archive.json"}
