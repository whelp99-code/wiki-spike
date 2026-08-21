"""Unsigned DB-03 me-wiki body binds source evidence without GO or signatures."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.second_brain_decision import BODY_FIELDS
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.me_wiki_source_evidence import MeWikiSourceEvidenceV1
from wiki_spike.memory_core.second_brain_contracts import DecisionRecordV1
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_ROOT = Path(__file__).resolve().parents[2]
_BODY = (
    _ROOT
    / "artifacts/product-release/second-brain-v1/decision-signing"
    / "DB-03-me-wiki.body.json"
)
_EVIDENCE = (
    _ROOT
    / "artifacts/product-release/second-brain-v1/evidence"
    / "me-wiki-source-evidence-v1.json"
)
_DECISIONS = _ROOT / "artifacts/product-release/second-brain-v1/decisions"
_FORBIDDEN = ("BEGIN ", "PRIVATE KEY", "private_key", "signature_b64")


def _load(path: Path) -> dict[str, JsonValue]:
    return decode_json_object(path.read_text(encoding="utf-8"))


def test_unsigned_body_binds_raw_source_evidence_digest_without_go_or_signatures() -> None:
    raw = _BODY.read_bytes()
    body = _load(_BODY)
    evidence = MeWikiSourceEvidenceV1.from_mapping(
        decode_json_object(_EVIDENCE.read_text(encoding="utf-8"))
    )
    assert evidence.authorized_go is False
    assert evidence.body_reads == "0"
    assert evidence.state == "CONTRACT_AND_SYNTHETIC_FIXTURE_ONLY"
    assert raw == canonical_bytes(body) + b"\n"
    assert set(body) == set(BODY_FIELDS)
    assert "signatures" not in body
    assert body["decision_id"] == "DB-03"
    assert body["scope_kind"] == "migration_source"
    assert body["scope_name"] == "me-wiki"
    assert body["evidence_digest"] == sha256(_EVIDENCE.read_bytes()).hexdigest()
    assert body["evidence_refs"] == [_EVIDENCE.relative_to(_ROOT).as_posix()]
    assert body["outcome"] == "UNRESOLVED"
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
    assert not (_DECISIONS / "DB-03.json").exists()
    assert not (_DECISIONS / "DB-03-me-wiki.json").exists()
    assert all(
        _load(path)["scope_name"] != "me-wiki"
        for path in _DECISIONS.glob("DB-03*.json")
    )
