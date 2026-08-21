"""DB-05 has no unsigned body until a governance evidence digest exists."""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_BODY = _ROOT / "artifacts/product-release/second-brain-v1/decision-signing/DB-05.body.json"
_RECORD = _ROOT / "artifacts/product-release/second-brain-v1/decisions/DB-05.json"
_GOVERNANCE = _ROOT / "artifacts/product-release/second-brain-v1/governance"
_SLO = _GOVERNANCE / "slo.json"


def test_db05_unsigned_body_and_authority_record_are_absent() -> None:
    assert not _BODY.exists()
    assert not _RECORD.exists()


def test_slo_artifact_is_not_treated_as_db05_governance_bundle() -> None:
    assert _SLO.is_file()
    names = {path.name for path in _GOVERNANCE.glob("*.json")}
    assert "slo.json" in names
    assert "governance.json" not in names
    assert "benchmark.json" not in names
    assert "holdout.json" not in names
