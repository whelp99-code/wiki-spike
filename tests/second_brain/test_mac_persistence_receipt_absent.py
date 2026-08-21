"""Mac persistence receipt is absent until owner and approver sign."""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_RELEASE = _ROOT / "artifacts/product-release/second-brain-v1"
_RECEIPT = _RELEASE / "persistence-receipt.json"
_PROFILE = _RELEASE / "persistence-profile.json"


def test_persistence_receipt_is_absent_while_unsigned_profile_exists() -> None:
    assert _PROFILE.is_file()
    assert not _RECEIPT.exists()
