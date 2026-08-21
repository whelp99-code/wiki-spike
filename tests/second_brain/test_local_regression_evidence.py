"""Local architecture/security regression evidence uses string counts only."""
from __future__ import annotations

import json
from pathlib import Path

_EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "artifacts/conformance/second-brain/local-regression-2026-08-21.json"
)


def test_local_regression_evidence_uses_string_counts() -> None:
    payload = json.loads(_EVIDENCE.read_text(encoding="utf-8"))
    assert payload["kind"] == "second-brain-local-regression-v1"
    assert payload["architecture_boundaries"] == "pass"
    assert payload["runtime_boundaries"] == "pass"
    assert payload["secret_scan"] == "pass"
    assert payload["pythonhashseed"] == "0"
    assert payload["second_brain_tests_passed"].isdigit()
    assert payload["encrypted_lifecycle_tests_passed"].isdigit()
    assert isinstance(payload["second_brain_tests_passed"], str)
    assert isinstance(payload["encrypted_lifecycle_tests_passed"], str)
    assert len(payload["implementation_commit"]) == 40
