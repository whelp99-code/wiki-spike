"""Phase3/phase4 local regression evidence uses string counts only."""
from __future__ import annotations

import json
from pathlib import Path

_EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "artifacts/conformance/second-brain/local-regression-2026-08-21-phase34.json"
)


def test_phase34_regression_evidence_uses_string_counts() -> None:
    payload = json.loads(_EVIDENCE.read_text(encoding="utf-8"))
    assert payload["kind"] == "second-brain-local-regression-phase34-v1"
    assert payload["pythonhashseed"] == "0"
    assert payload["phase3_and_phase4_tests_passed"].isdigit()
    assert isinstance(payload["phase3_and_phase4_tests_passed"], str)
    assert payload["wiki_console_script"] == "wiki_spike.cli:main"
