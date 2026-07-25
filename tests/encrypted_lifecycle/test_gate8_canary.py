"""Gate 8 24h canary runner tests (short-duration).

The production canary runs for exactly 24 hours on a self-hosted macOS runner;
these tests exercise the same probe/loop code with a short duration.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_encrypted_lifecycle_canary_24h as canary  # noqa: E402


def test_single_probe_roundtrip_passes():
    result = canary.run_probe(0)
    assert result["passed"] is True, result["error"]
    assert result["error"] is None


def test_short_canary_is_healthy():
    # duration 0 -> exactly one probe, no sleep.
    report = canary.run_canary(duration_seconds=0, interval_seconds=0)
    assert report["schema"] == canary.REPORT_SCHEMA
    assert report["healthy"] is True
    assert report["probe_count"] == "1"
    assert report["failure_count"] == "0"
    assert all(p["passed"] for p in report["probes"])


def test_canary_report_records_failures(monkeypatch):
    # A failing probe must mark the canary unhealthy (fail-closed reporting).
    def _failing_probe(_index: int) -> dict:
        return {"probe_index": "0", "passed": False, "error": "simulated", "elapsed_seconds": "0.001"}

    monkeypatch.setattr(canary, "run_probe", _failing_probe)
    report = canary.run_canary(duration_seconds=0, interval_seconds=0)
    assert report["healthy"] is False
    assert report["failure_count"] == "1"
