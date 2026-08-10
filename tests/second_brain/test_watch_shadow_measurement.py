from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _watcher_module():
    path = Path(__file__).resolve().parents[2] / "scripts" / "watch_shadow_measurement.py"
    spec = importlib.util.spec_from_file_location("watch_shadow_measurement_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report():
    return {
        "outcome": "NOT_READY", "sample_count": 12, "continuous_seconds": 300,
        "effective_seconds": 3600, "excluded_gap_seconds": 8 * 3600,
        "excluded_gap_count": 1, "reasons": ["effective measurement is below the required duration"],
    }


def test_silence_beyond_cliff_is_paused_and_auto_restart_does_not_archive(tmp_path, monkeypatch):
    watcher = _watcher_module()
    cohort = tmp_path / "cohort"
    cohort.mkdir()
    (cohort / "contract.json").write_text('{"min_shadow_days": 3}')
    last = datetime(2026, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(watcher, "_now", lambda: last + timedelta(hours=8))
    monkeypatch.setattr(watcher, "_last_sample_at", lambda _: last)
    monkeypatch.setattr(watcher, "LocalRetainedAuthority", lambda _: object())
    monkeypatch.setattr(watcher, "_fingerprint", lambda _: "fingerprint")
    monkeypatch.setattr(watcher, "open_measurement", lambda **_: object())
    monkeypatch.setattr(watcher, "report_measurement", lambda _: _report())
    monkeypatch.setattr(watcher, "_notify", lambda *_: None)
    monkeypatch.setattr(watcher, "_restart", lambda *_: (_ for _ in ()).throw(AssertionError("paused cohort restarted")))

    status = watcher.inspect(cohort)
    assert status["state"] == "paused"
    assert status["effective_seconds"] == 3600
    assert status["remaining_effective_seconds"] == 3 * 86400 - 3600
    assert status["calendar_completion"] == "can be later than the effective observation window"

    monkeypatch.setattr(sys, "argv", ["watch_shadow_measurement.py", "--cohort-dir", str(cohort), "--notify", "--auto-restart"])
    assert watcher.main() == 0
    assert cohort.exists()
