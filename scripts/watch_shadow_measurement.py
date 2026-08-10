#!/usr/bin/env python3
"""Report shadow-measurement progress and alert on state changes.

Run without flags for a one-shot progress readout. Run with --notify from a
periodic agent to raise a macOS notification when the cohort changes state.

The states are:

  collecting  the cohort is receiving samples
  paused      the laptop is asleep, offline, or otherwise silent; resume
              preserves prior effective observation time
  dead        journal corruption, unreadability, or clock rollback prevents use
  complete    every SLO reason cleared and the outcome is terminal
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wiki_spike.composition.retained_authority import LocalRetainedAuthority
from wiki_spike.composition.second_brain_shadow_measurement import (
    open_measurement,
    report_measurement,
)

# Intervals longer than this are visible evidence but contribute no effective
# observation time.  They are ordinary laptop sleep/offline pauses, not death.
CLIFF_SECONDS = 3600
_DEFAULT_WINDOW_SECONDS = 24 * 3600


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _window_seconds(cohort: Path) -> int:
    """Read the measurement window from the cohort contract when present."""
    path = cohort / "contract.json"
    if not path.exists():
        return _DEFAULT_WINDOW_SECONDS
    try:
        days = int(json.loads(path.read_text(encoding="utf-8"))["min_shadow_days"])
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return _DEFAULT_WINDOW_SECONDS
    if days < 1:
        return _DEFAULT_WINDOW_SECONDS
    return days * 86400


def _window_label(seconds: int) -> str:
    days = seconds / 86400
    if days == int(days):
        return f"{int(days)}d"
    return f"{seconds // 3600}h"


def _fingerprint(cohort: Path) -> str:
    from hashlib import sha256

    return sha256(bytes.fromhex((cohort / "measurement.pub").read_text().strip())).hexdigest()


def _last_sample_at(cohort: Path) -> datetime | None:
    frames = sorted((cohort / "cohort.json.segments").glob("*.frame"))
    for frame in reversed(frames):
        raw = frame.read_bytes()
        try:
            event = json.loads(raw[9:-1])
        except (ValueError, IndexError):
            continue
        entry = event.get("entry")
        if isinstance(entry, dict) and isinstance(event.get("recorded_at"), str):
            return _instant(event["recorded_at"])
    return None


def _first_sample_at(cohort: Path) -> datetime | None:
    for frame in sorted((cohort / "cohort.json.segments").glob("*.frame")):
        raw = frame.read_bytes()
        try:
            event = json.loads(raw[9:-1])
        except (ValueError, IndexError):
            continue
        entry = event.get("entry")
        if isinstance(entry, dict) and isinstance(event.get("recorded_at"), str):
            return _instant(event["recorded_at"])
    return None


def _is_dead_error(exc: Exception) -> bool:
    """Only unreadable/corrupt journals and rollback are restart candidates."""
    detail = str(exc).lower()
    return "clock rollback" in detail or any(
        marker in detail for marker in ("journal", "measurement chain", "measurement state")
    )


def inspect(cohort: Path) -> dict:
    """Classify the cohort without mutating anything the collector owns."""
    last = _last_sample_at(cohort)
    silence = (_now() - last).total_seconds() if last else None
    window = _window_seconds(cohort)

    try:
        collector = open_measurement(
            db=cohort / "cohort.json",
            authority=LocalRetainedAuthority(cohort / "authority"),
            measurement_public_key=cohort / "measurement.pub",
            measurement_key_fingerprint=_fingerprint(cohort),
            resolved_scope=cohort / "scope.json",
            contract=cohort / "contract.json",
            source_manifest=cohort / "source.json",
            capability_manifest=cohort / "capability.json",
            benchmark_manifest=cohort / "benchmark.json",
            holdout_manifest=cohort / "holdout.json",
        )
        report = report_measurement(collector)
    except Exception as exc:  # preserve evidence unless this is a true fatal state
        state = "dead" if _is_dead_error(exc) else "blocked"
        return {"state": state, "detail": f"cohort will not open: {exc}",
                "silence_seconds": silence, "window_seconds": window}

    if report["outcome"] == "EVIDENCE_COMPLETE_NON_SERVING":
        state = "complete"
    elif silence is not None and silence > CLIFF_SECONDS:
        state = "paused"
    else:
        state = "collecting"

    effective_seconds = report["effective_seconds"]
    return {
        "state": state,
        "outcome": report["outcome"],
        "samples": report["sample_count"],
        "effective_seconds": effective_seconds,
        "continuous_seconds": report["continuous_seconds"],
        "excluded_gap_seconds": report["excluded_gap_seconds"],
        "excluded_gap_count": report["excluded_gap_count"],
        "remaining_effective_seconds": max(0, window - effective_seconds),
        "window_seconds": window,
        "percent": round(100 * effective_seconds / window, 2) if window else 0.0,
        "silence_seconds": round(silence) if silence is not None else None,
        "calendar_completion": "can be later than the effective observation window",
        "reasons": report["reasons"],
    }


def _notify(title: str, message: str) -> None:
    subprocess.run(
        ["osascript", "-e", f'display notification {json.dumps(message)} with title {json.dumps(title)}'],
        check=False, capture_output=True,
    )


def _restart(cohort: Path, status: dict) -> dict:
    """Archive a dead cohort and provision a fresh one at the same path.

    The path is preserved because the authority endpoint is an absolute path
    baked into the signed checkpoint root; a cohort cannot be relocated. The
    dead cohort is archived rather than deleted because its signed journal is
    evidence of what actually happened.

    This is only for a cohort which cannot be read or has a clock rollback.
    Ordinary sleep/offline pauses are valid and must never reach this function.
    """
    stamp = _now().strftime("%Y%m%dT%H%M%SZ")
    archive = cohort.parent / f"cohort-dead-{stamp}"
    try:
        cohort.rename(archive)
    except OSError as exc:
        return {"ok": False, "error": f"could not archive dead cohort: {exc}"}

    provision = Path(__file__).resolve().parent / "provision_shadow_measurement.py"
    result = subprocess.run(
        [sys.executable, str(provision), "--output-dir", str(cohort)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return {"ok": False,
                "error": f"provisioning failed (rc={result.returncode}): {result.stderr.strip()[:200]}"}
    window = _window_seconds(cohort)
    return {"ok": True, "archive": str(archive), "window_seconds": window}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-dir", required=True)
    parser.add_argument("--notify", action="store_true",
                        help="raise a macOS notification when the state changes")
    parser.add_argument("--auto-restart", action="store_true",
                        help="on corruption or clock rollback, archive the dead cohort and provision a fresh one; paused/offline cohorts are never restarted")
    args = parser.parse_args()

    cohort = Path(args.cohort_dir)
    status = inspect(cohort)
    print(json.dumps(status, indent=2))

    if not args.notify:
        return 0

    # Only announce transitions, so a periodic agent does not repeat itself.
    marker = cohort / ".watch-state"
    previous = marker.read_text().strip() if marker.exists() else ""
    if status["state"] == previous:
        return 0
    marker.write_text(status["state"])

    window = int(status.get("window_seconds") or _window_seconds(cohort))
    label = _window_label(window)

    if status["state"] == "complete":
        _notify("Shadow measurement complete",
                f"{label} window closed with {status['samples']} samples. Outcome: {status['outcome']}.")
    elif status["state"] == "dead":
        if args.auto_restart:
            restart = _restart(cohort, status)
            marker.write_text("collecting" if restart["ok"] else "dead")
            if restart["ok"]:
                # A cohort that will not open reports no counters, so these
                # must degrade rather than raise: a restart notification that
                # crashes is worse than the failure it reports.
                lost = f"{status.get('samples', '?')} samples, {status.get('percent', '?')}%"
                restart_label = _window_label(int(restart.get("window_seconds") or window))
                _notify("Shadow measurement restarted",
                        f"Previous cohort died ({lost}) and was archived. "
                        f"A fresh {restart_label} effective-observation window started; calendar completion can be later.")
            else:
                _notify("Shadow measurement DIED and could not restart",
                        f"{restart['error']} — manual reset required.")
        else:
            _notify("Shadow measurement DIED",
                    status.get("detail") or f"No sample for {status['silence_seconds']}s; the cohort must be reset.")
    elif status["state"] == "paused":
        _notify("Shadow measurement paused",
                f"No sample for {status['silence_seconds']}s. Resume preserves "
                f"{status['effective_seconds']} effective seconds; "
                f"{status['remaining_effective_seconds']} remain.")
    elif status["state"] == "blocked":
        _notify("Shadow measurement blocked",
                f"{status.get('detail')} — preserving the cohort; manual investigation required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
