#!/usr/bin/env python3
"""Report shadow-measurement progress and alert on state changes.

Run without flags for a one-shot progress readout. Run with --notify from a
periodic agent to raise a macOS notification when the cohort changes state.

The states are:

  collecting  the cohort is healthy and inside its measurement window
  stalling    the newest sample is old enough that the 60-minute interval
              cliff is approaching; the cohort is still saveable
  dead        a gap, rollback, or unreadable journal already ended the cohort
  complete    every SLO reason cleared and the outcome is terminal

`stalling` exists because the cliff is unrecoverable once crossed. A warning
that arrives with the cohort already dead is useless, so the watcher warns
while there is still time to act.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wiki_spike.composition.retained_authority import LocalRetainedAuthority
from wiki_spike.composition.second_brain_shadow_measurement import (
    open_measurement,
    report_measurement,
)

# The collector rejects an append once consecutive samples fall more than
# _MAX_INTERVAL_SECONDS apart. Warn well before that so the cohort is saveable.
CLIFF_SECONDS = 3600
STALL_WARN_SECONDS = 2400
WINDOW_SECONDS = 72 * 3600


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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
        if isinstance(entry, dict) and "recorded_at" in entry:
            return _instant(entry["recorded_at"])
    return None


def _first_sample_at(cohort: Path) -> datetime | None:
    for frame in sorted((cohort / "cohort.json.segments").glob("*.frame")):
        raw = frame.read_bytes()
        try:
            event = json.loads(raw[9:-1])
        except (ValueError, IndexError):
            continue
        entry = event.get("entry")
        if isinstance(entry, dict) and "recorded_at" in entry:
            return _instant(entry["recorded_at"])
    return None


def inspect(cohort: Path) -> dict:
    """Classify the cohort without mutating anything the collector owns."""
    last = _last_sample_at(cohort)
    first = _first_sample_at(cohort)
    silence = (_now() - last).total_seconds() if last else None

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
    except Exception as exc:  # cohort no longer opens at all
        return {"state": "dead", "detail": f"cohort will not open: {exc}",
                "silence_seconds": silence}

    if report["outcome"] == "EVIDENCE_COMPLETE_NON_SERVING":
        state = "complete"
    elif silence is not None and silence > CLIFF_SECONDS:
        state = "dead"
    elif silence is not None and silence > STALL_WARN_SECONDS:
        state = "stalling"
    else:
        state = "collecting"

    eta = (first + timedelta(seconds=WINDOW_SECONDS)).isoformat().replace("+00:00", "Z") if first else None
    return {
        "state": state,
        "outcome": report["outcome"],
        "samples": report["sample_count"],
        "elapsed_seconds": report["continuous_seconds"],
        "window_seconds": WINDOW_SECONDS,
        "percent": round(100 * report["continuous_seconds"] / WINDOW_SECONDS, 2),
        "silence_seconds": round(silence) if silence is not None else None,
        "eta": eta,
        "reasons": report["reasons"],
    }


def _notify(title: str, message: str) -> None:
    subprocess.run(
        ["osascript", "-e", f'display notification {json.dumps(message)} with title {json.dumps(title)}'],
        check=False, capture_output=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-dir", required=True)
    parser.add_argument("--notify", action="store_true",
                        help="raise a macOS notification when the state changes")
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

    if status["state"] == "complete":
        _notify("Shadow measurement complete",
                f"72h window closed with {status['samples']} samples. Outcome: {status['outcome']}.")
    elif status["state"] == "dead":
        _notify("Shadow measurement DIED",
                status.get("detail") or f"No sample for {status['silence_seconds']}s; the cohort must be reset.")
    elif status["state"] == "stalling":
        _notify("Shadow measurement stalling",
                f"No sample for {status['silence_seconds']}s. The cohort dies at {CLIFF_SECONDS}s — act now.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
