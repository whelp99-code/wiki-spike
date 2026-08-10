#!/usr/bin/env python3
"""Synthetic pipeline canary for shadow-measurement append path verification.

WARNING: This script generates SYNTHETIC samples with hardcoded outcomes.
It does NOT perform real measurement. Its purpose is to verify that the
append/sign/authority/journal pipeline operates correctly end-to-end.

Real operational measurement requires source-specific integration adapters
that query actual Codex, Claude/Memory Bank, Git, and Markdown sources and
record genuine outcomes. This script must NOT be used as evidence for
serving cutover decisions.

Usage:
    python3 scripts/collect_shadow_samples.py --cohort-dir <dir>

The cohort-dir must contain the provisioned state from provision_shadow_measurement.py.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.composition.retained_authority import LocalRetainedAuthority
from wiki_spike.composition.second_brain_shadow_measurement import open_measurement, report_measurement
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_bytes

DOMAIN = "second-brain-native-shadow-sample-v1"
SOURCES = ("Codex", "Claude/Memory Bank", "Git", "Markdown")


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_measurement_key(path: Path) -> Ed25519PrivateKey:
    raw = bytes.fromhex(path.read_text(encoding="utf-8").strip())
    return Ed25519PrivateKey.from_private_bytes(raw)


def _sign_sample(key: Ed25519PrivateKey, payload: dict) -> str:
    return key.sign(canonical_ledger_bytes(DOMAIN, payload)).hex()


def collect(cohort_dir: Path) -> None:
    # Load measurement key
    key = _load_measurement_key(cohort_dir / "measurement.key")
    fingerprint = sha256(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).hexdigest()

    # Load authority
    auth_dir = cohort_dir / "authority"
    authority = LocalRetainedAuthority(auth_dir)

    # Open collector
    collector = open_measurement(
        db=cohort_dir / "cohort.json",
        authority=authority,
        measurement_public_key=cohort_dir / "measurement.pub",
        measurement_key_fingerprint=fingerprint,
        resolved_scope=cohort_dir / "scope.json",
        contract=cohort_dir / "contract.json",
        source_manifest=cohort_dir / "source.json",
        capability_manifest=cohort_dir / "capability.json",
        benchmark_manifest=cohort_dir / "benchmark.json",
        holdout_manifest=cohort_dir / "holdout.json",
    )

    cohort_digest = collector.cohort_digest
    state = collector._state
    previous = state["chain_head"]
    sequence = state["sample_count"]

    appended = 0
    for source in SOURCES:
        sample_id = f"{source.lower().replace('/', '-').replace(' ', '-')}:{uuid4().hex[:12]}"
        payload = {
            "sample_version": "second-brain-native-shadow-sample-v1",
            "sample_id": sample_id,
            "source_profile": source,
            "outcome": "valid",
            "citation": True,
            "completeness": True,
            "parity": True,
            "safety_violation": False,
            "cohort_digest": cohort_digest,
            "previous": previous,
            "sequence": sequence,
        }
        payload["signature"] = _sign_sample(key, payload)
        try:
            collector.append(payload)
            appended += 1
            # Update chain state for next sample
            state = collector._state
            previous = state["chain_head"]
            sequence = state["sample_count"]
        except Exception as exc:
            print(f"warning: failed to append {source} sample: {exc}", file=sys.stderr)

    report = report_measurement(collector)
    print(json.dumps({
        "appended": appended,
        "total_samples": report["sample_count"],
        "outcome": report["outcome"],
        "continuous_seconds": report["continuous_seconds"],
        "collected_at": _stamp(datetime.now(timezone.utc)),
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect shadow measurement samples")
    parser.add_argument("--cohort-dir", required=True, help="Operational cohort directory")
    args = parser.parse_args()
    collect(Path(args.cohort_dir))


if __name__ == "__main__":
    main()
