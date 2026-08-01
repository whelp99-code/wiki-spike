#!/usr/bin/env python3
"""Operational CLI for a closed native shadow-measurement cohort.

Commands:
  init    -- create a fresh cohort with a signed checkpoint
  status  -- report current measurement outcome
  append  -- append a signed sample to the cohort
  verify  -- re-verify durable evidence and report outcome

The --authority-endpoint must be a retention-authority://local/<path> URI
pointing to a provisioned LocalRetainedAuthority directory.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wiki_spike.applications.second_brain_shadow_measurement import ShadowMeasurementError
from wiki_spike.composition.second_brain_shadow_measurement import (
    ShadowMeasurementCompositionError,
    open_measurement,
    report_measurement,
)
from wiki_spike.composition.retained_authority import (
    LocalRetainedAuthority,
    LocalRetainedAuthorityError,
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def _arguments() -> argparse.Namespace:
    parser = _Parser(add_help=False)
    parser.add_argument("command", choices=("init", "status", "append", "verify"))
    parser.add_argument("--db", required=True)
    parser.add_argument("--authority-endpoint", required=True)
    parser.add_argument("--measurement-public-key", required=True)
    parser.add_argument("--measurement-key-fingerprint", required=True)
    parser.add_argument("--resolved-scope", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--source-manifest", required=True)
    parser.add_argument("--capability-manifest", required=True)
    parser.add_argument("--benchmark-manifest", required=True)
    parser.add_argument("--holdout-manifest", required=True)
    parser.add_argument("--sample")
    parser.add_argument("--checkpoint")
    args = parser.parse_args()
    if args.command == "init" and not args.checkpoint:
        raise ValueError("init requires --checkpoint")
    if args.command != "init" and args.checkpoint:
        raise ValueError("only init accepts --checkpoint")
    if (args.command == "append") != bool(args.sample):
        raise ValueError("append requires --sample and other commands forbid it")
    if not args.authority_endpoint.startswith("retention-authority://"):
        raise ValueError("--authority-endpoint must name a retention-enforced external adapter")
    return args


def _authority_from_endpoint(endpoint: str) -> LocalRetainedAuthority:
    """Construct a LocalRetainedAuthority from a retention-authority:// URI."""
    prefix = "retention-authority://local/"
    if not endpoint.startswith(prefix):
        raise ValueError(
            f"unsupported authority endpoint scheme; expected retention-authority://local/<path>"
        )
    directory = endpoint[len(prefix):]
    if not directory or not Path(directory).is_dir():
        raise ValueError(f"authority directory does not exist: {directory}")
    return LocalRetainedAuthority(directory)


def main() -> int:
    try:
        args = _arguments()
    except (SystemExit, ValueError) as exc:
        print(f"argument error: {exc}", file=sys.stderr)
        return 2

    try:
        authority = _authority_from_endpoint(args.authority_endpoint)
    except (ValueError, LocalRetainedAuthorityError) as exc:
        print(f"authority error: {exc}", file=sys.stderr)
        return 2

    try:
        collector = open_measurement(
            db=args.db,
            authority=authority,
            measurement_public_key=args.measurement_public_key,
            measurement_key_fingerprint=args.measurement_key_fingerprint,
            resolved_scope=args.resolved_scope,
            contract=args.contract,
            source_manifest=args.source_manifest,
            capability_manifest=args.capability_manifest,
            benchmark_manifest=args.benchmark_manifest,
            holdout_manifest=args.holdout_manifest,
            checkpoint=args.checkpoint,
            create=(args.command == "init"),
        )
    except (ShadowMeasurementError, ShadowMeasurementCompositionError) as exc:
        print(f"measurement error: {exc}", file=sys.stderr)
        return 1

    if args.command == "init":
        print(json.dumps({"status": "initialized", "cohort_digest": collector.cohort_digest}))
        return 0

    if args.command == "append":
        try:
            sample = json.loads(Path(args.sample).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"sample error: {exc}", file=sys.stderr)
            return 1
        try:
            collector.append(sample)
        except ShadowMeasurementError as exc:
            print(f"append error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"status": "appended", "cohort_digest": collector.cohort_digest}))
        return 0

    # status and verify both report
    report = report_measurement(collector)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
