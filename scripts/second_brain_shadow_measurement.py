#!/usr/bin/env python3
"""Local-only CLI for a closed native shadow-measurement cohort."""
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


def main() -> int:
    try:
        _arguments()
    except (SystemExit, ValueError):
        return 2
    print(
        "measurement input rejected: standalone CLI cannot adapt an unverified endpoint; "
        "use a deployment-provided MonotonicAppendAuthority adapter",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
