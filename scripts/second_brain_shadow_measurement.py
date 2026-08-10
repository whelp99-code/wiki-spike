#!/usr/bin/env python3
"""Local-only CLI for a closed native shadow-measurement cohort."""
from __future__ import annotations

import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.applications.second_brain_shadow_measurement import ShadowMeasurementError
from wiki_spike.composition.second_brain_shadow_measurement import (
    ShadowMeasurementCompositionError,
    open_measurement,
    report_measurement,
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
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
    parser.add_argument("--authority-evidence")
    args = parser.parse_args(argv)
    if args.command == "init" and not args.checkpoint:
        raise ValueError("init requires --checkpoint")
    if args.command != "init" and args.checkpoint:
        raise ValueError("only init accepts --checkpoint")
    if (args.command == "append") != bool(args.sample):
        raise ValueError("append requires --sample and other commands forbid it")
    if not args.authority_endpoint.startswith("retention-authority://"):
        raise ValueError("--authority-endpoint must name a retention-enforced external adapter")
    return args


def _measurement_binding(args: argparse.Namespace) -> str:
    """Bind deployment evidence to this exact local measurement run, not a name."""
    try:
        inputs = {
            name: sha256(Path(getattr(args, name)).read_bytes()).hexdigest()
            for name in ("resolved_scope", "contract", "source_manifest", "capability_manifest", "benchmark_manifest", "holdout_manifest")
        }
    except OSError as exc:
        raise ValueError("measurement binding inputs are unreadable") from exc
    body = {"db": str(Path(args.db).resolve()), "endpoint": args.authority_endpoint,
            "measurement_key_fingerprint": args.measurement_key_fingerprint, "inputs": inputs}
    return sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _injection_evidence(path: str | None, authority: object, args: argparse.Namespace) -> None:
    """Require a closed deployment attestation before an injected adapter runs.

    This script cannot import Infrastructure: that is a native-measurement
    boundary.  Deployment composition verifies the evidence and injects the
    authority; this narrow check prevents accidental use of an unbound object.
    """
    if not path:
        raise ValueError("a deployment authority evidence file is required")
    try:
        evidence = json.loads(Path(path).read_text(encoding="utf-8"))
        key = authority.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        fingerprint = sha256(key).hexdigest()
    except Exception as exc:
        raise ValueError("deployment authority evidence is unreadable") from exc
    if (not isinstance(evidence, dict) or not callable(getattr(authority, "verify_deployment_evidence", None))
            or evidence.get("measurement_binding") != _measurement_binding(args)
            or (evidence.get("identity"), evidence.get("endpoint"), evidence.get("policy_id"), evidence.get("public_key_fingerprint"))
            != (authority.identity, authority.endpoint, authority.policy_id, fingerprint)):
        raise ValueError("deployment authority evidence is unverified or does not bind the injected authority")
    try:
        authority.verify_deployment_evidence(evidence, measurement_binding=evidence["measurement_binding"])
    except Exception as exc:
        raise ValueError("deployment authority evidence is unverified") from exc


def run_with_authority(authority: object, argv: list[str] | None = None) -> int:
    """Execute only under a deployment-injected, evidenced authority adapter.

    The public CLI deliberately does not construct adapters from endpoint text.
    This seam is for trusted composition/tests and keeps live operations out of
    a standalone native-measurement process.
    """
    try:
        args = _arguments(argv)
        _injection_evidence(args.authority_evidence, authority, args)
        collector = open_measurement(
            db=args.db, authority=authority, measurement_public_key=args.measurement_public_key,
            measurement_key_fingerprint=args.measurement_key_fingerprint,
            resolved_scope=args.resolved_scope, contract=args.contract,
            source_manifest=args.source_manifest, capability_manifest=args.capability_manifest,
            benchmark_manifest=args.benchmark_manifest, holdout_manifest=args.holdout_manifest,
            checkpoint=args.checkpoint, create=args.command == "init",
        )
        if args.command == "append":
            sample = json.loads(Path(args.sample).read_text(encoding="utf-8"))
            if not isinstance(sample, dict):
                raise ValueError("sample must be an object")
            collector.append(sample)
        print(json.dumps(report_measurement(collector), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, ShadowMeasurementError, ShadowMeasurementCompositionError):
        return 2


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
