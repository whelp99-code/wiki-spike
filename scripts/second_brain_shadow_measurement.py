#!/usr/bin/env python3
"""Local-only CLI for a closed native shadow-measurement cohort."""
from __future__ import annotations

import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.composition.second_brain_shadow_measurement import open_measurement, report_measurement

_PATH_FLAGS = (
    "db", "measurement_public_key", "resolved_scope", "contract", "source_manifest",
    "capability_manifest", "benchmark_manifest", "holdout_manifest",
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)  # noqa: GENERIC_ERR_OK


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = _Parser(add_help=False)
    parser.add_argument("command", choices=("init", "status", "append", "verify"))
    for flag in ("--db", "--authority-endpoint", "--measurement-public-key", "--measurement-key-fingerprint", "--resolved-scope", "--contract", "--source-manifest", "--capability-manifest", "--benchmark-manifest", "--holdout-manifest", "--sample", "--checkpoint", "--run-config", "--authority-evidence"):
        parser.add_argument(flag)
    args = parser.parse_args(argv)
    if args.command == "init" and not args.checkpoint: raise ValueError("init requires --checkpoint")  # noqa: GENERIC_ERR_OK
    if args.command != "init" and args.checkpoint: raise ValueError("only init accepts --checkpoint")  # noqa: GENERIC_ERR_OK
    if (args.command == "append") != bool(args.sample): raise ValueError("append requires --sample and other commands forbid it")  # noqa: GENERIC_ERR_OK
    if not args.run_config and any(not getattr(args, name) for name in (*_PATH_FLAGS, "authority_endpoint", "measurement_key_fingerprint")): raise ValueError("measurement flags are required without --run-config")  # noqa: GENERIC_ERR_OK
    if args.authority_endpoint and not args.authority_endpoint.startswith("retention-authority://"): raise ValueError("--authority-endpoint must name a retention-enforced external adapter")  # noqa: GENERIC_ERR_OK
    return args


def _measurement_binding(args: argparse.Namespace) -> str:
    try:
        if args.run_config:
            body = {"run_config": sha256(Path(args.run_config).read_bytes()).hexdigest()}
        else:
            body = {
                "db": str(Path(args.db).resolve()),
                "endpoint": args.authority_endpoint,
                "measurement_key_fingerprint": args.measurement_key_fingerprint,
                "inputs": {name: sha256(Path(getattr(args, name)).read_bytes()).hexdigest() for name in (
                    "resolved_scope", "contract", "source_manifest", "capability_manifest",
                    "benchmark_manifest", "holdout_manifest",
                )},
            }
    except OSError as exc:
        raise ValueError("measurement binding inputs are unreadable") from exc  # noqa: GENERIC_ERR_OK
    return sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _injection_evidence(path: str | None, authority: Any, args: argparse.Namespace) -> None:
    if not path:
        raise ValueError("a deployment authority evidence file is required")  # noqa: GENERIC_ERR_OK
    try:
        evidence = json.loads(Path(path).read_text(encoding="utf-8"))
        key = authority.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        fingerprint = sha256(key).hexdigest()
    except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError) as exc:
        raise ValueError("deployment authority evidence is unreadable") from exc  # noqa: GENERIC_ERR_OK
    if (
        not isinstance(evidence, dict)
        or not callable(getattr(authority, "verify_deployment_evidence", None))
        or evidence.get("measurement_binding") != _measurement_binding(args)
        or (evidence.get("identity"), evidence.get("endpoint"), evidence.get("policy_id"), evidence.get("public_key_fingerprint"))
        != (authority.identity, authority.endpoint, authority.policy_id, fingerprint)
    ):
        raise ValueError("deployment authority evidence is unverified or does not bind the injected authority")  # noqa: GENERIC_ERR_OK
    try:
        authority.verify_deployment_evidence(evidence, measurement_binding=evidence["measurement_binding"])
    except Exception as exc:  # noqa: BROAD_EXCEPT_OK
        raise ValueError("deployment authority evidence is unverified") from exc  # noqa: GENERIC_ERR_OK


def run_with_authority(authority: Any, argv: list[str] | None = None) -> int:
    try:
        args = _arguments(argv)
        _injection_evidence(args.authority_evidence, authority, args)
        if not all(getattr(args, name) for name in (*_PATH_FLAGS, "measurement_key_fingerprint")):
            raise ValueError("injected measurement still requires resolved local input paths")  # noqa: GENERIC_ERR_OK
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
                raise ValueError("sample must be an object")  # noqa: GENERIC_ERR_OK
            collector.append(sample)
        print(json.dumps(report_measurement(collector), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:  # noqa: BROAD_EXCEPT_OK
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
