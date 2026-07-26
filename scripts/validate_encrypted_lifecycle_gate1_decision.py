#!/usr/bin/env python3
"""Fail closed unless Gate 1 platform evidence is an exact, consistent tuple."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
KIND = "SQLCIPHER_FEASIBILITY"
PAYLOAD_PATH = "payload/sqlcipher-feasibility.json"
UBUNTU_PLATFORM = "github-hosted/ubuntu-24.04/x86_64"
MACOS_PLATFORM = "self-hosted/macos-26/arm64/wiki-gate1-workstation"
MACOS_HARNESS_PLATFORM = "darwin/arm64"


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_object(path: str, label: str) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"{label} must be a regular file")
    value = json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def fail(message: str) -> int:
    print(f"REFUSED [GATE1_EVIDENCE_INVALID] {message}", file=sys.stderr)
    return 1


def validate_tuple(args: argparse.Namespace) -> None:
    receipt = load_object(args.receipt, "receipt")
    expected = {
        "repository": args.repository,
        "artifact_kind": KIND,
        "platform": args.platform,
        "producer_commit": args.producer_commit,
        "contract_digest": args.contract_digest,
        "toolchain_lock_digest": args.toolchain_lock_digest,
        "workflow_file_digest": args.workflow_file_digest,
        "workflow_run_id": args.workflow_run_id,
        "workflow_run_attempt": args.workflow_run_attempt,
        "artifact_name": args.artifact_name,
        "bundle_sha256": args.bundle_sha256,
        "payload_paths": [PAYLOAD_PATH],
        "payload_sha256": [args.payload_sha256],
        "source_run_url": "",
        "verified": True,
    }
    if receipt != expected:
        raise ValueError("receipt does not equal the closed expected SQLCIPHER_FEASIBILITY tuple")
    if not SHA40.fullmatch(args.producer_commit):
        raise ValueError("producer commit is not a lowercase SHA-1")
    digests = (args.contract_digest, args.toolchain_lock_digest, args.workflow_file_digest,
               args.bundle_sha256, args.payload_sha256)
    if any(not HEX64.fullmatch(value) for value in digests):
        raise ValueError("digest is not lowercase SHA-256")
    if not DECIMAL.fullmatch(args.workflow_run_id) or not DECIMAL.fullmatch(args.workflow_run_attempt):
        raise ValueError("run identifiers are not canonical decimal strings")
    expected_name = f"encrypted-lifecycle-sqlcipher-feasibility-{args.workflow_run_id}-{args.workflow_run_attempt}-{args.bundle_sha256[:16]}"
    if args.artifact_name != expected_name:
        raise ValueError("artifact name is not the exact computed bundle name")


def validate_evidence(args: argparse.Namespace) -> None:
    macos = load_object(args.macos_feasibility, "macOS feasibility")
    ubuntu = load_object(args.ubuntu_feasibility, "Ubuntu feasibility")
    vector = load_object(args.vector_validation, "vector validation")
    decision = load_object(args.decision, "Gate 1 decision")
    if macos.get("platform") != MACOS_HARNESS_PLATFORM or ubuntu.get("platform") != "linux/x86_64":
        raise ValueError("feasibility evidence does not contain distinct Darwin arm64 and Linux x86_64 results")
    if {macos.get("recorded_commit"), ubuntu.get("recorded_commit")} != {args.producer_commit}:
        raise ValueError("feasibility recorded_commit does not equal the envelope commit")
    if vector.get("verdict") != "PASS" or vector.get("cryptography_available") is not True or vector.get("jsonschema_available") is not True:
        raise ValueError("vector validation is not a complete passing cryptography/schema receipt")
    if decision.get("schema") != "wiki-gate1-decision-v1" or decision.get("profile_selection") not in {"A", "B"}:
        raise ValueError("decision schema or profile selection is invalid")
    if set(decision.get("adr_refs", [])) != {"ADR-0026", "ADR-0027"}:
        raise ValueError("decision ADR references are incomplete")
    if any(result.get("must_verdict") == "FAIL" for result in (macos, ubuntu)):
        raise ValueError("a feasibility MUST check failed")
    expected_profile = "A" if any(
        result.get("status") == "ok" and result.get("must_verdict") == "PASS"
        for result in (macos, ubuntu)
    ) else "B" if all(result.get("status") == "platform_unavailable" for result in (macos, ubuntu)) else None
    if decision.get("profile_selection") != expected_profile:
        raise ValueError("decision profile does not match the two-platform feasibility evidence")
    metric_freeze = decision.get("metric_freeze")
    if not isinstance(metric_freeze, dict) or metric_freeze.get("extraction_precision_min") != "80" or metric_freeze.get("extraction_recall_min") != "80":
        raise ValueError("decision intent metric freeze is inconsistent")
    contract_digests = decision.get("contract_digests")
    if not isinstance(contract_digests, dict):
        raise ValueError("decision contract digests are missing")
    required_files = [Path(args.vector_validation), *[Path(path) for path in args.adr]]
    schemas = sorted(Path(args.schemas_dir).glob("*.schema.json"))
    fixtures = sorted(path for path in Path(args.fixtures_dir).rglob("*") if path.is_file())
    if not schemas or not fixtures:
        raise ValueError("schema or vector fixture evidence is incomplete")
    for path in [*required_files, *schemas, *fixtures]:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if contract_digests.get(str(path)) != digest:
            raise ValueError(f"decision digest does not bind {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--contract-digest", required=True)
    parser.add_argument("--toolchain-lock-digest", required=True)
    parser.add_argument("--workflow-file-digest", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--payload-sha256", required=True)
    parser.add_argument("--platform", default=UBUNTU_PLATFORM)
    parser.add_argument("--macos-feasibility")
    parser.add_argument("--ubuntu-feasibility")
    parser.add_argument("--vector-validation")
    parser.add_argument("--decision")
    parser.add_argument("--adr", action="append", default=[])
    parser.add_argument("--schemas-dir")
    parser.add_argument("--fixtures-dir")
    args = parser.parse_args(argv)
    try:
        validate_tuple(args)
        evidence_args = (args.macos_feasibility, args.ubuntu_feasibility, args.vector_validation,
                         args.decision, args.schemas_dir, args.fixtures_dir)
        if any(evidence_args) and not all(evidence_args):
            raise ValueError("complete cross-platform evidence arguments are required together")
        if all(evidence_args):
            validate_evidence(args)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return fail(str(exc))
    print("validated exact SQLCIPHER_FEASIBILITY tuple and Gate 1 evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
