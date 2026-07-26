#!/usr/bin/env python3
"""Same-commit Gate 8 conformance run for the Encrypted Single-Memory Lifecycle.

Runs the full conformance surface at the CURRENT implementation commit and
records the outcome as a single ``payload/conformance-pre-canary.json``:

  * project test suite
  * architecture-boundary check
  * secret scan and encrypted-lifecycle plaintext-safety tests
  * independent vector validator
  * recall corpus evaluation (Top-3 hit rate >= 0.80, zero forbidden returns)
  * extraction corpus evaluation (zero forbidden returns)

The run is fail-closed: any failing surface marks the whole run non-conformant.
With the required provenance arguments it wraps the report into an immutable
``CONFORMANCE_PRE_CANARY`` bundle and writes its computed identity metadata.

This script never fabricates a green result: a non-conformant run exits
non-zero and (when bundling) refuses to emit a bundle.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from build_encrypted_lifecycle_bundle import canonical_bytes

REPO_ROOT = Path(__file__).resolve().parent.parent

REPORT_SCHEMA = "wiki-gate8-conformance-report-v1"


def _run(cmd: list[str]) -> tuple[bool, str]:
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    tail = (proc.stdout + proc.stderr).strip().splitlines()[-5:]
    return proc.returncode == 0, "\n".join(tail)


def _check_project_tests() -> tuple[bool, str]:
    return _run([sys.executable, "-m", "pytest", "-q"])


def _check_boundaries() -> tuple[bool, str]:
    return _run([sys.executable, "scripts/check_architecture_boundaries.py"])
def _check_secrets() -> tuple[bool, str]:
    return _run([sys.executable, "scripts/scan_secrets.py"])

def _check_plaintext_safety() -> tuple[bool, str]:
    return _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/encrypted_lifecycle/test_encrypted_cas.py",
            "tests/encrypted_lifecycle/test_lifecycle_db.py",
            "tests/encrypted_lifecycle/test_gate5_forget.py",
            "-q",
        ]
    )


def _check_vectors() -> tuple[bool, str]:
    return _run([sys.executable, "scripts/validate_encrypted_lifecycle_vectors.py"])


def _check_recall() -> tuple[bool, str]:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from wiki_spike.infrastructure.recall import RELEVANT_HIT_THRESHOLD, run_recall_evaluation

    ev = run_recall_evaluation()
    ok = ev.top3_hit_rate >= RELEVANT_HIT_THRESHOLD and ev.zero_forbidden_returns
    detail = (
        f"queries={ev.total_queries} relevant_hits={ev.relevant_hits}/"
        f"{ev.relevant_count} top3_hit_rate={ev.top3_hit_rate:.3f} "
        f"zero_forbidden={ev.zero_forbidden_returns}"
    )
    return ok, detail


def _check_extraction() -> tuple[bool, str]:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from wiki_spike.infrastructure.extraction import run_corpus_evaluation

    ev = run_corpus_evaluation()
    ok = ev.zero_forbidden_returns
    detail = (
        f"items={ev.total_items} precision_avg={ev.precision_avg:.3f} "
        f"recall_avg={ev.recall_avg:.3f} zero_forbidden={ev.zero_forbidden_returns}"
    )
    return ok, detail


def run_conformance() -> dict:
    checks = {
        "project_tests": _check_project_tests,
        "architecture_boundaries": _check_boundaries,
        "secret_scan": _check_secrets,
        "plaintext_safety": _check_plaintext_safety,
        "vector_validator": _check_vectors,
        "recall_corpus": _check_recall,
        "extraction_corpus": _check_extraction,
    }
    results: dict[str, dict] = {}
    all_ok = True
    for name, fn in checks.items():
        ok, detail = fn()
        results[name] = {"passed": ok, "detail": detail}
        all_ok = all_ok and ok
    return {
        "schema": REPORT_SCHEMA,
        "conformant": all_ok,
        "checks": results,
    }


def _git_head_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""
def _required_sha256(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("provenance digest must be a lowercase 64-hex SHA-256")
    return value


def _required_nonempty(value: str, name: str) -> str:
    if not value:
        raise ValueError(f"{name} is required")
    return value

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="directory to write payload/conformance-pre-canary.json")
    parser.add_argument("--bundle-output-dir", required=True, help="build a CONFORMANCE_PRE_CANARY bundle here")
    parser.add_argument("--artifact-metadata-output", required=True, help="write computed bundle identity and strict expected tuple here")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--produced-at", required=True)
    parser.add_argument("--source-run-url", required=True)
    parser.add_argument("--contract-digest", required=True)
    parser.add_argument("--toolchain-lock-digest", required=True)
    parser.add_argument("--workflow-file-digest", required=True)
    args = parser.parse_args(argv)
    try:
        for name in (
            "repository",
            "workflow_run_id",
            "workflow_run_attempt",
            "platform",
            "produced_at",
            "source_run_url",
        ):
            _required_nonempty(getattr(args, name), name)
        for name in ("contract_digest", "toolchain_lock_digest", "workflow_file_digest"):
            _required_sha256(getattr(args, name))
        implementation_commit = _git_head_commit()
        if not re.fullmatch(r"[0-9a-f]{40,64}", implementation_commit):
            raise ValueError("checked-out implementation commit must be a hexadecimal Git object ID")
    except ValueError as exc:
        parser.error(str(exc))
    report = run_conformance()
    report["implementation_commit"] = implementation_commit
    payload_bytes = canonical_bytes(report)
    out = Path(args.output_dir)
    payload_path = out / "payload" / "conformance-pre-canary.json"
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_path.write_bytes(payload_bytes)

    print(json.dumps(report, indent=2, sort_keys=True))

    if not report["conformant"]:
        print("CONFORMANCE FAILED: one or more surfaces did not pass", file=sys.stderr)
        return 1

    if args.bundle_output_dir:
        # Wrap the report payload into an immutable CONFORMANCE_PRE_CANARY bundle.
        import tempfile

        from build_encrypted_lifecycle_bundle import (
            ENVELOPE_ENTRY_PATH,
            MANIFEST_ENTRY_PATH,
            build_bundle,
            write_deterministic_tar,
        )

        with tempfile.TemporaryDirectory() as tmp:
            payload_dir = Path(tmp)
            payload = payload_dir / "payload"
            payload.mkdir()
            (payload / "conformance-pre-canary.json").write_bytes(payload_bytes)
            built = build_bundle(
                input_dir=payload_dir,
                payload_names=["payload/conformance-pre-canary.json"],
                artifact_kind="CONFORMANCE_PRE_CANARY",
                repository=args.repository,
                producer_commit=report["implementation_commit"],
                contract_digest=args.contract_digest,
                toolchain_lock_digest=args.toolchain_lock_digest,
                workflow_file_digest=args.workflow_file_digest,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                platform_token=args.platform,
                produced_at=args.produced_at,
            )
            out = Path(args.bundle_output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / ENVELOPE_ENTRY_PATH).write_bytes(built["envelope_bytes"])
            (out / MANIFEST_ENTRY_PATH).write_bytes(built["manifest_bytes"])
            tar_files = [
                (ENVELOPE_ENTRY_PATH, built["envelope_bytes"]),
                (MANIFEST_ENTRY_PATH, built["manifest_bytes"]),
            ]
            for rel, data in built["payload_bytes"].items():
                tar_files.append((rel, data))
            tar_path = out / f"{built['artifact_name']}.tar"
            write_deterministic_tar(tar_path, tar_files)
            expected = {
                field: built["envelope"][field]
                for field in (
                    "repository",
                    "artifact_kind",
                    "platform",
                    "producer_commit",
                    "contract_digest",
                    "toolchain_lock_digest",
                    "workflow_file_digest",
                    "workflow_run_id",
                    "workflow_run_attempt",
                    "artifact_name",
                    "bundle_sha256",
                    "payload_paths",
                    "payload_sha256",
                )
            }
            expected["source_run_url"] = args.source_run_url
            metadata = {
                "artifact_name": built["artifact_name"],
                "tar_path": str(tar_path),
                "expected": expected,
            }
            metadata_path = Path(args.artifact_metadata_output)
            metadata_path.parent.mkdir(parents=True, exist_ok=True)
            metadata_path.write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(json.dumps(metadata, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
