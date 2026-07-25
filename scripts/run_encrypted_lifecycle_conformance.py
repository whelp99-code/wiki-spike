#!/usr/bin/env python3
"""Same-commit Gate 8 conformance run for the Encrypted Single-Memory Lifecycle.

Runs the full conformance surface at the CURRENT implementation commit and
records the outcome as a single ``conformance-report.json`` payload:

  * encrypted-lifecycle test suite (pytest tests/encrypted_lifecycle)
  * architecture-boundary check (scripts/check_architecture_boundaries.py)
  * independent vector validator (scripts/validate_encrypted_lifecycle_vectors.py)
  * recall corpus evaluation (Top-3 hit rate >= 0.80, zero forbidden returns)
  * extraction corpus evaluation (zero forbidden returns)

The run is fail-closed: any failing surface marks the whole run non-conformant.
With ``--output-dir`` the report payload is written; with the bundle arguments
supplied it is then wrapped into an immutable ``CONFORMANCE_PRE_CANARY`` bundle
via ``build_encrypted_lifecycle_bundle.py`` for the Gate 8 three-lane join.

This script never fabricates a green result: a non-conformant run exits
non-zero and (when bundling) refuses to emit a bundle.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

REPORT_SCHEMA = "wiki-gate8-conformance-report-v1"


def _run(cmd: list[str]) -> tuple[bool, str]:
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    tail = (proc.stdout + proc.stderr).strip().splitlines()[-5:]
    return proc.returncode == 0, "\n".join(tail)


def _check_pytest() -> tuple[bool, str]:
    return _run([sys.executable, "-m", "pytest", "tests/encrypted_lifecycle", "-q"])


def _check_boundaries() -> tuple[bool, str]:
    return _run([sys.executable, "scripts/check_architecture_boundaries.py"])


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
        "encrypted_lifecycle_tests": _check_pytest,
        "architecture_boundaries": _check_boundaries,
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", help="directory to write conformance-report.json")
    parser.add_argument("--bundle-output-dir", help="also build a CONFORMANCE_PRE_CANARY bundle here")
    parser.add_argument("--repository", default="wiki-spike")
    parser.add_argument("--workflow-run-id", default="0")
    parser.add_argument("--workflow-run-attempt", default="1")
    parser.add_argument("--platform", default="local/conformance-run")
    parser.add_argument("--contract-digest", default="")
    parser.add_argument("--toolchain-lock-digest", default="")
    parser.add_argument("--workflow-file-digest", default="")
    args = parser.parse_args(argv)

    report = run_conformance()
    report["implementation_commit"] = _git_head_commit()

    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "conformance-report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    print(json.dumps(report, indent=2, sort_keys=True))

    if not report["conformant"]:
        print("CONFORMANCE FAILED: one or more surfaces did not pass", file=sys.stderr)
        return 1

    if args.bundle_output_dir:
        # Wrap the report payload into an immutable CONFORMANCE_PRE_CANARY bundle.
        import tempfile

        from build_encrypted_lifecycle_bundle import build_bundle, write_deterministic_tar
        from build_encrypted_lifecycle_bundle import ENVELOPE_ENTRY_PATH, MANIFEST_ENTRY_PATH

        with tempfile.TemporaryDirectory() as tmp:
            payload_dir = Path(tmp)
            (payload_dir / "conformance-report.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            built = build_bundle(
                input_dir=payload_dir,
                payload_names=["conformance-report.json"],
                artifact_kind="CONFORMANCE_PRE_CANARY",
                repository=args.repository,
                producer_commit=report["implementation_commit"],
                contract_digest=args.contract_digest or ("0" * 64),
                toolchain_lock_digest=args.toolchain_lock_digest or ("0" * 64),
                workflow_file_digest=args.workflow_file_digest or ("0" * 64),
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                platform_token=args.platform,
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
            print(f"built conformance bundle {tar_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
