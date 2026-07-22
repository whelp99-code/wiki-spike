#!/usr/bin/env python3
"""Assemble canonical P3-00 evidence from independently executed gate logs."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

try:
    from .preflight_common import PreflightError, find_repo_root, git, sha256_file, write_canonical_json
except ImportError:
    from preflight_common import PreflightError, find_repo_root, git, sha256_file, write_canonical_json


def _relative(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError as exc:
        raise PreflightError(f"evidence log escapes repository: {path}") from exc


def _read_pass_log(path: Path, marker: str, repo: Path) -> dict[str, str]:
    text = path.read_text("utf-8")
    if marker not in text:
        raise PreflightError(f"expected marker {marker!r} missing from {path}")
    return {"path": _relative(path, repo), "sha256": sha256_file(path), "status": "pass"}


def build_evidence(repo: Path, log_dir: Path) -> dict:
    checkpoint = _read_pass_log(log_dir / "checkpoint.log", "PASS: Phase 2 checkpoint", repo)
    phase3_pin_path = log_dir / "phase3-pin.json"
    phase3_pin = json.loads(phase3_pin_path.read_text("utf-8"))
    if phase3_pin.get("status") != "pass":
        raise PreflightError("Phase 3 contract pin did not pass")
    phase3_pin_ref = {"path": _relative(phase3_pin_path, repo), "sha256": sha256_file(phase3_pin_path), "status": "pass", "pin_id": str(phase3_pin["pin_id"])}
    boundaries = _read_pass_log(log_dir / "boundaries.log", "PASS: architecture boundaries", repo)
    runtime_path = log_dir / "runtime-boundaries.json"
    runtime = json.loads(runtime_path.read_text("utf-8"))
    if runtime.get("status") != "pass":
        raise PreflightError("Runtime boundary gate did not pass")
    runtime_ref = {"path": _relative(runtime_path, repo), "sha256": sha256_file(runtime_path), "status": "pass"}
    secrets = _read_pass_log(log_dir / "secrets.log", "PASS: no tracked secrets detected", repo)
    pytest_path = log_dir / "pytest.log"
    pytest_text = pytest_path.read_text("utf-8")
    matches = re.findall(r"(\d+) passed", pytest_text)
    if not matches:
        raise PreflightError("pytest pass count missing")
    passed = matches[-1]
    if int(passed) < 116:
        raise PreflightError("regression count below G2 minimum")
    package_path = log_dir / "package.json"
    package = json.loads(package_path.read_text("utf-8"))
    if package.get("status") != "pass":
        raise PreflightError("package smoke did not pass")
    head = git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    return {
        "commands": {
            "architecture_boundaries": boundaries,
            "phase3_contract_pin": phase3_pin_ref,
            "runtime_boundaries": runtime_ref,
            "package_smoke": {
                "path": _relative(package_path, repo),
                "sha256": sha256_file(package_path),
                "status": "pass",
                "wheel_sha256": str(package["wheel_sha256"]),
            },
            "phase2_checkpoint": checkpoint,
            "regression": {
                "passed_tests": passed,
                "path": _relative(pytest_path, repo),
                "sha256": sha256_file(pytest_path),
                "status": "pass",
            },
            "secret_scan": secrets,
        },
        "head_commit": head,
        "phase": "3",
        "pr_id": "P3-00",
        "result": "pass",
        "schema_version": "phase3-preflight-evidence-v1",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--log-dir", type=Path, default=Path(".ci/p3-00"))
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    log_dir = args.log_dir if args.log_dir.is_absolute() else repo / args.log_dir
    output = args.json_out if args.json_out.is_absolute() else repo / args.json_out
    try:
        evidence = build_evidence(repo, log_dir)
        write_canonical_json(output, evidence)
    except (PreflightError, OSError, ValueError, KeyError) as exc:
        print(f"FAIL: {exc}")
        return 1
    print(f"PASS: wrote P3-00 evidence to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
