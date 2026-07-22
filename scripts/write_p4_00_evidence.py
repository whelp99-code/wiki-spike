#!/usr/bin/env python3
"""Write minimized machine-readable P4-00 conformance evidence."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re

try:
    from .preflight_common import (
        PreflightError,
        find_repo_root,
        git,
        sha256_file,
        write_canonical_json,
    )
except ImportError:
    from preflight_common import (
        PreflightError,
        find_repo_root,
        git,
        sha256_file,
        write_canonical_json,
    )

from wiki_spike.memory_core.contracts import canonical_bytes

EVIDENCE_VERSION = "phase4-p4-00-evidence-v1"


def _relative(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError as exc:
        raise PreflightError(f"P4-00 evidence path escapes repository: {path}") from exc


def _json_pass(path: Path, repo: Path) -> tuple[dict, dict[str, str]]:
    value = json.loads(path.read_text("utf-8"))
    if not isinstance(value, dict) or value.get("status") != "pass":
        raise PreflightError(f"P4-00 gate did not pass: {path}")
    return value, {
        "path": _relative(path, repo),
        "sha256": sha256_file(path),
        "status": "pass",
    }


def _pytest_pass(path: Path, repo: Path, *, minimum: int) -> dict[str, str]:
    text = path.read_text("utf-8")
    matches = re.findall(r"(\d+) passed", text)
    if not matches:
        raise PreflightError(f"pytest pass count missing: {path}")
    count = int(matches[-1])
    if count < minimum:
        raise PreflightError(f"pytest pass count below minimum {minimum}: {count}")
    return {
        "path": _relative(path, repo),
        "sha256": sha256_file(path),
        "status": "pass",
        "passed_tests": str(count),
    }


def build_evidence(repo: Path, log_dir: Path) -> dict:
    pin, pin_ref = _json_pass(log_dir / "phase3-pin.json", repo)
    _, runtime_ref = _json_pass(log_dir / "runtime-boundaries.json", repo)
    _, architecture_ref = _json_pass(log_dir / "architecture-boundaries.json", repo)
    _, secrets_ref = _json_pass(log_dir / "secrets.json", repo)
    targeted = _pytest_pass(log_dir / "targeted-tests.log", repo, minimum=1)
    regression = _pytest_pass(log_dir / "regression.log", repo, minimum=396)
    package, package_ref = _json_pass(log_dir / "package.json", repo)
    package_ref["wheel_sha256"] = str(package.get("wheel_sha256", ""))
    head = git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    body = {
        "evidence_version": EVIDENCE_VERSION,
        "phase": "4",
        "pr_id": "P4-00",
        "head_commit": head,
        "phase3_contract_release": pin["contract_release"],
        "phase3_checkpoint_id": pin["g3_checkpoint_id"],
        "phase3_pin_id": pin["pin_id"],
        "commands": {
            "phase3_contract_pin": pin_ref,
            "runtime_boundaries": runtime_ref,
            "architecture_boundaries": architecture_ref,
            "secret_scan": secrets_ref,
            "targeted_tests": targeted,
            "regression": regression,
            "package_smoke": package_ref,
        },
        "result": "pass",
    }
    return {**body, "evidence_id": sha256(canonical_bytes(body)).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    log_dir = args.log_dir if args.log_dir.is_absolute() else repo / args.log_dir
    output = args.json_out if args.json_out.is_absolute() else repo / args.json_out
    try:
        evidence = build_evidence(repo, log_dir)
        write_canonical_json(output, evidence)
    except (PreflightError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}")
        return 1
    print(f"PASS: wrote P4-00 evidence {evidence['evidence_id']} to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
