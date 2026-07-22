#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

try:
    from .preflight_common import PreflightError, find_repo_root
except ImportError:
    from preflight_common import PreflightError, find_repo_root


def validate(repo: Path) -> None:
    doc = repo / "docs/adversarial/P3-00_ADVERSARIAL_VALIDATION_50R_KR.md"
    rounds = [int(x) for x in re.findall(r"^## Round (\d{2})", doc.read_text("utf-8"), re.M)]
    if rounds != list(range(1, 51)):
        raise PreflightError(f"expected adversarial rounds 01..50, got {rounds}")
    required = [
        ".github/workflows/phase3-preflight.yml",
        "architecture-boundaries.json",
        "artifacts/checkpoints/g2/phase2-storage-checkpoint.json",
        "artifacts/checkpoints/g2/phase2-storage-checkpoint.sig",
        "artifacts/checkpoints/g2/phase2-storage-public-key.pem",
        "artifacts/conformance/phase3/P3-00/report.md",
        "scripts/check_architecture_boundaries.py",
        "scripts/scan_secrets.py",
        "scripts/verify_phase2_checkpoint.py",
    ]
    missing = [path for path in required if not (repo / path).is_file()]
    if missing:
        raise PreflightError(f"missing P3-00 artifacts: {missing}")


def main() -> int:
    repo = find_repo_root()
    try:
        validate(repo)
    except PreflightError as exc:
        print(f"FAIL: {exc}")
        return 1
    print("PASS: P3-00 artifacts and 50 adversarial rounds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
