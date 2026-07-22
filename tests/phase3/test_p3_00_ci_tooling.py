from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.package_smoke import package_smoke


def root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_package_build_install_and_console_smoke():
    result = package_smoke(root())
    assert result["status"] == "pass"
    assert result["wheel"].endswith(".whl")
    assert len(result["wheel_sha256"]) == 64


def test_workflow_runs_full_history_and_preflight():
    text = (root() / ".github/workflows/phase3-preflight.yml").read_text("utf-8")
    assert "fetch-depth: 0" in text
    assert "python-version: \"3.12\"" in text
    assert "bash scripts/run_p3_00_preflight.sh" in text
    assert "actions/upload-artifact@v4" in text
    assert "P3_00_LOG_DIR: artifacts/conformance/phase3/${{ github.sha }}/logs" in text
    assert "path: artifacts/conformance/phase3/${{ github.sha }}/" in text


def test_pytest_warnings_are_errors_by_default():
    text = (root() / "pyproject.toml").read_text("utf-8")
    assert 'filterwarnings = ["error"]' in text
    assert 'dev = ["pytest>=8"]' in text


def test_public_checkpoint_key_contains_no_private_material():
    data = (root() / "artifacts/checkpoints/g2/phase2-storage-public-key.pem").read_bytes()
    assert b"PUBLIC KEY" in data
    assert b"PRIVATE KEY" not in data


def test_preflight_contains_all_required_gates_in_fail_fast_order():
    text = (root() / "scripts/run_p3_00_preflight.sh").read_text("utf-8")
    markers = [
        "verify_phase2_checkpoint.py",
        "check_architecture_boundaries.py",
        "scan_secrets.py",
        "python -m pytest",
        "package_smoke.py",
        "write_p3_00_evidence.py",
    ]
    positions = [text.index(marker) for marker in markers]
    assert positions == sorted(positions)
    assert "set -euo pipefail" in text


def test_checkpoint_runtime_regression_gate_parses_count(monkeypatch):
    from types import SimpleNamespace

    from scripts import verify_phase2_checkpoint as verifier

    monkeypatch.setattr(
        verifier,
        "_run_regression",
        lambda repo: SimpleNamespace(returncode=0, stdout="116 passed in 1.00s\n"),
    )
    repo = root()
    result = verifier.verify_checkpoint(
        repo=repo,
        manifest_path=repo / "artifacts/checkpoints/g2/phase2-storage-checkpoint.json",
        signature_path=repo / "artifacts/checkpoints/g2/phase2-storage-checkpoint.sig",
        public_key_path=repo / "artifacts/checkpoints/g2/phase2-storage-public-key.pem",
        trust_path=repo / ".github/phase2-checkpoint-trust.json",
        run_tests=True,
    )
    assert result["runtime_test_count"] == 116


def test_adversarial_report_contains_exactly_50_rounds():
    import re

    text = (root() / "docs/adversarial/P3-00_ADVERSARIAL_VALIDATION_50R_KR.md").read_text("utf-8")
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
    assert rounds == list(range(1, 51))


def test_p3_00_artifact_validator_passes():
    from scripts.validate_p3_00_artifacts import validate

    validate(root())
