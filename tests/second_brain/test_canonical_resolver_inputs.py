"""Canonical resolver inputs fail closed on missing human-attestation identities."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from wiki_spike.memory_core.contracts import canonical_bytes

_ROOT = Path(__file__).resolve().parents[2]
_RESOLVER = _ROOT / "artifacts/product-release/second-brain-v1/resolver"
_CLI = _ROOT / "scripts/second_brain_contract_resolver.py"
_COVERAGE = "decision evidence does not exactly match the expected-scope manifest"


def _run_resolve(out: Path) -> subprocess.CompletedProcess[str]:
    root = _ROOT
    return subprocess.run(
        [
            sys.executable,
            str(_CLI),
            "resolve",
            "--records-dir",
            str(root / "artifacts/product-release/second-brain-v1/decisions"),
            "--resolved-scope",
            str(_RESOLVER / "resolved-scope.json"),
            "--expected-scopes",
            str(root / "artifacts/product-release/second-brain-v1/governance/expected-scopes.json"),
            "--aggregate",
            str(_RESOLVER / "aggregate-envelope.json"),
            "--trusted-bindings",
            str(root / "artifacts/product-release/second-brain-v1/governance/trusted-bindings.json"),
            "--evidence-manifest",
            str(_RESOLVER / "evidence-manifest-envelope.json"),
            "--now",
            "2026-08-21T15:00:00Z",
            "--out",
            str(out),
        ],
        capture_output=True,
        check=False,
        text=True,
    )


def test_resolver_input_files_are_canonical() -> None:
    for name in (
        "resolved-scope.json",
        "aggregate-envelope.json",
        "evidence-manifest-envelope.json",
    ):
        path = _RESOLVER / name
        raw = path.read_bytes()
        assert raw == canonical_bytes(json.loads(raw))


def test_real_resolver_fail_closes_on_missing_human_attestation_identities(
    tmp_path: Path,
) -> None:
    out = tmp_path / "receipt.json"
    result = _run_resolve(out)
    combined = result.stdout + result.stderr
    assert result.returncode != 0
    assert "FAIL:" in result.stderr
    assert _COVERAGE in combined
    assert not out.exists()
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined
