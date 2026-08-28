from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def active_trigger_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text("utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_required_compatibility_check_runs_only_operational_gate() -> None:
    workflow = (ROOT / ".github/workflows/phase3-preflight.yml").read_text("utf-8")
    assert "name: phase3-preflight" in workflow
    assert "name: P3-00 preflight" in workflow
    assert "bash scripts/run_operational_gate.sh" in workflow
    run_lines = [line.strip() for line in workflow.splitlines() if line.strip().startswith("run:")]
    assert not any("run_p3_00_preflight.sh" in line for line in run_lines)


def test_historical_phase_workflows_are_dispatch_only() -> None:
    for name in (
        "phase3-g3-conformance.yml",
        "phase4-preflight.yml",
        "phase4-g4-conformance.yml",
    ):
        lines = active_trigger_lines(ROOT / ".github/workflows" / name)
        on_index = lines.index("on:")
        permissions_index = lines.index("permissions:")
        triggers = lines[on_index + 1 : permissions_index]
        assert triggers == ["workflow_dispatch:"]
