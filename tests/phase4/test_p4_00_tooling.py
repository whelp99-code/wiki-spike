from __future__ import annotations

import json
from pathlib import Path
import re

from scripts.preflight_common import strict_json_load


def root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_pin_and_runtime_boundary_policies_are_canonical():
    pin = strict_json_load(root() / ".github/phase4-g3-contract-pin.json", require_canonical=True)
    policy = strict_json_load(root() / ".github/phase4-runtime-boundaries.json", require_canonical=True)
    assert pin["pin"]["contract_release"] == "phase3-core-v1.0.0"
    assert policy["policy"]["runtime_root"] == "src/wiki_spike/memory_runtime"


def test_runtime_schema_is_fail_closed_until_p4_01():
    schema = json.loads((root() / "schemas/phase4/runtime-contracts.schema.json").read_text("utf-8"))
    assert schema["not"] == {}
    assert "P4-01" in schema["description"]


def test_phase4_workflow_checks_out_tags_runs_gate_and_uploads_evidence():
    text = (root() / ".github/workflows/phase4-preflight.yml").read_text("utf-8")
    assert "fetch-depth: 0" in text
    assert "fetch-tags: true" in text
    assert "bash scripts/run_p4_00_preflight.sh" in text
    assert "P4-00 contract pin" in text
    assert "actions/upload-artifact@v4" in text


def test_phase3_g3_workflow_verifies_immutable_tag_not_evolving_head():
    text = (root() / ".github/workflows/phase3-g3-conformance.yml").read_text("utf-8")
    assert "ref: phase3-core-v1.0.0" in text
    assert "fa7523344008c8c5bfbcc6aca790f297524f33dc" in text
    assert "git cat-file -t" in text
    assert "bash scripts/run_p3_12_gate.sh" in text


def test_existing_preflight_includes_phase3_pin_and_runtime_boundary():
    text = (root() / "scripts/run_p3_00_preflight.sh").read_text("utf-8")
    assert "verify_phase3_contract_pin.py" in text
    assert "check_runtime_boundaries.py" in text


def test_branch_protection_document_names_phase4_check():
    text = (root() / ".github/BRANCH_PROTECTION_REQUIRED_CHECKS.md").read_text("utf-8")
    assert "phase4-preflight / P4-00 contract pin" in text


def test_adversarial_report_contains_exactly_20_rounds():
    text = (root() / "docs/adversarial/P4-00_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
    assert rounds == list(range(1, 21))


def test_conformance_report_preserves_phase_boundary():
    text = (root() / "artifacts/conformance/phase4/P4-00/report.md").read_text("utf-8")
    assert "P4-01" in text
    assert "Phase 5" in text
    assert "Production" in text
