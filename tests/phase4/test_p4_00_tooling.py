from __future__ import annotations

import json
from pathlib import Path
import re
import tempfile

from scripts.preflight_common import strict_json_load
from scripts.write_p4_00_evidence import (
    EVIDENCE_VERSION,
    MINIMUM_PHASE4_TESTS,
    build_evidence,
)


def root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_pin_and_runtime_boundary_policies_are_canonical():
    pin = strict_json_load(root() / ".github/phase4-g3-contract-pin.json", require_canonical=True)
    policy = strict_json_load(root() / ".github/phase4-runtime-boundaries.json", require_canonical=True)
    assert pin["pin"]["contract_release"] == "phase3-core-v1.0.0"
    assert policy["policy"]["runtime_root"] == "src/wiki_spike/memory_runtime"


def test_runtime_schema_is_versioned_by_p4_01():
    schema = json.loads((root() / "schemas/phase4/runtime-contracts.schema.json").read_text("utf-8"))
    assert schema["title"].endswith("P4-01")
    assert len(schema["oneOf"]) == 5
    assert schema["$defs"]["runtimeRequest"]["additionalProperties"] is False
    assert schema["$defs"]["runtimeResponse"]["additionalProperties"] is False


def test_phase4_workflow_checks_out_tags_runs_gate_and_uploads_evidence():
    text = (root() / ".github/workflows/phase4-preflight.yml").read_text("utf-8")
    assert "fetch-depth: 0" in text
    assert "fetch-tags: true" in text
    assert "bash scripts/run_p4_00_preflight.sh" in text
    assert "P4-00 contract pin" in text
    assert "actions/upload-artifact@v4" in text



def test_p4_preflight_runs_only_phase_specific_validation():
    text = (root() / "scripts/run_p4_00_preflight.sh").read_text("utf-8")
    assert "verify_phase3_contract_pin.py" in text
    assert "check_runtime_boundaries.py" in text
    assert "check_architecture_boundaries.py" in text
    assert "pytest -W error -q tests/phase4" in text
    assert "scan_secrets.py" not in text
    assert 'pytest -W error -q >"$LOG_DIR/regression.log"' not in text
    assert "package_smoke.py" not in text


def test_p4_evidence_contains_only_focused_gate_results():
    ci_root = root() / ".ci"
    ci_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="p4-00-test-", dir=ci_root) as temp_dir:
        log_dir = Path(temp_dir)
        (log_dir / "phase3-pin.json").write_text(
            json.dumps(
                {
                    "status": "pass",
                    "contract_release": "phase3-core-v1.0.0",
                    "g3_checkpoint_id": "a" * 64,
                    "pin_id": "b" * 64,
                }
            ),
            encoding="utf-8",
        )
        for name in ("runtime-boundaries.json", "architecture-boundaries.json"):
            (log_dir / name).write_text(
                json.dumps({"status": "pass", "violations": []}),
                encoding="utf-8",
            )
        (log_dir / "targeted-tests.log").write_text(
            f"{MINIMUM_PHASE4_TESTS} passed in 1.00s\n",
            encoding="utf-8",
        )

        evidence = build_evidence(root(), log_dir)

    assert evidence["evidence_version"] == EVIDENCE_VERSION
    assert set(evidence["commands"]) == {
        "phase3_contract_pin",
        "runtime_boundaries",
        "architecture_boundaries",
        "targeted_tests",
    }
    assert evidence["commands"]["targeted_tests"]["passed_tests"] == str(
        MINIMUM_PHASE4_TESTS
    )


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


def test_p4_02_intent_temporal_schema_is_strict_and_versioned():
    schema = json.loads((root() / "schemas/phase4/intent-temporal-contracts.schema.json").read_text("utf-8"))
    assert schema["title"].endswith("P4-02")
    assert len(schema["oneOf"]) == 4
    definitions = schema["$defs"]
    assert set(definitions) == {
        "intentTemporalInput",
        "intentResolution",
        "temporalResolution",
        "intentTemporalResolution",
    }
    assert all(value["additionalProperties"] is False for value in definitions.values())


def test_p4_02_documents_preserve_runtime_and_phase_boundaries():
    adr = (root() / "docs/adr/ADR-0013-intent-temporal-resolution.md").read_text("utf-8")
    report = (root() / "artifacts/conformance/phase4/P4-02/report.md").read_text("utf-8")
    adversarial = (root() / "docs/adversarial/P4-02_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    assert "IANA" in adr and "LLM" in adr
    assert "P4-F-002" in report and "Phase 5" in report
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", adversarial, re.M)]
    assert rounds == list(range(1, 21))
