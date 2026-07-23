from __future__ import annotations

import json
from pathlib import Path
import re

from scripts.verify_g4_checkpoint import verify


def root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_signed_g4_checkpoint_and_inventory_verify():
    result = verify(root())
    assert result["status"] == "pass"
    assert result["contract_release"] == "phase4-runtime-v1.0.0"
    assert result["verified_files"] >= 40


def test_g4_requirements_cover_p4_f_001_through_020():
    value = json.loads((root() / "artifacts/conformance/phase4/G4/requirements.json").read_text("utf-8"))
    ids = [item["requirement_id"] for item in value["requirements"]]
    assert ids == [f"P4-F-{number:03d}" for number in range(1, 21)]
    assert all(item["status"] == "pass" for item in value["requirements"])


def test_every_remaining_work_unit_has_exactly_twenty_adversarial_rounds():
    for number in range(3, 15):
        path = root() / f"docs/adversarial/P4-{number:02d}_ADVERSARIAL_VALIDATION_20R_KR.md"
        text = path.read_text("utf-8")
        rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
        assert rounds == list(range(1, 21)), path


def test_phase4_public_api_has_no_storage_connector_ui_or_credentials():
    text = (root() / "src/wiki_spike/memory_runtime/phase4_api.py").read_text("utf-8")
    for forbidden in (
        "wiki_spike.controlplane", "wiki_spike.cas", "wiki_spike.publish",
        "wiki_spike.gitrepo", "wiki_spike.connectors", "wiki_spike.ui",
        "api_key", "access_token", "provider_client",
    ):
        assert forbidden not in text


def test_g4_workflow_runs_full_fail_closed_gate():
    text = (root() / ".github/workflows/phase4-g4-conformance.yml").read_text("utf-8")
    assert "fetch-depth: 0" in text
    assert "bash scripts/run_p4_14_gate.sh" in text
    script = (root() / "scripts/run_p4_14_gate.sh").read_text("utf-8")
    for marker in (
        "verify_g4_checkpoint.py", "check_runtime_boundaries.py",
        "check_architecture_boundaries.py", "scan_secrets.py",
        "pytest -W error", "package_smoke.py", "compileall",
    ):
        assert marker in script


def test_runtime_service_and_checkpoint_schemas_parse():
    for name in ("runtime-services.schema.json", "g4-checkpoint.schema.json"):
        value = json.loads((root() / "schemas/phase4" / name).read_text("utf-8"))
        assert value["$schema"].endswith("2020-12/schema")
