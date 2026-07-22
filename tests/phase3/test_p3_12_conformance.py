from __future__ import annotations

import base64
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.p3_12_conformance import (
    CONTRACT_RELEASE,
    GateExecution,
    PreflightError,
    apply_negative_fixture,
    build_evidence,
    load_and_validate_matrix,
    source_inventory,
    validate_matrix,
    validate_negative_fixture,
    validate_required_adrs,
    verify_inventory,
)
from scripts.preflight_common import strict_json_load, write_canonical_json
from scripts.verify_g3_checkpoint import verify_g3_checkpoint


def root() -> Path:
    return Path(__file__).resolve().parents[2]


@contextmanager
def g3_release_tree():
    """Expose the immutable signed G3 tag without treating current Phase 4 files as G3."""
    parent = Path(tempfile.mkdtemp(prefix="wiki-g3-test-"))
    target = parent / "release"
    added = False
    try:
        result = subprocess.run(
            ["git", "worktree", "add", "--detach", str(target), "phase3-core-v1.0.0^{commit}"],
            cwd=root(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"cannot create G3 release worktree: {result.stderr}")
        added = True
        yield target
    finally:
        if added:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(target)],
                cwd=root(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            subprocess.run(
                ["git", "worktree", "prune"], cwd=root(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
        shutil.rmtree(parent, ignore_errors=True)


def matrix() -> dict:
    return strict_json_load(
        root() / "artifacts/conformance/phase3/G3/requirements.json",
        require_canonical=True,
    )


def committed_inventory() -> dict:
    return strict_json_load(
        root() / "artifacts/checkpoints/g3/phase3-source-inventory.json",
        require_canonical=True,
    )


def copy_verification_repo(tmp_path: Path) -> Path:
    destination = tmp_path / "repo"
    destination.mkdir()
    with g3_release_tree() as release:
        inventory = strict_json_load(
            release / "artifacts/checkpoints/g3/phase3-source-inventory.json",
            require_canonical=True,
        )
        paths = [entry["path"] for entry in inventory["entries"]]
        extras = [
            "artifacts/checkpoints/g2/phase2-storage-checkpoint.json",
            "artifacts/checkpoints/g3/phase3-source-inventory.json",
            "artifacts/checkpoints/g3/phase3-g3-checkpoint.json",
            "artifacts/checkpoints/g3/phase3-g3-checkpoint.sig",
            "artifacts/checkpoints/g3/phase3-g3-public-key.pem",
            ".github/phase3-g3-checkpoint-trust.json",
        ]
        for relative in sorted(set(paths + extras)):
            source = release / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    return destination


def test_committed_matrix_has_exact_requirement_coverage():
    validated = load_and_validate_matrix(
        root(), root() / "artifacts/conformance/phase3/G3/requirements.json"
    )
    assert [row["requirement_id"] for row in validated["requirements"]] == [
        f"P3-F-{index:03d}" for index in range(1, 21)
    ]


def test_committed_g3_checkpoint_verifies():
    with g3_release_tree() as release:
        result = verify_g3_checkpoint(repo=release)
    assert result["status"] == "pass"
    assert result["contract_release"] == CONTRACT_RELEASE
    assert int(result["phase3_test_count"]) >= 256
    assert int(result["total_test_count"]) >= 390


def test_requirement_gap_is_rejected():
    value = matrix()
    value["requirements"].pop(4)
    with pytest.raises(PreflightError, match="coverage/order"):
        validate_matrix(root(), value)


def test_duplicate_requirement_is_rejected():
    value = matrix()
    value["requirements"][1] = deepcopy(value["requirements"][0])
    with pytest.raises(PreflightError, match="coverage/order"):
        validate_matrix(root(), value)


def test_missing_bound_path_is_rejected():
    value = matrix()
    value["requirements"][0]["implementation_paths"] = ["src/wiki_spike/memory_core/missing.py"]
    with pytest.raises(PreflightError, match="missing or unsafe"):
        validate_matrix(root(), value)


def test_unknown_gate_is_rejected():
    value = matrix()
    value["requirements"][0]["gate_ids"] = ["always_pass"]
    with pytest.raises(PreflightError, match="unknown gate"):
        validate_matrix(root(), value)


def test_unsorted_or_duplicate_requirement_paths_are_rejected():
    value = matrix()
    value["requirements"][0]["test_paths"] = [
        "tests/phase3/test_p3_10_recovery.py",
        "tests/phase3/test_p3_05_changeset_publication.py",
    ]
    with pytest.raises(PreflightError, match="sorted and unique"):
        validate_matrix(root(), value)


def test_committed_negative_fixture_blocks_pass():
    validate_negative_fixture(
        root(), matrix(), root() / "tests/phase3/fixtures/g3-negative-gate.json"
    )


def test_negative_fixture_that_does_not_break_gate_is_rejected():
    value = matrix()
    fixture = {
        "fixture_version": "phase3-g3-negative-fixture-v1",
        "operation": "remove_gate",
        "requirement_id": "P3-F-019",
        "gate_id": "boundary_lint",
    }
    mutated = apply_negative_fixture(value, fixture)
    # Preserve the required gate via a second requirement: the matrix still fails
    # because P3-F-019 itself is no longer tied to its boundary proof.
    with pytest.raises(PreflightError):
        validate_matrix(root(), mutated)


def test_source_inventory_contains_load_bearing_zones():
    inventory = committed_inventory()
    paths = {entry["path"] for entry in inventory["entries"]}
    required = {
        "src/wiki_spike/memory_core/contracts.py",
        "src/wiki_spike/memory_core/recovery.py",
        "src/wiki_spike/memory_core/operability.py",
        "tests/phase3/test_p3_12_conformance.py",
        "schemas/phase3/g3-checkpoint.schema.json",
        "scripts/verify_g3_checkpoint.py",
        "docs/adr/ADR-0010-phase3-g3-conformance-checkpoint.md",
        ".github/workflows/phase3-g3-conformance.yml",
    }
    assert required <= paths


def test_checkpoint_artifacts_are_not_self_inventoried():
    paths = {entry["path"] for entry in committed_inventory()["entries"]}
    assert not any(path.startswith("artifacts/checkpoints/g3/") for path in paths)
    assert not any("/runs/" in path for path in paths)


def test_immutable_release_source_inventory_matches_committed_root():
    with g3_release_tree() as release:
        inventory = strict_json_load(
            release / "artifacts/checkpoints/g3/phase3-source-inventory.json",
            require_canonical=True,
        )
        assert verify_inventory(release, inventory)["source_root"] == inventory["source_root"]


def test_source_tamper_is_rejected(tmp_path):
    repo = tmp_path / "repo"
    with g3_release_tree() as release:
        inventory = strict_json_load(
            release / "artifacts/checkpoints/g3/phase3-source-inventory.json",
            require_canonical=True,
        )
        for entry in inventory["entries"]:
            source = release / entry["path"]
            target = repo / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    target = repo / "src/wiki_spike/memory_core/contracts.py"
    target.write_bytes(target.read_bytes() + b"\n# tampered\n")
    with pytest.raises(PreflightError, match="do not match"):
        verify_inventory(repo, inventory)


def test_unsorted_inventory_is_rejected():
    value = deepcopy(committed_inventory())
    value["entries"][0], value["entries"][1] = value["entries"][1], value["entries"][0]
    with pytest.raises(PreflightError, match="strictly sorted|root mismatch"):
        verify_inventory(root(), value)


def test_checkpoint_id_tamper_is_rejected(tmp_path):
    repo = copy_verification_repo(tmp_path)
    path = repo / "artifacts/checkpoints/g3/phase3-g3-checkpoint.json"
    value = strict_json_load(path, require_canonical=True)
    value["checkpoint"]["acceptance"]["minimum_total_tests"] = "1"
    write_canonical_json(path, value)
    with pytest.raises(PreflightError, match="checkpoint id mismatch"):
        verify_g3_checkpoint(repo=repo, verify_git_lineage=False, verify_test_counts=False)


def test_checkpoint_signature_tamper_is_rejected(tmp_path):
    repo = copy_verification_repo(tmp_path)
    (repo / "artifacts/checkpoints/g3/phase3-g3-checkpoint.sig").write_text(
        base64.b64encode(b"x" * 64).decode("ascii"), encoding="ascii"
    )
    with pytest.raises(PreflightError, match="signature verification failed"):
        verify_g3_checkpoint(repo=repo, verify_git_lineage=False, verify_test_counts=False)


def test_trust_or_public_key_substitution_is_rejected(tmp_path):
    repo = copy_verification_repo(tmp_path)
    key = Ed25519PrivateKey.generate().public_key()
    from cryptography.hazmat.primitives import serialization
    (repo / "artifacts/checkpoints/g3/phase3-g3-public-key.pem").write_bytes(
        key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(PreflightError, match="fingerprint"):
        verify_g3_checkpoint(repo=repo, verify_git_lineage=False, verify_test_counts=False)


def test_g2_binding_is_required(tmp_path):
    repo = copy_verification_repo(tmp_path)
    path = repo / "artifacts/checkpoints/g2/phase2-storage-checkpoint.json"
    value = strict_json_load(path, require_canonical=True)
    value["checkpoint_id"] = "0" * 64
    write_canonical_json(path, value)
    with pytest.raises(PreflightError, match="G2 checkpoint"):
        verify_g3_checkpoint(repo=repo, verify_git_lineage=False, verify_test_counts=False)


def test_lineage_anchor_must_be_available_and_ancestor(tmp_path):
    repo = copy_verification_repo(tmp_path)
    with pytest.raises(PreflightError, match="lineage anchor"):
        verify_g3_checkpoint(repo=repo, verify_git_lineage=True, verify_test_counts=False)


def test_test_inventory_floor_is_enforced_by_committed_checkpoint():
    with g3_release_tree() as release:
        result = verify_g3_checkpoint(repo=release, verify_test_counts=True)
    assert int(result["phase3_test_count"]) >= 256
    assert int(result["total_test_count"]) >= 390


def test_required_adr_registry_is_complete():
    paths = validate_required_adrs(root())
    assert len([path for path in paths if Path(path).name.startswith("ADR-")]) >= 10
    assert any("ADR-0010-" in path for path in paths)


def test_evidence_contract_contains_hashes_not_log_bodies():
    execution = GateExecution(
        gate_id="boundary_lint",
        command=("python", "scripts/check_architecture_boundaries.py"),
        status="pass",
        exit_code="0",
        output_sha256="a" * 64,
        passed_tests=None,
        log_path="logs/boundary_lint.log",
    )
    evidence = build_evidence(
        root(),
        checkpoint_id="b" * 64,
        source_root="c" * 64,
        matrix_digest="d" * 64,
        executions=(execution,),
    )
    serialized = json.dumps(evidence, sort_keys=True)
    assert "stdout" not in serialized
    assert "prompt" not in serialized
    assert "credential" not in serialized
    assert evidence["gate_executions"][0]["output_sha256"] == "a" * 64


def test_evidence_binds_checkpoint_source_and_matrix():
    execution = GateExecution("g3_checkpoint", ("verify",), "pass", "0", "e" * 64, None, "g3.log")
    evidence = build_evidence(
        root(), checkpoint_id="1" * 64, source_root="2" * 64,
        matrix_digest="3" * 64, executions=(execution,),
    )
    assert evidence["checkpoint_id"] == "1" * 64
    assert evidence["source_root"] == "2" * 64
    assert evidence["matrix_sha256"] == "3" * 64
    assert len(evidence["evidence_id"]) == 64


def test_workflow_runs_closed_catalog_and_uploads_evidence():
    text = (root() / ".github/workflows/phase3-g3-conformance.yml").read_text("utf-8")
    assert "fetch-depth: 0" in text
    assert "bash scripts/run_p3_12_gate.sh" in text
    assert "actions/upload-artifact@v4" in text
    assert "G3 conformance checkpoint" in text


def test_adversarial_report_contains_exactly_20_rounds():
    import re
    text = (root() / "docs/adversarial/P3-12_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    assert [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)] == list(range(1, 21))


def test_report_preserves_non_claims_and_phase_boundary():
    text = (root() / "artifacts/conformance/phase3/G3/report.md").read_text("utf-8")
    assert "Runtime" in text and "Application" in text
    assert "production" in text.lower()
    assert "phase3-core-v1.0.0" in (root() / "docs/releases/phase3-core-v1.0.0.md").read_text("utf-8")
