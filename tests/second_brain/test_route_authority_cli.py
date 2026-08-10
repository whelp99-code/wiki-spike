"""CLI-facing route authority contracts: all local, no live endpoint access."""
from __future__ import annotations

import json
import runpy
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_stage3_ledger_persistence import digest
from test_stage6_cutover import _cohort, _decision, _scope
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    CUTOVER_RUNBOOK_VERSION,
    PRE_MUTATION_ROLLBACK_RECEIPT_VERSION,
    PreMutationRollbackReceiptV1,
    route_switch_digest,
)
from wiki_spike.infrastructure.second_brain_route_authority import (
    DeploymentRouteSwitchAuthority,
    RouteAuthorityError,
    mint_route_authority_anchor,
)


CLI = Path(__file__).parents[2] / "scripts" / "second_brain_route_authority.py"
AUTHORITY = "route-authority:local-cutover"
TARGET = "wiki-spike://canonical"
ROLLBACK_TARGET = "legacy://readonly-banner"


def _write(path: Path, value: object) -> Path:
    path.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
    return path


def _rollback(cohort, decision) -> dict[str, object]:
    body: dict[str, object] = {
        "rollback_receipt_version": PRE_MUTATION_ROLLBACK_RECEIPT_VERSION,
        "cohort_manifest_digest": cohort.manifest_digest,
        "route_authority": AUTHORITY,
        "target": TARGET,
        "generation_digest": decision.generation_digest,
        "route_version": decision.route_version,
        "rollback_target": ROLLBACK_TARGET,
        "state": "ROUTE_SWITCHED_NO_MUTATION",
        "live_operation_authorized": False,
    }
    return body | {
        "rollback_receipt_digest": route_switch_digest(
            PRE_MUTATION_ROLLBACK_RECEIPT_VERSION, body
        )
    }


def _runbook(cohort, decision, rollback: dict[str, object], *, capability_epoch: str = "1") -> dict[str, object]:
    body: dict[str, object] = {
        "runbook_version": CUTOVER_RUNBOOK_VERSION,
        "cohort_manifest_digest": cohort.manifest_digest,
        "cutover_decision_digest": decision.decision_digest,
        "route_authority": AUTHORITY,
        "target": TARGET,
        "generation_digest": decision.generation_digest,
        "route_version": decision.route_version,
        "capability_epoch": capability_epoch,
        "visibility": "CANONICAL_ONLY",
        "pre_mutation_rollback_target": ROLLBACK_TARGET,
        "pre_mutation_rollback_receipt_digest": rollback["rollback_receipt_digest"],
        "approval_digests": [
            {"role": role, "approval_digest": digest(f"approval:{role}")}
            for role in ("migration", "product", "quality", "security")
        ],
        "postcheck_contract_digest": decision.contract_digest,
    }
    return body | {"runbook_digest": route_switch_digest(CUTOVER_RUNBOOK_VERSION, body)}


def _files(tmp_path: Path, *, capability_epoch: str = "1"):
    scope = _scope()
    cohort = _cohort(scope)
    decision = _decision(scope, cohort)
    rollback = _rollback(cohort, decision)
    runbook = _runbook(cohort, decision, rollback, capability_epoch=capability_epoch)
    paths = {
        "runbook": _write(tmp_path / "runbook.json", runbook),
        "decision": _write(tmp_path / "decision.json", decision.to_mapping()),
        "cohort": _write(tmp_path / "cohort.json", cohort.to_mapping()),
        "rollback": _write(tmp_path / "rollback.json", rollback),
    }
    return scope, cohort, decision, rollback, runbook, paths


def _authority(tmp_path: Path, *, capability_epoch: str = "1", output_name: str = "out.json"):
    scope, cohort, decision, rollback, runbook, paths = _files(tmp_path, capability_epoch=capability_epoch)
    key = Ed25519PrivateKey.generate()
    subject = DeploymentRouteSwitchAuthority(
        state_path=tmp_path / output_name, route_authority=AUTHORITY, signing_key=key,
    )
    anchor = mint_route_authority_anchor(
        route_authority=AUTHORITY, runbook_digest=runbook["runbook_digest"],
        cutover_decision_digest=decision.decision_digest, cohort_manifest_digest=cohort.manifest_digest,
        target=TARGET, resolved_scope_digest=decision.resolved_scope_digest,
        contract_digest=decision.contract_digest, source_manifest_digest=decision.source_manifest_digest,
        capability_manifest_digest=decision.capability_manifest_digest,
        benchmark_manifest_digest=decision.benchmark_manifest_digest,
        generation_digest=decision.generation_digest, checkpoint_digest=decision.checkpoint_digest,
        route_version=decision.route_version, capability_epoch=capability_epoch,
        visibility="CANONICAL_ONLY",
        pre_mutation_rollback_receipt_digest=rollback["rollback_receipt_digest"],
        state_revision="0", state_digest=sha256(canonical_bytes({
            "route_authority": AUTHORITY, "route_state": None,
        })).hexdigest(), signing_key=key,
    )
    subject.verify_trusted_anchor(anchor)
    return subject, key, (scope, cohort, decision, rollback, runbook, paths)


def _command(paths: dict[str, Path], out: Path, *, action: str = "switch-atomic") -> list[str]:
    return [
        action, "--runbook", str(paths["runbook"]), "--decision", str(paths["decision"]),
        "--cohort-manifest", str(paths["cohort"]), "--route-authority", AUTHORITY,
        "--target", TARGET, "--generation", digest("generation"), "--route-version", "route-v1",
        "--rollback-receipt", str(paths["rollback"]), "--out", str(out),
    ]


def test_rehearse_is_read_only_then_switch_and_verify_bind_one_complete_route_state(tmp_path):
    authority, _, (_, cohort, decision, rollback, _, paths) = _authority(tmp_path, output_name="switch.json")
    script = runpy.run_path(str(CLI))
    rehearsal = tmp_path / "rehearsal.json"
    assert script["run_with_authority"](authority, _command(paths, rehearsal, action="rehearse")) == 0
    assert not (tmp_path / "switch.json").exists()
    rehearsal_data = json.loads(rehearsal.read_text())
    assert rehearsal_data["state"] == "ROUTE_SWITCHED_NO_MUTATION"
    assert rehearsal_data["live_operation_authorized"] is False

    switched = tmp_path / "switch.json"
    assert script["run_with_authority"](authority, _command(paths, switched)) == 0
    switch_bundle = json.loads(switched.read_text())
    switch_data = switch_bundle["receipt"]
    assert switch_bundle["route_state"]["state"] == "CANONICAL_MUTATED"
    assert switch_data["cohort_manifest_digest"] == cohort.manifest_digest
    assert switch_data["contract_digest"] == decision.contract_digest
    assert switch_data["pre_mutation_rollback_receipt_digest"] == rollback["rollback_receipt_digest"]
    assert switch_data["live_operation_authorized"] is False

    postcheck = tmp_path / "postcheck.json"
    verify = [
        "verify", "--route-authority", AUTHORITY, "--target", TARGET,
        "--generation", digest("generation"), "--route-version", "route-v1",
        "--receipt", str(switched), "--out", str(postcheck),
    ]
    assert script["run_with_authority"](authority, verify) == 0
    assert json.loads(postcheck.read_text())["operation"] == "VERIFY"
    with pytest.raises(RouteAuthorityError, match="external rollback is closed"):
        authority.external_rollback()


def test_public_cli_never_constructs_an_authority_and_preserves_help_and_invalid_rcs(tmp_path):
    _, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    out = tmp_path / "out.json"
    denied = subprocess.run(
        [sys.executable, str(CLI), *_command(paths, out)], text=True, capture_output=True, check=False,
    )
    assert denied.returncode == 2 and not out.exists()
    help_result = subprocess.run([sys.executable, str(CLI), "--help"], text=True, capture_output=True, check=False)
    invalid = subprocess.run([sys.executable, str(CLI), "nope"], text=True, capture_output=True, check=False)
    assert help_result.returncode == 0 and invalid.returncode == 2


def test_output_collision_is_refused_before_route_mutation(tmp_path):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path, output_name="collision.json")
    script = runpy.run_path(str(CLI))
    output = _write(tmp_path / "collision.json", {"already": "there"})
    assert script["run_with_authority"](authority, _command(paths, output)) == 2
    assert json.loads(output.read_text()) == {"already": "there"}
    assert authority.canonical_switch_output_path.read_bytes() == output.read_bytes()


def test_receipt_and_runbook_dtos_are_closed_and_hash_bound(tmp_path):
    _, _, (_, _, _, rollback, runbook, _) = _authority(tmp_path)
    assert PreMutationRollbackReceiptV1.from_mapping(rollback).rollback_receipt_digest == rollback["rollback_receipt_digest"]
    runbook["approval_digests"] = runbook["approval_digests"][:-1]
    with pytest.raises(Exception, match="approval_digests"):
        from wiki_spike.memory_core.second_brain_contracts import CutoverRunbookV1
        CutoverRunbookV1.from_mapping(runbook)
