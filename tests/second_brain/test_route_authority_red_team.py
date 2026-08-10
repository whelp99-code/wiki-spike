"""Adversarial coverage for the hash-bound, no-fallback route authority."""
from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest

from test_stage3_ledger_persistence import digest
from test_route_authority_cli import (
    AUTHORITY,
    CLI,
    TARGET,
    _authority,
    _command,
    _runbook,
    _write,
)
from wiki_spike.infrastructure import second_brain_route_authority as route_module
from wiki_spike.infrastructure.second_brain_route_authority import (
    DeploymentRouteSwitchAuthority,
    RouteAuthorityError,
    mint_route_authority_anchor,
)
from wiki_spike.memory_core.second_brain_contracts import CutoverRunbookV1, RouteAuthorityStateV1
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.second_brain_contracts import CUTOVER_RUNBOOK_VERSION, route_switch_digest


def _switch(authority, paths: dict[str, Path], out: Path) -> int:
    return runpy.run_path(str(CLI))["run_with_authority"](authority, _command(paths, out))


def test_missing_runbook_refuses_before_any_authority_mutation(tmp_path):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    paths["runbook"].unlink()
    assert _switch(authority, paths, tmp_path / "out.json") == 2
    assert not authority.canonical_switch_output_path.exists()


@pytest.mark.parametrize("mutation", [
    lambda book: book.__setitem__("approval_digests", book["approval_digests"][:-1]),
    lambda book: book.__setitem__("approval_digests", [*book["approval_digests"], book["approval_digests"][0]]),
    lambda book: book.__setitem__("approval_digests", [
        {"role": "operator", "approval_digest": book["approval_digests"][0]["approval_digest"]},
        *book["approval_digests"][1:],
    ]),
])
def test_missing_duplicate_or_wrong_four_role_approval_refuses_before_mutation(tmp_path, mutation):
    authority, _, (_, _, _, rollback, _, paths) = _authority(tmp_path)
    bad = json.loads(paths["runbook"].read_text())
    mutation(bad)
    _write(paths["runbook"], bad)
    assert _switch(authority, paths, tmp_path / "out.json") == 2
    assert not authority.canonical_switch_output_path.exists()


def test_anchor_refuses_capability_epoch_and_version_race_before_mutation(tmp_path):
    authority, _, (_, cohort, decision, rollback, _, paths) = _authority(tmp_path)
    raced = _runbook(cohort, decision, rollback, capability_epoch="2")
    _write(paths["runbook"], raced)
    assert _switch(authority, paths, tmp_path / "out.json") == 2
    assert not authority.canonical_switch_output_path.exists()


def test_forged_but_self_digested_decision_and_runbook_refuse_before_mutation(tmp_path):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    decision = json.loads(paths["decision"].read_text())
    decision["decision_id"] = "cutover-forged-but-well-formed"
    decision["decision_digest"] = canonical_ledger_digest(
        "cutover-decision-v1", {key: value for key, value in decision.items() if key != "decision_digest"}
    )
    runbook = json.loads(paths["runbook"].read_text())
    runbook["cutover_decision_digest"] = decision["decision_digest"]
    runbook["runbook_digest"] = route_switch_digest(
        CUTOVER_RUNBOOK_VERSION, {key: value for key, value in runbook.items() if key != "runbook_digest"}
    )
    _write(paths["decision"], decision)
    _write(paths["runbook"], runbook)
    assert _switch(authority, paths, tmp_path / "out.json") == 2
    assert not authority.canonical_switch_output_path.exists()


@pytest.mark.parametrize("field", ["target", "generation_digest", "checkpoint_digest"])
def test_wrong_target_generation_or_checkpoint_refuses_before_mutation(tmp_path, field):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    decision = json.loads(paths["decision"].read_text())
    decision[field] = "f" * 64 if field != "target" else "wiki-spike://wrong"
    # The existing decision body digest is intentionally stale; no parser may
    # accept this as a route candidate merely because other arguments match.
    _write(paths["decision"], decision)
    assert _switch(authority, paths, tmp_path / "out.json") == 2
    assert not authority.canonical_switch_output_path.exists()


def test_same_version_state_tamper_fallback_and_dual_write_fields_fail_closed(tmp_path):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path, output_name="switch.json")
    switched = authority.canonical_switch_output_path
    assert _switch(authority, paths, switched) == 0
    state_path = authority.canonical_switch_output_path
    state = json.loads(state_path.read_text())
    original_receipt = state["receipt"]
    state["route_state"]["target"] = "wiki-spike://same-version-tamper"
    state["legacy_fallback"] = "legacy://forbidden"
    _write(state_path, state)
    receipt = json.loads(switched.read_text())
    from wiki_spike.memory_core.second_brain_contracts import RouteSwitchReceiptV1
    with pytest.raises(RouteAuthorityError):
        authority.verify_atomic(receipt=RouteSwitchReceiptV1.from_mapping(original_receipt))
    with pytest.raises(Exception):
        RouteAuthorityStateV1.from_mapping(state["route_state"] | {"dual_write_target": "forbidden"})


def test_restart_rejects_old_head_and_accepts_only_fresh_signed_trusted_head(tmp_path):
    authority, key, (_, _, _, _, _, paths) = _authority(tmp_path, output_name="switch.json")
    old_anchor = authority._trusted_anchor
    assert old_anchor is not None
    assert _switch(authority, paths, tmp_path / "switch.json") == 0
    restarted = DeploymentRouteSwitchAuthority(
        state_path=authority.canonical_switch_output_path, route_authority=AUTHORITY, signing_key=key,
    )
    with pytest.raises(RouteAuthorityError, match="head does not match"):
        restarted.verify_trusted_anchor(old_anchor)
    state = json.loads(authority.canonical_switch_output_path.read_text())["route_state"]
    fresh = mint_route_authority_anchor(
        route_authority=AUTHORITY, runbook_digest=old_anchor.runbook_digest,
        cutover_decision_digest=old_anchor.cutover_decision_digest,
        cohort_manifest_digest=old_anchor.cohort_manifest_digest, target=old_anchor.target,
        resolved_scope_digest=old_anchor.resolved_scope_digest,
        contract_digest=old_anchor.contract_digest,
        source_manifest_digest=old_anchor.source_manifest_digest,
        capability_manifest_digest=old_anchor.capability_manifest_digest,
        benchmark_manifest_digest=old_anchor.benchmark_manifest_digest,
        generation_digest=old_anchor.generation_digest,
        checkpoint_digest=old_anchor.checkpoint_digest, route_version=old_anchor.route_version,
        capability_epoch=old_anchor.capability_epoch, visibility=old_anchor.visibility,
        pre_mutation_rollback_receipt_digest=old_anchor.pre_mutation_rollback_receipt_digest,
        state_revision=state["authority_revision"], state_digest=state["state_digest"], signing_key=key,
    )
    restarted.verify_trusted_anchor(fresh)


def test_unsigned_or_signature_tampered_deployment_anchor_never_establishes_trust(tmp_path):
    authority, key, _ = _authority(tmp_path)
    anchor = authority._trusted_anchor
    assert anchor is not None
    tampered = anchor.to_mapping() | {"signature": "00" * 64}
    fresh = DeploymentRouteSwitchAuthority(
        state_path=tmp_path / "other-route-state.json", route_authority=AUTHORITY, signing_key=key,
    )
    with pytest.raises(RouteAuthorityError, match="signature"):
        fresh.verify_trusted_anchor(tampered)
    assert not (tmp_path / "other-route-state.json").exists()


@pytest.mark.parametrize("failed_call", ["write", "fsync"])
def test_transaction_persistence_fault_leaves_no_partial_state_or_temp_file(tmp_path, monkeypatch, failed_call):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    def fail(*unused, **unused_kw):
        raise OSError("injected persistence failure")
    monkeypatch.setattr(route_module.os, failed_call, fail)
    assert _switch(authority, paths, tmp_path / "out.json") == 2
    assert not authority.canonical_switch_output_path.exists()
    assert not list(tmp_path.glob(f".{authority.canonical_switch_output_path.name}.*.tmp"))


@pytest.mark.parametrize("failed_call", ["write", "fsync", "link"])
def test_switch_bundle_publish_failures_never_leave_mutated_state_without_exact_output(tmp_path, monkeypatch, failed_call):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    original = getattr(route_module.os, failed_call)

    def fail(*unused, **unused_kw):
        raise OSError("injected bundle publication failure")

    monkeypatch.setattr(route_module.os, failed_call, fail)
    assert _switch(authority, paths, authority.canonical_switch_output_path) == 2
    assert not authority.canonical_switch_output_path.exists()
    assert not list(tmp_path.glob(f".{authority.canonical_switch_output_path.name}.*.tmp"))
    monkeypatch.setattr(route_module.os, failed_call, original)


def test_directory_fsync_failure_after_atomic_publish_recovers_and_returns_success(tmp_path, monkeypatch):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    original = route_module.os.fsync
    calls = 0

    def fail_after_publish(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected directory fsync failure")
        original(descriptor)

    monkeypatch.setattr(route_module.os, "fsync", fail_after_publish)
    output = authority.canonical_switch_output_path
    assert _switch(authority, paths, output) == 0
    bundle = json.loads(output.read_text())
    assert bundle["route_state"]["state"] == "CANONICAL_MUTATED"
    assert bundle["receipt"]["operation"] == "SWITCH_ATOMIC"


def test_receipt_writer_post_link_directory_fsync_failure_never_returns_rc2_with_final(tmp_path, monkeypatch):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    script = runpy.run_path(str(CLI))
    original = script["os"].fsync
    calls = 0

    def fail_second_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected post-link directory fsync failure")
        original(descriptor)

    monkeypatch.setattr(script["os"], "fsync", fail_second_fsync)
    output = tmp_path / "rehearsal.json"
    assert script["run_with_authority"](authority, _command(paths, output, action="rehearse")) == 0
    receipt = json.loads(output.read_text())
    assert receipt["operation"] == "REHEARSE"
    assert receipt["state"] == "ROUTE_SWITCHED_NO_MUTATION"


def test_post_link_fsync_failure_never_unlinks_a_replaced_collision(tmp_path, monkeypatch):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    script = runpy.run_path(str(CLI))
    original_link = script["os"].link
    original_fsync = script["os"].fsync
    calls = 0
    output = tmp_path / "rehearsal.json"

    def publish_then_replace(source: str, destination: str) -> None:
        original_link(source, destination)
        Path(destination).unlink()
        Path(destination).write_bytes(b'{"foreign":"collision"}')

    def fail_second_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected post-link directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(script["os"], "link", publish_then_replace)
    monkeypatch.setattr(script["os"], "fsync", fail_second_fsync)
    assert script["run_with_authority"](authority, _command(paths, output, action="rehearse")) == 2
    assert output.read_bytes() == b'{"foreign":"collision"}'


def test_post_link_fsync_failure_never_follows_or_unlinks_a_replaced_symlink(tmp_path, monkeypatch):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    script = runpy.run_path(str(CLI))
    original_link = script["os"].link
    original_fsync = script["os"].fsync
    calls = 0
    output = tmp_path / "rehearsal.json"

    def publish_then_replace(source: str, destination: str) -> None:
        original_link(source, destination)
        Path(destination).unlink()
        Path(destination).symlink_to(source)

    def fail_second_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected post-link directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(script["os"], "link", publish_then_replace)
    monkeypatch.setattr(script["os"], "fsync", fail_second_fsync)
    assert script["run_with_authority"](authority, _command(paths, output, action="rehearse")) == 2
    assert output.is_symlink()


def test_primary_repro_receipt_writer_failure_cannot_create_rc2_after_switch_mutation(tmp_path):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    script = runpy.run_path(str(CLI))

    def fail_if_called(*unused, **unused_kw):
        raise AssertionError("legacy second receipt publication must not be called")

    script["_write_new_receipt"] = fail_if_called
    output = authority.canonical_switch_output_path
    assert script["run_with_authority"](authority, _command(paths, output)) == 0
    bundle = json.loads(output.read_text())
    assert set(bundle) == {"state_schema", "route_state", "receipt", "signer_fingerprint", "signature"}
    assert bundle["receipt"]["state"] == "CANONICAL_MUTATED"


def test_output_path_race_never_overwrites_foreign_file_or_mutates_route(tmp_path, monkeypatch):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    output = authority.canonical_switch_output_path

    def lose_create_only_race(*unused, **unused_kw):
        output.write_bytes(b'{"foreign":"race"}')
        raise FileExistsError("raced output")

    monkeypatch.setattr(route_module.os, "link", lose_create_only_race)
    assert _switch(authority, paths, output) == 2
    assert json.loads(output.read_text()) == {"foreign": "race"}


def test_rename_fault_cannot_split_the_transaction_because_publish_is_create_only_link(tmp_path, monkeypatch):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    def fail_if_called(*unused, **unused_kw):
        raise OSError("rename must not be the route commit path")
    monkeypatch.setattr(route_module.os, "replace", fail_if_called)
    assert _switch(authority, paths, authority.canonical_switch_output_path) == 0
    assert authority.canonical_switch_output_path.exists()


def test_restart_retry_returns_success_from_the_exact_signed_bundle(tmp_path):
    authority, key, (_, _, _, _, _, paths) = _authority(tmp_path)
    output = authority.canonical_switch_output_path
    old_anchor = authority._trusted_anchor
    assert old_anchor is not None and _switch(authority, paths, output) == 0
    state = json.loads(output.read_text())["route_state"]
    fresh_anchor = mint_route_authority_anchor(
        route_authority=AUTHORITY, runbook_digest=old_anchor.runbook_digest,
        cutover_decision_digest=old_anchor.cutover_decision_digest,
        cohort_manifest_digest=old_anchor.cohort_manifest_digest, target=old_anchor.target,
        resolved_scope_digest=old_anchor.resolved_scope_digest,
        contract_digest=old_anchor.contract_digest,
        source_manifest_digest=old_anchor.source_manifest_digest,
        capability_manifest_digest=old_anchor.capability_manifest_digest,
        benchmark_manifest_digest=old_anchor.benchmark_manifest_digest,
        generation_digest=old_anchor.generation_digest,
        checkpoint_digest=old_anchor.checkpoint_digest, route_version=old_anchor.route_version,
        capability_epoch=old_anchor.capability_epoch, visibility=old_anchor.visibility,
        pre_mutation_rollback_receipt_digest=old_anchor.pre_mutation_rollback_receipt_digest,
        state_revision=state["authority_revision"], state_digest=state["state_digest"], signing_key=key,
    )
    restarted = DeploymentRouteSwitchAuthority(state_path=output, route_authority=AUTHORITY, signing_key=key)
    restarted.verify_trusted_anchor(fresh_anchor)
    assert _switch(restarted, paths, output) == 0


def test_postcheck_publication_failure_is_nonmutating_and_retry_recovers(tmp_path, monkeypatch):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    switch = authority.canonical_switch_output_path
    assert _switch(authority, paths, switch) == 0
    script = runpy.run_path(str(CLI))
    postcheck = tmp_path / "postcheck.json"
    verify = [
        "verify", "--route-authority", AUTHORITY, "--target", TARGET,
        "--generation", digest("generation"),
        "--route-version", "route-v1", "--receipt", str(switch), "--out", str(postcheck),
    ]
    def fail(*unused, **unused_kw):
        raise OSError("postcheck output fault")
    monkeypatch.setattr(script["os"], "write", fail)
    assert script["run_with_authority"](authority, verify) == 2
    assert switch.exists() and not postcheck.exists()
    monkeypatch.undo()
    assert script["run_with_authority"](authority, verify) == 0
    assert json.loads(postcheck.read_text())["operation"] == "VERIFY"


def test_invalid_input_error_never_reflects_raw_secret_content(tmp_path, capsys):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    runbook = json.loads(paths["runbook"].read_text())
    runbook["unexpected_secret"] = "TOKEN-DO-NOT-LEAK"
    _write(paths["runbook"], runbook)
    assert _switch(authority, paths, tmp_path / "out.json") == 2
    assert "TOKEN-DO-NOT-LEAK" not in capsys.readouterr().err


def test_route_state_parser_refuses_extra_fallback_or_dual_write_shape(tmp_path):
    authority, _, (_, _, _, _, _, paths) = _authority(tmp_path)
    assert _switch(authority, paths, authority.canonical_switch_output_path) == 0
    route_state = json.loads(authority.canonical_switch_output_path.read_text())["route_state"]
    for forbidden in ("legacy_query", "fallback_target", "dual_write_target"):
        with pytest.raises(Exception):
            RouteAuthorityStateV1.from_mapping(route_state | {forbidden: "forbidden"})
