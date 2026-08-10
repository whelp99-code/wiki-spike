from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from test_deployment_monotonic_append_authority import authority, signed_evidence
from wiki_spike.infrastructure import second_brain_monotonic_append_authority as deployment
from wiki_spike.infrastructure.second_brain_monotonic_append_authority import (
    DeploymentAuthorityError, DeploymentMonotonicAppendAuthority, write_live_operation_denial_receipt,
)


def test_injected_trusted_clock_is_independent_of_a_host_clock_step(tmp_path, monkeypatch):
    fixed = datetime(2026, 1, 1, tzinfo=timezone.utc)
    subject, _ = authority(tmp_path, trusted_clock=lambda: fixed)
    first = subject.snapshot(request_nonce="a" * 64)

    class HostClockAfterStep:
        @classmethod
        def now(cls, unused_timezone):
            return datetime(2099, 1, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(deployment, "datetime", HostClockAfterStep)
    advanced = subject.compare_and_advance(
        expected_revision=0, event={"kind": "trusted-time-only"}, request_nonce="b" * 64,
    )
    assert first.issued_at == advanced.issued_at == "2026-01-01T00:00:00Z"
    assert advanced.events[-1]["recorded_at"] == "2026-01-01T00:00:00Z"


@pytest.mark.parametrize("trusted_clock", [
    lambda: datetime(2026, 1, 1),
    lambda: datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=9))),
])
def test_naive_or_noncanonical_trusted_clock_fails_before_any_mutation(tmp_path, trusted_clock):
    with pytest.raises(DeploymentAuthorityError, match="canonical UTC"):
        authority(tmp_path, trusted_clock=trusted_clock)
    assert not (tmp_path / "authority.json").exists()


def test_rejects_revision_replay_before_any_second_mutation(tmp_path):
    subject, _ = authority(tmp_path)
    subject.compare_and_advance(expected_revision=0, event={"kind": "one"}, request_nonce="a" * 64)
    with pytest.raises(DeploymentAuthorityError, match="revision conflict"):
        subject.compare_and_advance(expected_revision=0, event={"kind": "replay"}, request_nonce="b" * 64)
    assert json.loads((tmp_path / "authority.json").read_text())["events"][0]["kind"] == "one"


def test_rejects_rollback_tamper_and_never_reinitializes_authority_state(tmp_path):
    subject, _ = authority(tmp_path)
    subject.compare_and_advance(expected_revision=0, event={"kind": "one"}, request_nonce="a" * 64)
    (tmp_path / "authority.json").write_text('{"events":[],"measurement_binding":"' + "b" * 64 + '","schema":"second-brain-deployment-monotonic-authority-state-v1"}')
    with pytest.raises(DeploymentAuthorityError, match="state"):
        subject.snapshot(request_nonce="b" * 64)


def test_rejects_malformed_or_unbound_state_without_permissive_repair(tmp_path):
    subject, _ = authority(tmp_path)
    (tmp_path / "authority.json").write_text('{"schema":"wrong","events":[]}')
    with pytest.raises(DeploymentAuthorityError):
        subject.snapshot(request_nonce="a" * 64)
    assert (tmp_path / "authority.json").read_text() == '{"schema":"wrong","events":[]}'


@pytest.mark.parametrize("mutation", [
    lambda value: value.__setitem__("signature", "00" * 64),
    lambda value: value.__setitem__("unknown", "field"),
    lambda value: value.__setitem__("measurement_binding", "c" * 64),
])
def test_rejects_forged_unknown_or_mismatched_evidence_before_authority_mutation(tmp_path, mutation):
    subject, key = authority(tmp_path)
    evidence = signed_evidence(subject, key); mutation(evidence)
    with pytest.raises(DeploymentAuthorityError):
        subject.verify_deployment_evidence(evidence, measurement_binding="b" * 64)
    assert not (tmp_path / "authority.json").exists()


def test_receipt_collision_is_create_only_and_preserves_first_receipt(tmp_path):
    subject, _ = authority(tmp_path)
    path = tmp_path / "receipt.json"
    write_live_operation_denial_receipt(path=path, authority=subject, operation="status")
    first = path.read_bytes()
    with pytest.raises(DeploymentAuthorityError):
        write_live_operation_denial_receipt(path=path, authority=subject, operation="verify")
    assert path.read_bytes() == first
    assert not list(tmp_path.glob("receipt.json.*"))


def test_two_independent_adapters_cannot_win_the_same_revision_race(tmp_path):
    first, key = authority(tmp_path)
    second = DeploymentMonotonicAppendAuthority(
        state_path=tmp_path / "authority.json", evidence=first._evidence, signing_key=key,
        snapshot_factory=first._snapshot_factory, trusted_clock=first._trusted_clock,
    )
    second.verify_deployment_evidence(signed_evidence(second, key), measurement_binding="b" * 64)
    assert first.snapshot(request_nonce="a" * 64).revision == second.snapshot(request_nonce="b" * 64).revision == 0
    first.compare_and_advance(expected_revision=0, event={"kind": "first"}, request_nonce="c" * 64)
    with pytest.raises(DeploymentAuthorityError, match="head changed"):
        second.compare_and_advance(expected_revision=0, event={"kind": "second"}, request_nonce="d" * 64)
    assert json.loads((tmp_path / "authority.json").read_text())["events"][0]["kind"] == "first"


@pytest.mark.parametrize("failed_call", ["write", "fsync"])
def test_authority_write_failure_leaves_no_partial_state_or_temporary_file(tmp_path, monkeypatch, failed_call):
    subject, _ = authority(tmp_path)
    original = getattr(deployment.os, failed_call)
    def fail_once(*args, **kwargs):
        raise OSError("injected persistence failure")
    monkeypatch.setattr(deployment.os, failed_call, fail_once)
    with pytest.raises(DeploymentAuthorityError):
        subject.snapshot(request_nonce="a" * 64)
    assert not (tmp_path / "authority.json").exists()
    assert not [path for path in tmp_path.glob("authority.json.*") if path.name != "authority.json.lock"]
    monkeypatch.setattr(deployment.os, failed_call, original)


@pytest.mark.parametrize("failed_call", ["write", "fsync"])
def test_receipt_write_failure_leaves_no_partial_receipt_or_temporary_file(tmp_path, monkeypatch, failed_call):
    subject, _ = authority(tmp_path)
    subject.snapshot(request_nonce="a" * 64)  # establish retained authority before faulting receipt publication
    original = getattr(deployment.os, failed_call)
    def fail_once(*args, **kwargs):
        raise OSError("injected publication failure")
    monkeypatch.setattr(deployment.os, failed_call, fail_once)
    with pytest.raises(DeploymentAuthorityError):
        write_live_operation_denial_receipt(path=tmp_path / "receipt.json", authority=subject, operation="status")
    assert not (tmp_path / "receipt.json").exists()
    assert not list(tmp_path.glob("receipt.json.*"))
    monkeypatch.setattr(deployment.os, failed_call, original)


def test_state_and_receipt_reject_original_symlink_paths_before_resolution(tmp_path):
    subject, key = authority(tmp_path)
    state_alias = tmp_path / "state-alias.json"
    state_alias.symlink_to(tmp_path / "state-target.json")
    with pytest.raises(DeploymentAuthorityError, match="alias"):
        DeploymentMonotonicAppendAuthority(
            state_path=state_alias, evidence=subject._evidence, signing_key=key,
            snapshot_factory=subject._snapshot_factory, trusted_clock=subject._trusted_clock,
        )
    receipt_dir = tmp_path / "receipt-dir"
    receipt_dir.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(DeploymentAuthorityError, match="alias"):
        write_live_operation_denial_receipt(path=receipt_dir / "receipt.json", authority=subject, operation="status")


def test_same_revision_event_tamper_without_resigning_is_rejected_before_snapshot(tmp_path):
    subject, _ = authority(tmp_path)
    subject.compare_and_advance(expected_revision=0, event={"kind": "one"}, request_nonce="a" * 64)
    path = tmp_path / "authority.json"
    state = json.loads(path.read_text()); state["events"][0]["kind"] = "tampered"
    path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    before = path.read_bytes()
    with pytest.raises(DeploymentAuthorityError):
        subject.snapshot(request_nonce="b" * 64)
    assert path.read_bytes() == before


def test_restart_rejects_signed_old_empty_state_when_fresh_evidence_pins_rev1(tmp_path):
    subject, key = authority(tmp_path)
    subject.snapshot(request_nonce="a" * 64)
    path = tmp_path / "authority.json"; signed_empty = path.read_bytes()
    subject.compare_and_advance(expected_revision=0, event={"kind": "one"}, request_nonce="b" * 64)
    head = json.loads(path.read_text())
    restarted = DeploymentMonotonicAppendAuthority(
        state_path=path, evidence=subject._evidence, signing_key=key,
        snapshot_factory=subject._snapshot_factory, trusted_clock=subject._trusted_clock,
    )
    path.write_bytes(signed_empty)
    with pytest.raises(DeploymentAuthorityError, match="head"):
        restarted.verify_deployment_evidence(
            signed_evidence(restarted, key, revision=head["revision"], root=head["root"]), measurement_binding="b" * 64,
        )
    assert path.read_bytes() == signed_empty


def test_snapshot_and_advance_reject_before_evidence_anchor(tmp_path):
    seeded, key = authority(tmp_path)
    raw = seeded._evidence
    subject = DeploymentMonotonicAppendAuthority(
        state_path=tmp_path / "pre-evidence.json", evidence=raw, signing_key=key,
        snapshot_factory=seeded._snapshot_factory, trusted_clock=seeded._trusted_clock,
    )
    with pytest.raises(DeploymentAuthorityError, match="evidence"):
        subject.snapshot(request_nonce="a" * 64)
    with pytest.raises(DeploymentAuthorityError, match="evidence"):
        subject.compare_and_advance(expected_revision=0, event={"kind": "x"}, request_nonce="b" * 64)
    assert not (tmp_path / "pre-evidence.json").exists()


def test_throwing_snapshot_factory_cannot_publish_an_unreported_revision(tmp_path):
    seeded, key = authority(tmp_path)

    def raise_factory(**unused):
        raise RuntimeError("injected snapshot factory fault")

    subject = DeploymentMonotonicAppendAuthority(
        state_path=tmp_path / "factory-fault.json", evidence=seeded._evidence,
        signing_key=key, snapshot_factory=raise_factory, trusted_clock=seeded._trusted_clock,
    )
    subject.verify_deployment_evidence(
        signed_evidence(subject, key), measurement_binding="b" * 64,
    )
    with pytest.raises(DeploymentAuthorityError, match="snapshot factory"):
        subject.compare_and_advance(
            expected_revision=0, event={"kind": "must-not-commit"}, request_nonce="a" * 64,
        )
    assert not (tmp_path / "factory-fault.json").exists()


def test_fresh_head_mismatch_and_missing_state_with_nonzero_head_reject(tmp_path):
    subject, key = authority(tmp_path)
    subject.snapshot(request_nonce="a" * 64)
    with pytest.raises(DeploymentAuthorityError, match="head"):
        subject.verify_deployment_evidence(signed_evidence(subject, key, revision=1, root="a" * 64), measurement_binding="b" * 64)
    missing = tmp_path / "missing.json"
    other = DeploymentMonotonicAppendAuthority(
        state_path=missing, evidence=subject._evidence, signing_key=key,
        snapshot_factory=subject._snapshot_factory, trusted_clock=subject._trusted_clock,
    )
    with pytest.raises(DeploymentAuthorityError, match="missing"):
        other.verify_deployment_evidence(signed_evidence(other, key, revision=1, root="a" * 64), measurement_binding="b" * 64)
    assert not missing.exists()


def test_state_signer_substitution_is_rejected_without_mutating_state(tmp_path):
    subject, _ = authority(tmp_path)
    subject.snapshot(request_nonce="a" * 64)
    path = tmp_path / "authority.json"; state = json.loads(path.read_text())
    state["signer_fingerprint"] = "f" * 64
    path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    before = path.read_bytes()
    with pytest.raises(DeploymentAuthorityError):
        subject.snapshot(request_nonce="b" * 64)
    assert path.read_bytes() == before


def test_unsigned_retained_state_is_rejected_before_snapshot_mutation(tmp_path):
    subject, _ = authority(tmp_path)
    subject.snapshot(request_nonce="a" * 64)
    path = tmp_path / "authority.json"; state = json.loads(path.read_text())
    del state["signature"]
    path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    before = path.read_bytes()
    with pytest.raises(DeploymentAuthorityError, match="schema"):
        subject.snapshot(request_nonce="b" * 64)
    assert path.read_bytes() == before


def test_evidence_public_key_fingerprint_substitution_rejects_pre_mutation(tmp_path):
    subject, key = authority(tmp_path)
    evidence = signed_evidence(subject, key)
    evidence["public_key_fingerprint"] = "e" * 64
    before = (tmp_path / "authority.json").exists()
    with pytest.raises(DeploymentAuthorityError, match="pins"):
        subject.verify_deployment_evidence(evidence, measurement_binding="b" * 64)
    assert (tmp_path / "authority.json").exists() is before
