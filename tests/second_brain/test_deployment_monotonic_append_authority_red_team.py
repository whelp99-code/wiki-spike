"""Task 48B red-team: artifact tampers, rollback, mismatch, and absent adapter."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from tests.second_brain.test_deployment_monotonic_append_authority import (
    DIGEST_FIELDS,
    MemoryInputs,
    authority,
    produce_request,
    signed_evidence,
    signed_world,
)
from tests.second_brain.test_native_shadow_measurement_cli import command, run, write_contracts

from wiki_spike.applications.second_brain_shadow_measurement import AuthoritySnapshot
from wiki_spike.infrastructure.second_brain_authority_factory import InstalledArtifactIdentity
from wiki_spike.infrastructure.second_brain_monotonic_append_authority import (
    DeploymentAuthorityError,
    DeploymentMonotonicAppendAuthority,
    produce_shadow_artifacts,
    verify_shadow_artifacts,
    write_live_operation_denial_receipt,
)


def test_verifier_rejects_tampered_inputs_and_installed_artifacts() -> None:
    key, req, bundle, root, config, inputs, artifacts = signed_world()
    cases: tuple[tuple[str, bytes], ...] = (
        ("db:native", b"tampered-db"),
        ("endpoint:native", b"tampered-endpoint"),
        ("key:measure", b"tampered-key"),
        ("scope:native", b"tampered-scope"),
        ("contract:native", b"tampered-contract"),
        ("source:native", b"tampered-source"),
        ("capability:native", b"tampered-capability"),
        ("benchmark:native", b"tampered-benchmark"),
        ("holdout:native", b"tampered-holdout"),
    )
    for ref, payload in cases:
        mutated = MemoryInputs({**inputs._items, ref: payload})
        with pytest.raises(DeploymentAuthorityError):
            verify_shadow_artifacts(
                bundle=bundle, root=root, config=config, inputs=mutated,
                artifacts=artifacts, public_key=key.public_key(),
            )
    for field, digest in (
        ("host_artifact_sha256", sha256(b"wheel-tamper").hexdigest()),
        ("executor_artifact_sha256", sha256(b"cli-tamper").hexdigest()),
        ("lockfile_sha256", sha256(b"lock-tamper").hexdigest()),
    ):
        wrong = InstalledArtifactIdentity(
            digest if field == "host_artifact_sha256" else artifacts.host_artifact_sha256,
            digest if field == "executor_artifact_sha256" else artifacts.executor_artifact_sha256,
            digest if field == "lockfile_sha256" else artifacts.lockfile_sha256,
        )
        with pytest.raises(DeploymentAuthorityError):
            verify_shadow_artifacts(
                bundle=bundle, root=root, config=config, inputs=inputs,
                artifacts=wrong, public_key=key.public_key(),
            )
    other = produce_shadow_artifacts(produce_request(cohort="other"), key)
    with pytest.raises(DeploymentAuthorityError):
        verify_shadow_artifacts(
            bundle=other[0], root=root, config=config, inputs=inputs,
            artifacts=artifacts, public_key=key.public_key(),
        )
    with pytest.raises(DeploymentAuthorityError):
        verify_shadow_artifacts(
            bundle=bundle, root=other[1], config=config, inputs=inputs,
            artifacts=artifacts, public_key=key.public_key(),
        )


def test_same_revision_tamper_and_restart_rollback_are_rejected(tmp_path: Path) -> None:
    subject, key, _ = authority(tmp_path)
    subject.compare_and_advance(expected_revision=0, event={"kind": "one"}, request_nonce="a" * 64)
    path = tmp_path / "authority.json"
    state = json.loads(path.read_text())
    state["events"][0]["kind"] = "tampered"
    path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    before = path.read_bytes()
    with pytest.raises(DeploymentAuthorityError):
        subject.snapshot(request_nonce="b" * 64)
    assert path.read_bytes() == before
    subject2, key2, _ = authority(tmp_path / "restart")
    subject2.snapshot(request_nonce="s" * 64)
    empty = (tmp_path / "restart" / "authority.json").read_bytes()
    subject2.compare_and_advance(expected_revision=0, event={"kind": "one"}, request_nonce="c" * 64)
    head = json.loads((tmp_path / "restart" / "authority.json").read_text())
    restarted = DeploymentMonotonicAppendAuthority(
        state_path=tmp_path / "restart" / "authority.json",
        evidence=subject2._evidence,
        signing_key=key2,
        snapshot_factory=AuthoritySnapshot,
        trusted_clock=subject2._trusted_clock,
    )
    (tmp_path / "restart" / "authority.json").write_bytes(empty)
    with pytest.raises(DeploymentAuthorityError):
        restarted.verify_deployment_evidence(
            signed_evidence(restarted, key2, revision=head["revision"], root=head["root"]),
            measurement_binding="b" * 64,
        )


def test_signature_and_endpoint_mismatch_fail_before_mutation(tmp_path: Path) -> None:
    subject, key, _ = authority(tmp_path)
    evidence = signed_evidence(subject, key)
    evidence["signature"] = "00" * 64
    with pytest.raises(DeploymentAuthorityError):
        subject.verify_deployment_evidence(evidence, measurement_binding="b" * 64)
    forged = signed_evidence(subject, key)
    forged["endpoint"] = "retention-authority://forged"
    with pytest.raises(DeploymentAuthorityError):
        subject.verify_deployment_evidence(forged, measurement_binding="b" * 64)
    with pytest.raises(DeploymentAuthorityError):
        authority(tmp_path / "naive", trusted_clock=lambda: datetime(2026, 1, 1))


def test_absent_adapter_public_cli_stays_rc2_and_writes_nothing(tmp_path: Path) -> None:
    _, fingerprint = write_contracts(tmp_path)
    result = run(command(tmp_path, fingerprint, "init"))
    assert result.returncode == 2
    assert not (tmp_path / "cohort.json").exists()
    assert not (tmp_path / "cohort.json.lock").exists()
    assert not (tmp_path / "authority.json").exists()


def test_revision_conflict_receipt_collision_and_missing_evidence(tmp_path: Path) -> None:
    subject, key, _ = authority(tmp_path)
    subject.compare_and_advance(expected_revision=0, event={"kind": "one"}, request_nonce="a" * 64)
    with pytest.raises(DeploymentAuthorityError):
        subject.compare_and_advance(expected_revision=0, event={"kind": "replay"}, request_nonce="b" * 64)
    path = tmp_path / "receipt.json"
    write_live_operation_denial_receipt(path=path, authority=subject, operation="status")
    first = path.read_bytes()
    with pytest.raises(DeploymentAuthorityError):
        write_live_operation_denial_receipt(path=path, authority=subject, operation="verify")
    assert path.read_bytes() == first
    raw = subject._evidence
    unbound = DeploymentMonotonicAppendAuthority(
        state_path=tmp_path / "pre-evidence.json",
        evidence=raw,
        signing_key=key,
        snapshot_factory=AuthoritySnapshot,
        trusted_clock=subject._trusted_clock,
    )
    with pytest.raises(DeploymentAuthorityError):
        unbound.snapshot(request_nonce="c" * 64)
    assert not (tmp_path / "pre-evidence.json").exists()
    assert set(DIGEST_FIELDS) <= set(raw.__dataclass_fields__)
