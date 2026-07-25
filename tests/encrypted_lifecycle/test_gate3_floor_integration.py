"""Gate 3 floor protocol integration tests.

Verifies that the forward-only floor protocol (FloorStateV1) and the
freshness serve gate (FreshnessServeGateV1) are wired end-to-end into the
deterministic vertical pipeline: bootstrap, forward-only advance with
exact-A CAS readback, quarantine-on-mismatch, and serve-gate enforcement
in ``activate_artifact``.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from wiki_spike.infrastructure import crypto, floor_protocol
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    EncryptedLifecyclePipeline,
    PipelineError,
)

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()


@pytest.fixture()
def pipeline(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-test-1",
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
    )


# ---------------------------------------------------------------------------
# bootstrap_workspace
# ---------------------------------------------------------------------------


def test_bootstrap_workspace_creates_stable_floor_and_clear_gate(pipeline):
    pipeline.bootstrap_workspace()
    with pipeline.db.unit_of_work() as uow:
        floor_row = uow.get_floor_state(pipeline.workspace_id)
        gate_row = uow.get_freshness_serve_gate(pipeline.workspace_id)
    assert floor_row["attempt_state"] == floor_protocol.FloorState.FLOOR_STABLE.value
    assert floor_row["stable_floor_generation"] == "1"
    assert gate_row["gate_state"] == "CLEAR"
    assert gate_row["reason_state"] == "NONE"
    assert pipeline.can_serve() is True


def test_bootstrap_workspace_is_idempotent(pipeline):
    pipeline.bootstrap_workspace()
    with pipeline.db.unit_of_work() as uow:
        first_checkpoint = uow.get_floor_state(pipeline.workspace_id)["stable_checkpoint_id"]
    pipeline.bootstrap_workspace()
    with pipeline.db.unit_of_work() as uow:
        second_checkpoint = uow.get_floor_state(pipeline.workspace_id)["stable_checkpoint_id"]
    assert first_checkpoint == second_checkpoint
    assert pipeline.can_serve() is True


# ---------------------------------------------------------------------------
# advance_floor: happy path
# ---------------------------------------------------------------------------


def test_advance_floor_happy_path_increments_generation(pipeline):
    pipeline.bootstrap_workspace()
    candidate_floor = {"schema": "wiki-keychain-v1", "entries": ["a"]}
    new_checkpoint_id = pipeline.advance_floor(
        candidate_floor=candidate_floor,
        counter="1",
        nonce_digest=hashlib.sha256(b"nonce-1").hexdigest(),
    )
    with pipeline.db.unit_of_work() as uow:
        floor_row = uow.get_floor_state(pipeline.workspace_id)
        gate_row = uow.get_freshness_serve_gate(pipeline.workspace_id)
    assert floor_row["attempt_state"] == floor_protocol.FloorState.FLOOR_STABLE.value
    assert floor_row["stable_floor_generation"] == "2"
    assert floor_row["stable_checkpoint_id"] == new_checkpoint_id
    assert new_checkpoint_id == floor_protocol.floor_hash(candidate_floor)
    assert gate_row["gate_state"] == "CLEAR"
    assert gate_row["reason_state"] == "NONE"
    assert pipeline.can_serve() is True


def test_advance_floor_without_bootstrap_raises(pipeline):
    with pytest.raises(PipelineError) as excinfo:
        pipeline.advance_floor(
            candidate_floor={"schema": "wiki-keychain-v1", "entries": []},
            counter="1",
            nonce_digest=hashlib.sha256(b"nonce").hexdigest(),
        )
    assert excinfo.value.code == "floor_not_bootstrapped"


# ---------------------------------------------------------------------------
# advance_floor: readback mismatch quarantines
# ---------------------------------------------------------------------------


def test_advance_floor_readback_mismatch_quarantines(pipeline):
    pipeline.bootstrap_workspace()
    candidate_floor = {"schema": "wiki-keychain-v1", "entries": ["a"]}
    different_floor = {"schema": "wiki-keychain-v1", "entries": ["b"]}

    with pytest.raises(PipelineError) as excinfo:
        pipeline.advance_floor(
            candidate_floor=candidate_floor,
            counter="1",
            nonce_digest=hashlib.sha256(b"nonce-1").hexdigest(),
            simulate_readback=different_floor,
        )
    assert excinfo.value.code == "quarantined_floor_conflict"

    with pipeline.db.unit_of_work() as uow:
        floor_row = uow.get_floor_state(pipeline.workspace_id)
        gate_row = uow.get_freshness_serve_gate(pipeline.workspace_id)
    assert floor_row["attempt_state"] == floor_protocol.FloorState.QUARANTINED_FLOOR_CONFLICT.value
    assert gate_row["gate_state"] == "FRESH_CHALLENGE_REQUIRED"
    assert gate_row["reason_state"] == "ATTESTATION_EXPIRED_BEFORE_STABILIZE"
    assert pipeline.can_serve() is False


# ---------------------------------------------------------------------------
# activate_artifact: serve-gate enforcement
# ---------------------------------------------------------------------------


def test_activate_artifact_lazy_bootstraps_when_no_gate_row(pipeline):
    r = pipeline.remember(raw_body=b"lazy bootstrap me", project_id="proj-1")
    pipeline.activate_artifact(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)
    with pipeline.db.unit_of_work() as uow:
        ks = uow.get_key_state(r.artifact_semantic_digest)
        gate_row = uow.get_freshness_serve_gate(pipeline.workspace_id)
    assert ks["custody_state"] == "ACTIVE"
    assert gate_row["gate_state"] == "CLEAR"


def test_activate_artifact_raises_serve_withheld_when_gate_not_clear(pipeline):
    r = pipeline.remember(raw_body=b"serve withheld", project_id="proj-1")
    pipeline.bootstrap_workspace()
    now = "2026-01-01T00:00:00Z"
    with pipeline.db.unit_of_work() as uow:
        uow.upsert_freshness_serve_gate(
            workspace_id=pipeline.workspace_id,
            gate_state="FRESH_CHALLENGE_REQUIRED",
            stable_floor_generation="1",
            stable_checkpoint_id="deadbeef",
            source_candidate_digest="deadbeef",
            reason_state="CLOCK_WINDOW_EXPIRED",
            updated_at=now,
        )
    with pytest.raises(PipelineError) as excinfo:
        pipeline.activate_artifact(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)
    assert excinfo.value.code == "serve_withheld"
    with pipeline.db.unit_of_work() as uow:
        ks = uow.get_key_state(r.artifact_semantic_digest)
    assert ks["custody_state"] != "ACTIVE"


# ---------------------------------------------------------------------------
# forward-only transition enforcement
# ---------------------------------------------------------------------------


def test_illegal_forward_transition_raises():
    with pytest.raises(floor_protocol.FloorProtocolError) as excinfo:
        floor_protocol.advance(
            floor_protocol.FloorState.FLOOR_STABLE,
            floor_protocol.FloorState.KEYCHAIN_COMMITTED,
        )
    assert excinfo.value.code == "illegal_transition"
