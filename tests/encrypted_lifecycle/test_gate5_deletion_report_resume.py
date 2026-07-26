"""Tests for Gate 5 deletion report 3-tier status and crash-recovery resume."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pytest

from wiki_spike.infrastructure import crypto, deletion
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.keystore import PlatformKeyStore, RecoveryKeyStore, KeyDestroyed
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.applications.encrypted_lifecycle_pipeline import EncryptedLifecyclePipeline, PipelineError

TEST_ONLY_IKM = b"TEST-ONLY-IKM-" + b"x" * 20
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()


@pytest.fixture()
def pipeline(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas")
    plat = PlatformKeyStore(tmp_path / "platform")
    rec = RecoveryKeyStore(tmp_path / "recovery")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-test-1",
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
        platform_keystore=plat,
        recovery_keystore=rec,
    )


@pytest.fixture()
def pipeline_no_keystores(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle_nokey.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas_nokey")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-test-1",
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
    )


def test_forget_returns_valid_deletion_state_report(pipeline: EncryptedLifecyclePipeline):
    rem = pipeline.remember(raw_body=b"test deletion report body", project_id="proj-1")
    res = pipeline.forget(artifact_id=rem.artifact_semantic_digest, blob_id=rem.blob_id)

    ds = res["deletion_state"]
    assert ds["schema"] == "wiki-deletion-state-v1"
    assert ds["workspace_id"] == "ws-test-1"
    assert ds["deletion_command_id"] == res["deletion_command_id"]
    assert ds["phase"] == "COMPLETE"

    report = ds["report"]
    assert report["live"]["status"] == "COMPLETE"
    assert report["live"]["verified_at"] is not None
    assert report["live"]["evidence_digest"] == res["deletion_checkpoint_id"]

    assert report["backup"]["status"] == "PENDING"
    assert report["backup"]["verified_at"] is None

    assert report["egress"]["status"] == "PENDING"
    assert report["egress"]["verified_at"] is None

    # Verify build_deletion_state validation works
    revalidated = deletion.build_deletion_state(
        workspace_id=ds["workspace_id"],
        deletion_command_id=ds["deletion_command_id"],
        phase=ds["phase"],
        report=ds["report"],
        updated_at=ds["updated_at"],
    )
    assert revalidated == ds


@pytest.mark.parametrize(
    "start_phase",
    [
        deletion.DeletionPhase.API_VETO_ACTIVE,
        deletion.DeletionPhase.TOMBSTONE_ACTIVE,
        deletion.DeletionPhase.CHECKPOINT_COMMITTED,
        deletion.DeletionPhase.REVOCATION_KEYS_DESTROYED,
        deletion.DeletionPhase.CRYPTO_SHRED_COMPLETE,
        deletion.DeletionPhase.PURGE_PENDING,
    ],
)
def test_resume_deletion_happy_path(
    pipeline: EncryptedLifecyclePipeline, start_phase: deletion.DeletionPhase
):
    rem = pipeline.remember(raw_body=b"body to resume delete", project_id="proj-1")
    aid, bid = rem.artifact_semantic_digest, rem.blob_id
    cmd_id = hashlib.sha256(f"cmd-{start_phase.value}-{aid}".encode()).hexdigest()

    # Seed an interrupted deletion_state row
    now = "2026-07-25T00:00:00Z"
    empty_digest = hashlib.sha256(b"").hexdigest()
    with pipeline.db.unit_of_work() as uow:
        uow.insert_command(
            command_id=cmd_id,
            workspace_id=pipeline.workspace_id,
            command_kind="FORGET",
            input_digest=empty_digest,
            command_state="ACCEPTED",
            created_at=now,
        )
        uow.insert_deletion_state(
            deletion_id=cmd_id,
            artifact_id=aid,
            phase_state=start_phase.value,
            updated_at=now,
        )

    # If seeding at REVOCATION_KEYS_DESTROYED or later, the ARKs were already destroyed
    order = list(deletion.DeletionPhase)
    if order.index(start_phase) >= order.index(deletion.DeletionPhase.REVOCATION_KEYS_DESTROYED):
        pipeline.platform_keystore.destroy(pipeline.workspace_id, aid)
        pipeline.recovery_keystore.destroy(pipeline.workspace_id, aid)
    resumed = pipeline.resume_deletion(
        deletion_command_id=cmd_id, artifact_id=aid, blob_id=bid
    )
    assert resumed["resumed"] is True
    assert resumed["phase"] == "COMPLETE"

    # Confirm final state
    row = pipeline.db.con.execute(
        "SELECT phase_state FROM deletion_state WHERE deletion_id=?", (cmd_id,)
    ).fetchone()
    assert row[0] == "COMPLETE"
    assert pipeline.cas.is_tombstoned(bid) is True

    # ARKs destroyed
    for ks in (pipeline.platform_keystore, pipeline.recovery_keystore):
        with pytest.raises(KeyDestroyed):
            ks.readback_challenge(pipeline.workspace_id, aid)


def test_resume_deletion_already_complete_is_noop(pipeline: EncryptedLifecyclePipeline):
    rem = pipeline.remember(raw_body=b"body complete noop", project_id="proj-1")
    aid, bid = rem.artifact_semantic_digest, rem.blob_id
    res = pipeline.forget(artifact_id=aid, blob_id=bid)

    noop = pipeline.resume_deletion(
        deletion_command_id=res["deletion_command_id"], artifact_id=aid, blob_id=bid
    )
    assert noop["resumed"] is False
    assert noop["phase"] == "COMPLETE"


def test_resume_deletion_not_found(pipeline: EncryptedLifecyclePipeline):
    with pytest.raises(PipelineError) as excinfo:
        pipeline.resume_deletion(
            deletion_command_id="ff" * 32, artifact_id="aa" * 32, blob_id="bb" * 32
        )
    assert excinfo.value.code == "resume_deletion_not_found"


def test_resume_deletion_requires_dual_custody(
    pipeline_no_keystores: EncryptedLifecyclePipeline,
):
    rem = pipeline_no_keystores.remember(raw_body=b"no key body", project_id="proj-1")
    aid, bid = rem.artifact_semantic_digest, rem.blob_id
    cmd_id = "cc" * 32
    now = "2026-07-25T00:00:00Z"
    empty_digest = hashlib.sha256(b"").hexdigest()
    with pipeline_no_keystores.db.unit_of_work() as uow:
        uow.insert_command(
            command_id=cmd_id,
            workspace_id=pipeline_no_keystores.workspace_id,
            command_kind="FORGET",
            input_digest=empty_digest,
            command_state="ACCEPTED",
            created_at=now,
        )
        uow.insert_deletion_state(
            deletion_id=cmd_id,
            artifact_id=aid,
            phase_state="API_VETO_ACTIVE",
            updated_at=now,
        )

    with pytest.raises(PipelineError) as excinfo:
        pipeline_no_keystores.resume_deletion(
            deletion_command_id=cmd_id, artifact_id=aid, blob_id=bid
        )
    assert excinfo.value.code == "forget_requires_dual_custody"
