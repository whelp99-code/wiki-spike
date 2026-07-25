"""Gate 5 FORGET deletion workflow tests.

Covers the dual-custody crypto-shred deletion workflow driven by
``EncryptedLifecyclePipeline.forget`` over the forward-only deletion
phase machine (infrastructure/deletion.py), including tombstoning the
CAS blob, destroying the per-artifact ARK in both custodian keystores,
immediate live-API veto, fail-closed ARK destroy, and wait_seconds
bounds validation.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure import keystore
from wiki_spike.infrastructure import encrypted_cas
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.keystore import PlatformKeyStore, RecoveryKeyStore
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
        platform_keystore=PlatformKeyStore(tmp_path / "platform"),
        recovery_keystore=RecoveryKeyStore(tmp_path / "recovery"),
    )


@pytest.fixture()
def pipeline_no_keystores(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle-nk.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas-nk")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-test-1",
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
    )


# ---------------------------------------------------------------------------
# (a) Happy path
# ---------------------------------------------------------------------------


def test_forget_happy_path_reaches_complete(pipeline):
    plaintext = b"the quick brown fox jumps over the lazy dog - to be forgotten"
    r = pipeline.remember(raw_body=plaintext, project_id="proj-1")

    result = pipeline.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)

    assert result["phase"] == "COMPLETE"
    assert len(result["deletion_command_id"]) == 64
    assert len(result["deletion_checkpoint_id"]) == 64

    row = pipeline.db.con.execute(
        "SELECT phase_state FROM deletion_state WHERE deletion_id=?",
        (result["deletion_command_id"],),
    ).fetchone()
    assert row is not None
    assert row[0] == "COMPLETE"


def test_forget_tombstones_cas_blob(pipeline):
    r = pipeline.remember(raw_body=b"body to tombstone", project_id="proj-1")
    pipeline.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)

    assert pipeline.cas.is_tombstoned(r.blob_id) is True
    with pytest.raises(encrypted_cas.Tombstoned):
        pipeline.cas.get(r.blob_id)


def test_forget_destroys_both_custodian_arks(pipeline):
    r = pipeline.remember(raw_body=b"body under dual custody", project_id="proj-1")
    pipeline.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)

    with pytest.raises(keystore.KeyDestroyed):
        pipeline.platform_keystore.readback_challenge("ws-test-1", r.artifact_semantic_digest)
    with pytest.raises(keystore.KeyDestroyed):
        pipeline.recovery_keystore.readback_challenge("ws-test-1", r.artifact_semantic_digest)


def test_forget_returns_absence_receipts(pipeline):
    r = pipeline.remember(raw_body=b"receipt body", project_id="proj-1")
    result = pipeline.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)

    for key in ("platform_absence_receipt", "recovery_absence_receipt"):
        receipt = result[key]
        assert isinstance(receipt, dict)
        assert receipt["namespace"] == "ws-test-1"
        assert receipt["ark_handle"] == r.artifact_semantic_digest
        assert len(receipt["receipt_digest"]) == 64


def test_forget_event_chain_order(pipeline):
    r = pipeline.remember(raw_body=b"event chain body", project_id="proj-1")
    pipeline.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)

    kinds = [row["event_kind"] for row in pipeline.db.event_log_rows()]
    expected = [
        "FORGET_REQUESTED",
        "DELETION_TOMBSTONED",
        "DELETION_ARK_DESTROYED",
        "DELETION_CRYPTO_SHRED_COMPLETE",
        "DELETION_COMPLETE",
    ]
    positions = []
    for kind in expected:
        assert kind in kinds, f"missing event kind {kind}"
        positions.append(kinds.index(kind))
    assert positions == sorted(positions), f"events out of order: {kinds}"


# ---------------------------------------------------------------------------
# (b) Immediate veto
# ---------------------------------------------------------------------------


def test_forget_vetoes_artifact_immediately_and_blocks_activation(pipeline):
    r = pipeline.remember(raw_body=b"veto body", project_id="proj-1")
    assert pipeline.is_object_vetoed(r.artifact_semantic_digest) is False

    pipeline.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)

    assert pipeline.is_object_vetoed(r.artifact_semantic_digest) is True

    with pytest.raises(PipelineError) as excinfo:
        pipeline.activate_artifact(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)
    assert excinfo.value.code == "artifact_vetoed"


# ---------------------------------------------------------------------------
# (c) No plaintext after shred / no wrapped DEK after destroy
# ---------------------------------------------------------------------------


def test_forget_no_plaintext_survives_on_disk_and_dek_is_scrubbed(pipeline, tmp_path):
    plaintext = b"SECRET-MARKER-PLAINTEXT-MUST-NEVER-APPEAR-ON-DISK"
    r = pipeline.remember(raw_body=plaintext, project_id="proj-1")

    # Sanity: even before deletion, the CAS never stores plaintext bytes
    # (encrypted-before-durability).
    cas_dir = tmp_path / "cas"
    for obj_path in (cas_dir / "objects").iterdir():
        if obj_path.name.endswith(".tmp"):
            continue
        assert plaintext not in obj_path.read_bytes()

    pipeline.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)

    # Post-shred: raw retained (tombstoned, not deleted) bytes still never
    # contain the original plaintext body.
    for obj_path in (cas_dir / "objects").iterdir():
        if obj_path.name.endswith(".tmp"):
            continue
        assert plaintext not in obj_path.read_bytes()

    # Destroyed keystore entries must not expose the wrapped DEK anymore.
    for root_dir in (tmp_path / "platform", tmp_path / "recovery"):
        entry_path = keystore._entry_path(root_dir, "ws-test-1", r.artifact_semantic_digest)
        assert entry_path.exists()
        raw = entry_path.read_text(encoding="utf-8")
        assert '"destroyed": true' in raw
        assert '"wrapped_dek_hex": ""' in raw


# ---------------------------------------------------------------------------
# (d) Dual custody required
# ---------------------------------------------------------------------------


def test_forget_requires_dual_custody(pipeline_no_keystores):
    r = pipeline_no_keystores.remember(raw_body=b"no keystores body", project_id="proj-1")

    with pytest.raises(PipelineError) as excinfo:
        pipeline_no_keystores.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)
    assert excinfo.value.code == "forget_requires_dual_custody"


# ---------------------------------------------------------------------------
# (e) Idempotent / repeat forget, distinct artifacts
# ---------------------------------------------------------------------------


def test_forget_repeat_rejected_already_under_deletion(pipeline):
    r = pipeline.remember(raw_body=b"repeat forget body", project_id="proj-1")
    pipeline.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)

    with pytest.raises(PipelineError) as excinfo:
        pipeline.forget(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)
    assert excinfo.value.code == "already_under_deletion"


def test_forget_distinct_artifacts_get_distinct_deletion_commands(pipeline):
    r1 = pipeline.remember(raw_body=b"artifact one body", project_id="proj-1")
    r2 = pipeline.remember(raw_body=b"artifact two body", project_id="proj-1")

    result1 = pipeline.forget(artifact_id=r1.artifact_semantic_digest, blob_id=r1.blob_id)
    result2 = pipeline.forget(artifact_id=r2.artifact_semantic_digest, blob_id=r2.blob_id)

    assert result1["deletion_command_id"] != result2["deletion_command_id"]
    assert result1["phase"] == "COMPLETE"
    assert result2["phase"] == "COMPLETE"


# ---------------------------------------------------------------------------
# (f) Fail-closed ARK destroy
# ---------------------------------------------------------------------------


def test_forget_fail_closed_when_ark_never_registered(pipeline):
    # A real, tombstoneable blob from a separate remember, but an
    # artifact_id whose canonical_artifact row exists (so the deletion FK
    # is satisfiable) yet was never registered as an ARK in either
    # keystore -- simulating a lost/never-completed ARK registration.
    r = pipeline.remember(raw_body=b"orphan ark body", project_id="proj-1")
    unregistered_artifact_id = "ab" * 32
    with pipeline.db.unit_of_work() as uow:
        uow.insert_canonical_artifact(
            artifact_id=unregistered_artifact_id,
            workspace_id="ws-test-1",
            artifact_kind="MEMORY_REVISION",
            revision_id="cd" * 32,
            artifact_state="ACTIVE",
            created_at="2026-01-01T00:00:00Z",
        )

    with pytest.raises(PipelineError) as excinfo:
        pipeline.forget(artifact_id=unregistered_artifact_id, blob_id=r.blob_id)
    assert excinfo.value.code == "forget_ark_destroy_failed"

    row = pipeline.db.con.execute(
        "SELECT deletion_id, phase_state FROM deletion_state WHERE artifact_id=?",
        (unregistered_artifact_id,),
    ).fetchone()
    assert row is not None
    deletion_id, phase_state = row
    assert phase_state == "CHECKPOINT_COMMITTED"

    shred_events = [
        rr
        for rr in pipeline.db.event_log_rows()
        if rr["event_kind"] == "DELETION_CRYPTO_SHRED_COMPLETE"
        and rr["ref_digest"] == unregistered_artifact_id
    ]
    assert shred_events == []


# ---------------------------------------------------------------------------
# (g) wait_seconds bounds
# ---------------------------------------------------------------------------


def test_forget_wait_seconds_out_of_range_rejected(pipeline):
    r = pipeline.remember(raw_body=b"wait bounds body", project_id="proj-1")

    with pytest.raises(PipelineError) as excinfo:
        pipeline.forget(
            artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id, wait_seconds="301"
        )
    assert excinfo.value.code == "forget_wait_out_of_range"


def test_forget_wait_seconds_boundaries_accepted(pipeline):
    r1 = pipeline.remember(raw_body=b"wait zero body", project_id="proj-1")
    r2 = pipeline.remember(raw_body=b"wait max body", project_id="proj-1")

    result1 = pipeline.forget(
        artifact_id=r1.artifact_semantic_digest, blob_id=r1.blob_id, wait_seconds="0"
    )
    result2 = pipeline.forget(
        artifact_id=r2.artifact_semantic_digest, blob_id=r2.blob_id, wait_seconds="300"
    )

    assert result1["phase"] == "COMPLETE"
    assert result2["phase"] == "COMPLETE"
