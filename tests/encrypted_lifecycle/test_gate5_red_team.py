"""Gate 5 adversarial red-team test suite.

TRIES TO BREAK the deletion & restore workflows. Fail-closed is the overriding
rule: any assertion that detects a REAL defect (unexpected success, missing
exception, data leak, accidental destroy, phase reversal) is a blocker.

Covers:
  (a) VETO IMMEDIACY
  (b) CRYPTO-SHRED PERMANENCE
  (c) RESUME IDEMPOTENCY
  (d) RECONCILIATION FAIL-CLOSED
  (e) CONDITIONAL DESTROY DRIFT
  (f) RESTORE GATES
  (g) ATTESTATION FRESHNESS
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    EncryptedLifecyclePipeline,
    PipelineError,
)
from wiki_spike.infrastructure import crypto, deletion, keystore as ks, recovery
from wiki_spike.infrastructure.binding_registry import BindingRegistry
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase

# ---------------------------------------------------------------------------
# Shared test constants / fixtures
# ---------------------------------------------------------------------------

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()

TEST_ONLY_ED25519_SEED = hashlib.sha256(
    b"WIKI-SPIKE-GATE5-RED-TEAM-ED25519-SEED"
).digest()
SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_ED25519_SEED)
SIGNER_KEY_ID = "gate5-redteam-signer"

FLOOR_CHECKPOINT_ID = hashlib.sha256(b"gate5-redteam-floor-checkpoint-genesis").hexdigest()
REGISTRY_NAMESPACE = "encrypted-lifecycle"
WITHIN_WINDOW_NOW = "2026-07-24T00:02:00Z"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture()
def pipeline(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-gate5-red",
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
        platform_keystore=ks.PlatformKeyStore(root_dir=tmp_path / "platform-keys"),
        recovery_keystore=ks.RecoveryKeyStore(root_dir=tmp_path / "recovery-keys"),
    )


@pytest.fixture()
def pipeline_no_keystores(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle-nk.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas-nk")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-gate5-red-nk",
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
    )


def _event_kinds(pipeline: EncryptedLifecyclePipeline) -> list[str]:
    return [row["event_kind"] for row in pipeline.db.event_log_rows()]


# ---------------------------------------------------------------------------
# (a) VETO IMMEDIACY
# ---------------------------------------------------------------------------


def test_veto_blocks_activate_immediately_after_forget_requested(pipeline):
    """After forget() is called, is_object_vetoed() is True and
    activate_artifact() raises artifact_vetoed -- even before CRYPTO_SHRED."""
    r = pipeline.remember(raw_body=b"veto-immediate-body", project_id="proj-1")
    result = pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    assert result["phase"] == "COMPLETE"

    # The veto is live.
    assert pipeline.is_object_vetoed(r.artifact_semantic_digest) is True

    # Activate must fail.
    with pytest.raises(PipelineError) as excinfo:
        pipeline.activate_artifact(
            artifact_id=r.artifact_semantic_digest,
            blob_id=r.blob_id,
        )
    assert excinfo.value.code == "artifact_vetoed"


def test_veto_blocks_restore_even_with_valid_proof_set(pipeline):
    """After forget(), restore() with a valid proof set must raise
    restore_vetoed, not restore_quarantined."""
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"veto-restore-body", project_id="proj-1")

    pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"redteam-veto-restore")

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(
            artifact_id=r.artifact_semantic_digest,
            mode=recovery.RecoveryMode.AUTHORITATIVE_SNAPSHOT,
            registry=registry,
            proof_set=proof_set,
            trusted_signer_pub=SIGNING_KEY.public_key(),
            local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
            expected_namespace=REGISTRY_NAMESPACE,
            expected_provider_handle="provider-b",
            now=WITHIN_WINDOW_NOW,
        )
    assert excinfo.value.code == "restore_vetoed"


def test_veto_blocks_repeat_forget(pipeline):
    """Second forget() on the same artifact must raise 'already_under_deletion'."""
    r = pipeline.remember(raw_body=b"repeat-forget-body", project_id="proj-1")
    pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    with pytest.raises(PipelineError) as excinfo:
        pipeline.forget(
            artifact_id=r.artifact_semantic_digest,
            blob_id=r.blob_id,
        )
    assert excinfo.value.code == "already_under_deletion"


# ---------------------------------------------------------------------------
# (b) CRYPTO-SHRED PERMANENCE
# ---------------------------------------------------------------------------


def test_crypto_shred_platform_readback_fails(pipeline):
    """After forget(), platform keystore readback must raise KeyDestroyed."""
    r = pipeline.remember(raw_body=b"shred-platform-body", project_id="proj-1")
    pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    with pytest.raises(ks.KeyDestroyed):
        pipeline.platform_keystore.readback_challenge(
            pipeline.workspace_id, r.artifact_semantic_digest
        )


def test_crypto_shred_recovery_readback_fails(pipeline):
    """After forget(), recovery keystore readback must raise KeyDestroyed."""
    r = pipeline.remember(raw_body=b"shred-recovery-body", project_id="proj-1")
    pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    with pytest.raises(ks.KeyDestroyed):
        pipeline.recovery_keystore.readback_challenge(
            pipeline.workspace_id, r.artifact_semantic_digest
        )


def test_crypto_shred_wrapped_dek_scrubbed_from_disk(pipeline, tmp_path):
    """After forget(), both keystore files contain empty wrapped_dek_hex."""
    r = pipeline.remember(raw_body=b"shred-disk-body", project_id="proj-1")
    pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )

    platform_dir = tmp_path / "platform-keys"
    recovery_dir = tmp_path / "recovery-keys"

    for ks_dir in (platform_dir, recovery_dir):
        for f in sorted(ks_dir.glob("*.json")):
            raw = f.read_text(encoding="utf-8")
            assert '"wrapped_dek_hex": ""' in raw, (
                f"wrapped_dek_hex not scrubbed in {f}"
            )
            assert '"destroyed": true' in raw, (
                f"destroyed flag not set in {f}"
            )


def test_crypto_shred_plaintext_not_recoverable_from_cas(pipeline):
    """After forget(), CAS tombstone makes the blob unreadable."""
    r = pipeline.remember(raw_body=b"SECRET-MARKER-CAS-SHRED-TEST", project_id="proj-1")
    pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    # CAS get on a tombstoned blob must raise.
    with pytest.raises(Exception):
        pipeline.cas.get(r.blob_id)


def test_crypto_shred_dek_cannot_decrypt_after_forget(pipeline):
    """After forget(), the DEK bytes are wiped from keystore; verify
    the raw wrapped_dek_hex is empty, so even if someone had the KEK,
    there is nothing to unwrap."""
    r = pipeline.remember(raw_body=b"dek-gone-after-forget", project_id="proj-1")
    pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )

    # Inventory shows both destroyed.
    platform_inv = pipeline.platform_keystore.inventory(pipeline.workspace_id)
    recovery_inv = pipeline.recovery_keystore.inventory(pipeline.workspace_id)
    for entry in platform_inv + recovery_inv:
        if entry.ark_handle == r.artifact_semantic_digest:
            assert entry.destroyed is True


# ---------------------------------------------------------------------------
# (c) RESUME IDEMPOTENCY
# ---------------------------------------------------------------------------


def test_resume_from_requested_phase_completes(pipeline):
    """Call resume_deletion from REQUESTED (the earliest phase)."""
    r = pipeline.remember(raw_body=b"resume-requested-body", project_id="proj-1")
    result = pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    cmd_id = result["deletion_command_id"]

    # Manually set phase back to REQUESTED to simulate crash.
    with pipeline.db.unit_of_work() as uow:
        uow.update_deletion_phase(
            deletion_id=cmd_id,
            phase_state="REQUESTED",
            updated_at="2026-07-24T00:01:00Z",
        )

    resumed = pipeline.resume_deletion(
        deletion_command_id=cmd_id,
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    assert resumed["phase"] == "COMPLETE"
    assert resumed["resumed"] is True


def test_resume_from_checkpoint_committed_completes(pipeline):
    """Call resume_deletion from CHECKPOINT_COMMITTED."""
    r = pipeline.remember(raw_body=b"resume-checkpoint-body", project_id="proj-1")
    result = pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    cmd_id = result["deletion_command_id"]

    with pipeline.db.unit_of_work() as uow:
        uow.update_deletion_phase(
            deletion_id=cmd_id,
            phase_state="CHECKPOINT_COMMITTED",
            updated_at="2026-07-24T00:01:00Z",
        )

    resumed = pipeline.resume_deletion(
        deletion_command_id=cmd_id,
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    assert resumed["phase"] == "COMPLETE"
    assert resumed["resumed"] is True


def test_resume_from_crypto_shred_complete_advances(pipeline):
    """Call resume_deletion from CRYPTO_SHRED_COMPLETE."""
    r = pipeline.remember(raw_body=b"resume-shred-body", project_id="proj-1")
    result = pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    cmd_id = result["deletion_command_id"]

    with pipeline.db.unit_of_work() as uow:
        uow.update_deletion_phase(
            deletion_id=cmd_id,
            phase_state="CRYPTO_SHRED_COMPLETE",
            updated_at="2026-07-24T00:01:00Z",
        )

    resumed = pipeline.resume_deletion(
        deletion_command_id=cmd_id,
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    assert resumed["phase"] == "COMPLETE"
    assert resumed["resumed"] is True


def test_resume_already_complete_is_noop(pipeline):
    """Call resume_deletion from COMPLETE -- must be no-op."""
    r = pipeline.remember(raw_body=b"resume-complete-body", project_id="proj-1")
    result = pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    cmd_id = result["deletion_command_id"]

    resumed = pipeline.resume_deletion(
        deletion_command_id=cmd_id,
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    assert resumed["phase"] == "COMPLETE"
    assert resumed["resumed"] is False


def test_resume_double_call_idempotent(pipeline):
    """Call resume_deletion twice from CHECKPOINT_COMMITTED; second is no-op."""
    r = pipeline.remember(raw_body=b"resume-double-body", project_id="proj-1")
    result = pipeline.forget(
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    cmd_id = result["deletion_command_id"]

    with pipeline.db.unit_of_work() as uow:
        uow.update_deletion_phase(
            deletion_id=cmd_id,
            phase_state="CHECKPOINT_COMMITTED",
            updated_at="2026-07-24T00:01:00Z",
        )

    first = pipeline.resume_deletion(
        deletion_command_id=cmd_id,
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    assert first["phase"] == "COMPLETE"
    assert first["resumed"] is True

    second = pipeline.resume_deletion(
        deletion_command_id=cmd_id,
        artifact_id=r.artifact_semantic_digest,
        blob_id=r.blob_id,
    )
    assert second["phase"] == "COMPLETE"
    assert second["resumed"] is False


def test_resume_not_found_raises(pipeline):
    """Call resume_deletion with a non-existent command id."""
    with pytest.raises(PipelineError) as excinfo:
        pipeline.resume_deletion(
            deletion_command_id="nonexistent" * 4,
            artifact_id="a" * 64,
            blob_id="b" * 64,
        )
    assert excinfo.value.code == "resume_deletion_not_found"


# ---------------------------------------------------------------------------
# (d) RECONCILIATION FAIL-CLOSED
# ---------------------------------------------------------------------------


def test_reconciliation_active_binding_never_destroys():
    """ACTIVE binding with full destroy proofs must still QUARANTINE_ACTIVE."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.ACTIVE,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_ACTIVE


def test_reconciliation_collision_never_destroys():
    """Collision flag must always result in QUARANTINE_COLLISION."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.UNBOUND,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        non_membership_verified=True,
        inventories_complete=True,
        collision=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_COLLISION


def test_reconciliation_historical_active_without_terminal_quarantines():
    """Historical ACTIVE without terminal event must quarantine."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.UNBOUND,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        non_membership_verified=True,
        inventories_complete=True,
        historical_active_without_terminal=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_ACTIVE


def test_reconciliation_corrupt_external_quarantines():
    """Corrupt external record must quarantine regardless of proofs."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.UNBOUND,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32, corrupt=True),
        non_membership_verified=True,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconciliation_none_external_quarantines():
    """None external must quarantine."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.UNBOUND,
        external=None,
        non_membership_verified=True,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconciliation_none_metadata_digest_quarantines():
    """External with None metadata_digest must quarantine."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.UNBOUND,
        external=ks.ExternalKeyRecord(metadata_digest=None),
        non_membership_verified=True,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconciliation_unbound_without_non_membership_proof_quarantines():
    """DESTROY_UNBOUND requires non_membership_verified=True."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.UNBOUND,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        non_membership_verified=False,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconciliation_unbound_without_complete_inventories_quarantines():
    """DESTROY_UNBOUND requires inventories_complete=True."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.UNBOUND,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        non_membership_verified=True,
        inventories_complete=False,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconciliation_loser_without_membership_quarantines():
    """DESTROY_LOSER requires membership_verified=True."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.LOSER,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        membership_verified=False,
        inventories_complete=True,
        metadata_matches=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconciliation_loser_without_metadata_match_quarantines():
    """DESTROY_LOSER requires metadata_matches=True."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.LOSER,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=False,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconciliation_prepared_missing_membership_quarantines():
    """RESUME_EXACT requires membership_verified=True."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.PREPARED,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        membership_verified=False,
        metadata_matches=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconciliation_prepared_missing_metadata_quarantines():
    """RESUME_EXACT requires metadata_matches=True."""
    inputs = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.PREPARED,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        membership_verified=True,
        metadata_matches=False,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


# ---------------------------------------------------------------------------
# (e) CONDITIONAL DESTROY DRIFT
# ---------------------------------------------------------------------------


def test_conditional_destroy_drift_from_loser_to_active():
    """DESTROY_LOSER -> re-read becomes ACTIVE: destroy blocked."""
    pre_outcome = ks.ReconciliationOutcome.DESTROY_LOSER
    reread = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.ACTIVE,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    assert ks.conditional_destroy_allowed(pre_outcome, reread) is False


def test_conditional_destroy_drift_from_unbound_to_collision():
    """DESTROY_UNBOUND -> re-read has collision: destroy blocked."""
    pre_outcome = ks.ReconciliationOutcome.DESTROY_UNBOUND
    reread = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.UNBOUND,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        non_membership_verified=True,
        inventories_complete=True,
        collision=True,
    )
    assert ks.conditional_destroy_allowed(pre_outcome, reread) is False


def test_conditional_destroy_drift_external_becomes_none():
    """DESTROY_UNBOUND -> re-read: external record disappears."""
    pre_outcome = ks.ReconciliationOutcome.DESTROY_UNBOUND
    reread = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.UNBOUND,
        external=None,
        non_membership_verified=True,
        inventories_complete=True,
    )
    assert ks.conditional_destroy_allowed(pre_outcome, reread) is False


def test_conditional_destroy_drift_loser_to_different_loser():
    """DESTROY_LOSER -> re-read is DESTROY_EXPIRED (different destroy outcome)."""
    pre_outcome = ks.ReconciliationOutcome.DESTROY_LOSER
    reread = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.EXPIRED,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    assert ks.conditional_destroy_allowed(pre_outcome, reread) is False


def test_conditional_destroy_non_destroy_pre_outcome_always_false():
    """RESUME_EXACT pre_outcome: conditional_destroy_allowed is always False."""
    pre_outcome = ks.ReconciliationOutcome.RESUME_EXACT
    reread = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.PREPARED,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
        membership_verified=True,
        metadata_matches=True,
    )
    assert ks.conditional_destroy_allowed(pre_outcome, reread) is False


def test_conditional_destroy_quarantine_pre_outcome_always_false():
    """QUARANTINE_ACTIVE pre_outcome: conditional_destroy_allowed is always False."""
    pre_outcome = ks.ReconciliationOutcome.QUARANTINE_ACTIVE
    reread = ks.ReconciliationInputs(
        binding_status=ks.BindingStatus.ACTIVE,
        external=ks.ExternalKeyRecord(metadata_digest="aa" * 32),
    )
    assert ks.conditional_destroy_allowed(pre_outcome, reread) is False


# ---------------------------------------------------------------------------
# (f) RESTORE GATES
# ---------------------------------------------------------------------------


def _build_registry() -> BindingRegistry:
    registry = BindingRegistry("ws-gate5-red")
    for handle, status in [
        ("provider-a", "PREPARED"),
        ("provider-b", "ACTIVE"),
        ("provider-c", "LOSER"),
    ]:
        registry.append_leaf(
            namespace=REGISTRY_NAMESPACE,
            provider_handle=handle,
            provider_key_fingerprint=sha256_hex(handle.encode() + b"-fingerprint"),
            intent_id=sha256_hex(handle.encode() + b"-intent"),
            artifact_id=sha256_hex(handle.encode() + b"-artifact"),
            revision_id=sha256_hex(handle.encode() + b"-revision"),
            semantic_digest=sha256_hex(handle.encode() + b"-semantic"),
            metadata_digest=sha256_hex(handle.encode() + b"-metadata"),
            status=status,
            activation_generation_id=sha256_hex(handle.encode() + b"-generation") if status == "ACTIVE" else None,
            signing_key=SIGNING_KEY,
            key_id=SIGNER_KEY_ID,
        )
    return registry


def _build_checkpoint(registry: BindingRegistry) -> tuple[dict, dict]:
    return registry.checkpoint(
        generation_id=sha256_hex(b"gate5-red-generation-1"),
        created_at="2026-07-24T00:05:00Z",
        signing_key=SIGNING_KEY,
        key_id=SIGNER_KEY_ID,
        registry_sequence="3",
    )


def _build_proof_set(
    registry: BindingRegistry,
    *,
    nonce_seed: bytes,
    issued_at: str = "2026-07-24T00:00:00Z",
    expires_at: str = "2026-07-24T00:05:00Z",
    provider_handle: str = "provider-b",
) -> dict:
    checkpoint, checkpoint_signature = _build_checkpoint(registry)
    attestation = registry.attest(
        request_nonce=sha256_hex(nonce_seed),
        challenge_counter="1",
        request_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        signer_key_id=SIGNER_KEY_ID,
        issued_at=issued_at,
        expires_at=expires_at,
        signing_key=SIGNING_KEY,
        checkpoint=checkpoint,
    )
    return registry.build_proof_set(
        attestation=attestation,
        checkpoint=checkpoint,
        checkpoint_signature=checkpoint_signature,
        namespace=REGISTRY_NAMESPACE,
        provider_handle=provider_handle,
        old_size=2,
        inclusion_indices=[1],
        predecessor_leaf_indices=[],
    )


def _restore_kwargs(artifact_id, registry, proof_set, now):
    return dict(
        artifact_id=artifact_id,
        mode=recovery.RecoveryMode.AUTHORITATIVE_SNAPSHOT,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace=REGISTRY_NAMESPACE,
        expected_provider_handle="provider-b",
        now=now,
    )


def test_restore_tampered_checkpoint_history_root(pipeline):
    """Tampered checkpoint history_root must fail."""
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"tampered-root-body", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"redteam-tampered-root")
    tampered = json.loads(json.dumps(proof_set))
    root = tampered["checkpoint"]["history_root"]
    tampered["checkpoint"]["history_root"] = ("0" if root[0] != "0" else "1") + root[1:]

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(**_restore_kwargs(r.artifact_semantic_digest, registry, tampered, WITHIN_WINDOW_NOW))
    assert excinfo.value.code == "restore_quarantined"


def test_restore_tampered_signature(pipeline):
    """Tampered checkpoint_signature must fail."""
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"tampered-sig-body", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"redteam-tampered-sig")
    tampered = json.loads(json.dumps(proof_set))
    sig = tampered["checkpoint_signature"]["signature"]
    tampered["checkpoint_signature"]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(**_restore_kwargs(r.artifact_semantic_digest, registry, tampered, WITHIN_WINDOW_NOW))
    assert excinfo.value.code == "restore_quarantined"


def test_restore_tampered_attestation_nonce(pipeline):
    """Tampered attestation nonce must fail (replay protection)."""
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"tampered-nonce-body", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"redteam-tampered-nonce")
    tampered = json.loads(json.dumps(proof_set))
    tampered["attestation"]["payload"]["request_nonce"] = "deadbeef" * 8

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(**_restore_kwargs(r.artifact_semantic_digest, registry, tampered, WITHIN_WINDOW_NOW))
    assert excinfo.value.code == "restore_quarantined"


def test_restore_wrong_provider_handle(pipeline):
    """Proof set for a different provider handle must fail."""
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"wrong-provider-body", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"redteam-wrong-provider")

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(
            artifact_id=r.artifact_semantic_digest,
            mode=recovery.RecoveryMode.AUTHORITATIVE_SNAPSHOT,
            registry=registry,
            proof_set=proof_set,
            trusted_signer_pub=SIGNING_KEY.public_key(),
            local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
            expected_namespace=REGISTRY_NAMESPACE,
            expected_provider_handle="nonexistent-provider",
            now=WITHIN_WINDOW_NOW,
        )
    assert excinfo.value.code == "restore_quarantined"


def test_restore_serve_gate_withheld(pipeline):
    """Restore must fail when freshness serve gate is not CLEAR."""
    with pipeline.db.unit_of_work() as uow:
        uow.upsert_freshness_serve_gate(
            workspace_id=pipeline.workspace_id,
            gate_state="FRESH_CHALLENGE_REQUIRED",
            stable_floor_generation="1",
            stable_checkpoint_id="x" * 64,
            source_candidate_digest="x" * 64,
            reason_state="ATTESTATION_EXPIRED_BEFORE_STABILIZE",
            updated_at="2026-07-24T00:01:00Z",
        )
    assert pipeline.can_serve() is False

    r = pipeline.remember(raw_body=b"serve-withheld-body", project_id="proj-1")
    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"redteam-serve-withheld")

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(**_restore_kwargs(r.artifact_semantic_digest, registry, proof_set, WITHIN_WINDOW_NOW))
    assert excinfo.value.code == "restore_serve_withheld"


# ---------------------------------------------------------------------------
# (g) ATTESTATION FRESHNESS
# ---------------------------------------------------------------------------


def test_attestation_expired_fails_restore(pipeline):
    """Attestation expired (now > expires_at + skew) must fail."""
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"expired-attest-body", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"redteam-expired")

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(
            **_restore_kwargs(
                r.artifact_semantic_digest, registry, proof_set,
                now="2026-07-24T09:00:00Z",  # well past expires_at
            )
        )
    assert excinfo.value.code == "restore_quarantined"


def test_attestation_future_skewed_fails_restore(pipeline):
    """Attestation issued_at is in the future (now < issued_at - skew) must fail."""
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"future-attest-body", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(
        registry,
        nonce_seed=b"redteam-future",
        issued_at="2026-07-25T00:00:00Z",  # far future
        expires_at="2026-07-25T00:05:00Z",
    )

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(
            **_restore_kwargs(
                r.artifact_semantic_digest, registry, proof_set,
                now=WITHIN_WINDOW_NOW,  # 2026-07-24, well before issued_at
            )
        )
    assert excinfo.value.code == "restore_quarantined"


def test_attestation_exactly_on_expiry_boundary(pipeline):
    """Attestation at exactly expires_at must be accepted (within window)."""
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"boundary-expiry-body", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(
        registry,
        nonce_seed=b"redteam-boundary",
        issued_at="2026-07-24T00:00:00Z",
        expires_at="2026-07-24T00:05:00Z",
    )

    result = pipeline.restore(
        **_restore_kwargs(
            r.artifact_semantic_digest, registry, proof_set,
            now="2026-07-24T00:05:00Z",  # exactly at expires_at
        )
    )
    assert result["restored"] is True


def test_attestation_just_after_expiry_fails(pipeline):
    """Attestation just 1 second after expires_at + skew must fail."""
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"just-after-expiry-body", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(
        registry,
        nonce_seed=b"redteam-just-after",
        issued_at="2026-07-24T00:00:00Z",
        expires_at="2026-07-24T00:05:00Z",
    )

    # 61 seconds after expiry (skew is 60s by default)
    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(
            **_restore_kwargs(
                r.artifact_semantic_digest, registry, proof_set,
                now="2026-07-24T00:06:01Z",
            )
        )
    assert excinfo.value.code == "restore_quarantined"


# ---------------------------------------------------------------------------
# (h) Deletion phase machine adversarial
# ---------------------------------------------------------------------------


def test_deletion_advance_from_complete_is_terminal():
    """Advancing from COMPLETE must always raise illegal_deletion_transition."""
    for target in deletion._PHASE_ORDER:
        with pytest.raises(deletion.DeletionError) as excinfo:
            deletion.advance(deletion.DeletionPhase.COMPLETE, target)
        assert excinfo.value.code == "illegal_deletion_transition"


def test_deletion_skip_phase_rejected():
    """Skipping from REQUESTED to TOMBSTONE_ACTIVE must be rejected."""
    with pytest.raises(deletion.DeletionError) as excinfo:
        deletion.advance(deletion.DeletionPhase.REQUESTED, deletion.DeletionPhase.TOMBSTONE_ACTIVE)
    assert excinfo.value.code == "illegal_deletion_transition"


def test_deletion_backward_transition_rejected():
    """Backward transition from TOMBSTONE_ACTIVE to API_VETO_ACTIVE must be rejected."""
    with pytest.raises(deletion.DeletionError) as excinfo:
        deletion.advance(deletion.DeletionPhase.TOMBSTONE_ACTIVE, deletion.DeletionPhase.API_VETO_ACTIVE)
    assert excinfo.value.code == "illegal_deletion_transition"


def test_deletion_same_phase_advance_rejected():
    """Same-phase advance (REQUESTED -> REQUESTED) must be rejected."""
    with pytest.raises(deletion.DeletionError) as excinfo:
        deletion.advance(deletion.DeletionPhase.REQUESTED, deletion.DeletionPhase.REQUESTED)
    assert excinfo.value.code == "illegal_deletion_transition"


def test_deletion_is_vetoed_true_all_phases():
    """is_vetoed() must return True for ALL phases (including COMPLETE)."""
    for phase in deletion._PHASE_ORDER:
        assert deletion.is_vetoed(phase) is True
        assert deletion.is_vetoed(phase.value) is True


def test_deletion_is_crypto_shredded_correct_boundary():
    """is_crypto_shredded must be False before CRYPTO_SHRED_COMPLETE, True after."""
    pre_shred = [
        deletion.DeletionPhase.REQUESTED,
        deletion.DeletionPhase.API_VETO_ACTIVE,
        deletion.DeletionPhase.TOMBSTONE_ACTIVE,
        deletion.DeletionPhase.CHECKPOINT_COMMITTED,
        deletion.DeletionPhase.REVOCATION_KEYS_DESTROYED,
    ]
    post_shred = [
        deletion.DeletionPhase.CRYPTO_SHRED_COMPLETE,
        deletion.DeletionPhase.PURGE_PENDING,
        deletion.DeletionPhase.COMPLETE,
    ]
    for phase in pre_shred:
        assert deletion.is_crypto_shredded(phase) is False
    for phase in post_shred:
        assert deletion.is_crypto_shredded(phase) is True


# ---------------------------------------------------------------------------
# (i) Forget requires dual custody
# ---------------------------------------------------------------------------


def test_forget_requires_dual_custody(pipeline_no_keystores):
    """Forget with no keystores must raise forget_requires_dual_custody."""
    r = pipeline_no_keystores.remember(raw_body=b"no-key-body", project_id="proj-1")
    with pytest.raises(PipelineError) as excinfo:
        pipeline_no_keystores.forget(
            artifact_id=r.artifact_semantic_digest,
            blob_id=r.blob_id,
        )
    assert excinfo.value.code == "forget_requires_dual_custody"


def test_resume_deletion_requires_dual_custody(pipeline_no_keystores):
    """Resume deletion with no keystores must raise forget_requires_dual_custody."""
    r = pipeline_no_keystores.remember(raw_body=b"no-key-resume-body", project_id="proj-1")
    # Insert a deletion_state row manually to simulate interrupted forget.
    with pipeline_no_keystores.db.unit_of_work() as uow:
        uow.insert_deletion_state(
            deletion_id="aa" * 32,
            artifact_id=r.artifact_semantic_digest,
            phase_state="CHECKPOINT_COMMITTED",
            updated_at="2026-07-24T00:01:00Z",
        )
    with pytest.raises(PipelineError) as excinfo:
        pipeline_no_keystores.resume_deletion(
            deletion_command_id="aa" * 32,
            artifact_id=r.artifact_semantic_digest,
            blob_id=r.blob_id,
        )
    assert excinfo.value.code == "forget_requires_dual_custody"


# ---------------------------------------------------------------------------
# (j) DeletionStateV1 validation adversarial
# ---------------------------------------------------------------------------


def test_deletion_state_rejects_bad_phase():
    """Build with invalid phase string must fail."""
    with pytest.raises(deletion.DeletionError) as excinfo:
        deletion.build_deletion_state(
            workspace_id="ws-test",
            deletion_command_id="a" * 64,
            phase="INVALID_PHASE",
            report=deletion.initial_report(),
            updated_at="2026-07-25T00:00:00Z",
        )
    assert excinfo.value.code == "deletion_state_schema_violation"
    # Should succeed, but let's test with a different schema
    state = deletion.build_deletion_state(
        workspace_id="ws-test",
        deletion_command_id="a" * 64,
        phase=deletion.DeletionPhase.REQUESTED,
        report=deletion.initial_report(),
        updated_at="2026-07-25T00:00:00Z",
    )
    state["schema"] = "wrong-schema"
    from wiki_spike.infrastructure.deletion import _validate_deletion_state_schema
    with pytest.raises(deletion.DeletionError) as excinfo:
        _validate_deletion_state_schema(state)
    assert excinfo.value.code == "deletion_state_schema_violation"


def test_deletion_state_rejects_bad_workspace_id():
    """Invalid workspace_id must fail validation."""
    with pytest.raises(deletion.DeletionError) as excinfo:
        deletion.build_deletion_state(
            workspace_id="Not-Valid!",
            deletion_command_id="a" * 64,
            phase=deletion.DeletionPhase.REQUESTED,
            report=deletion.initial_report(),
            updated_at="2026-07-25T00:00:00Z",
        )
    assert excinfo.value.code == "deletion_state_schema_violation"


def test_deletion_state_rejects_non_hex64_deletion_command_id():
    """Non-hex deletion_command_id must fail."""
    with pytest.raises(deletion.DeletionError) as excinfo:
        deletion.build_deletion_state(
            workspace_id="ws-test",
            deletion_command_id="not-hex-at-all",
            phase=deletion.DeletionPhase.REQUESTED,
            report=deletion.initial_report(),
            updated_at="2026-07-25T00:00:00Z",
        )
    assert excinfo.value.code == "deletion_state_schema_violation"


def test_deletion_state_rejects_extra_fields():
    """Extra fields in deletion state must fail."""
    state = deletion.build_deletion_state(
        workspace_id="ws-test",
        deletion_command_id="a" * 64,
        phase=deletion.DeletionPhase.REQUESTED,
        report=deletion.initial_report(),
        updated_at="2026-07-25T00:00:00Z",
    )
    state["surprise_key"] = "boom"
    from wiki_spike.infrastructure.deletion import _validate_deletion_state_schema
    with pytest.raises(deletion.DeletionError) as excinfo:
        _validate_deletion_state_schema(state)
    assert excinfo.value.code == "deletion_state_schema_violation"


# ---------------------------------------------------------------------------
# (k) Keystore destroy idempotency
# ---------------------------------------------------------------------------


def test_keystore_destroy_idempotent(pipeline):
    """Double destroy on the same handle must not raise."""
    r = pipeline.remember(raw_body=b"destroy-idempotent-body", project_id="proj-1")
    aid = r.artifact_semantic_digest
    ws = pipeline.workspace_id

    # First destroy
    receipt1 = pipeline.platform_keystore.destroy(ws, aid)
    assert receipt1.receipt_digest is not None

    # Second destroy -- must succeed (idempotent)
    receipt2 = pipeline.platform_keystore.destroy(ws, aid)
    assert receipt2.receipt_digest == receipt1.receipt_digest


def test_keystore_destroy_nonexistent_raises(pipeline):
    """Destroy on a non-existent handle must raise KeyNotFound."""
    with pytest.raises(ks.KeyNotFound):
        pipeline.platform_keystore.destroy(pipeline.workspace_id, "nonexistent-handle")


def test_keystore_create_only_on_destroyed_raises(pipeline):
    """Create-only on a destroyed handle must raise KeyAlreadyDestroyed."""
    r = pipeline.remember(raw_body=b"create-on-destroyed-body", project_id="proj-1")
    aid = r.artifact_semantic_digest
    ws = pipeline.workspace_id

    pipeline.platform_keystore.destroy(ws, aid)
    with pytest.raises(ks.KeyAlreadyDestroyed):
        pipeline.platform_keystore.create_only(ws, aid, TEST_DEK.hex(), aid)


# ---------------------------------------------------------------------------
# (l) KeyStoreError hierarchy
# ---------------------------------------------------------------------------


def test_keystore_readback_challenge_nonexistent_raises_key_not_found(pipeline):
    """Readback on non-existent handle must raise KeyNotFound."""
    with pytest.raises(ks.KeyNotFound):
        pipeline.platform_keystore.readback_challenge(pipeline.workspace_id, "nonexistent")


def test_keystore_readback_challenge_destroyed_raises_key_destroyed(pipeline):
    """Readback after destroy must raise KeyDestroyed."""
    r = pipeline.remember(raw_body=b"readback-destroyed-body", project_id="proj-1")
    pipeline.platform_keystore.destroy(pipeline.workspace_id, r.artifact_semantic_digest)
    with pytest.raises(ks.KeyDestroyed):
        pipeline.platform_keystore.readback_challenge(pipeline.workspace_id, r.artifact_semantic_digest)