"""Gate 5 selective-restore tests for ``EncryptedLifecyclePipeline.restore()``.

Covers the three fail-closed gates that MUST run, in order, before restore()
ever releases visibility (ADR-0027 §4 / restore() docstring):

  1. Current-veto gate (``is_object_vetoed``) — a forgotten (deletion_state)
     artifact is never restorable; the veto dominates even an otherwise
     valid recovery proof.
  2. Recovery-proof gate (``recover()``) — a tampered or expired proof set
     fails closed to QUARANTINE_UNKNOWN and restore() raises
     ``restore_quarantined``.
  3. Freshness serve gate (``can_serve()``) — even a RECOVERED, non-vetoed
     artifact is withheld until the floor/freshness serve gate is CLEAR.

Also pins that a successful restore (a) flips key_state custody_state to
ACTIVE and appends an ARTIFACT_RESTORED event, and (b) never recreates a
destroyed ARK -- it does no keystore work at all, so it succeeds unchanged
even when the pipeline is constructed with no keystores.

Registry/proof-set construction (``SIGNING_KEY_1``, ``SIGNER_KEY_ID_1``,
``FLOOR_CHECKPOINT_ID``, ``REGISTRY_NAMESPACE``, ``_build_registry``,
``_build_checkpoint``, ``sha256_hex``) mirrors
``tests/encrypted_lifecycle/test_gate3_integration_extra.py`` exactly. Every
``restore()`` call consumes a fresh attestation nonce (``verify_proof_set``
replay protection), so each test that builds a proof set uses a distinct
nonce seed.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    EncryptedLifecyclePipeline,
    PipelineError,
)
from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.binding_registry import BindingRegistry
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.recovery import RecoveryMode

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()

TEST_ONLY_ED25519_SEED_1 = hashlib.sha256(
    b"WIKI-SPIKE-GATE5-RESTORE-TEST-ONLY-ED25519-SEED-1"
).digest()
SIGNING_KEY_1 = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_ED25519_SEED_1)
SIGNER_KEY_ID_1 = "gate5-restore-signer-1"

FLOOR_CHECKPOINT_ID = hashlib.sha256(b"gate5-restore-floor-checkpoint-genesis").hexdigest()

REGISTRY_NAMESPACE = "encrypted-lifecycle"

WITHIN_WINDOW_NOW = "2026-07-24T00:02:00Z"


@pytest.fixture()
def pipeline(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-gate5-restore",
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _leaf_fields(handle: str, status: str) -> dict:
    return {
        "namespace": REGISTRY_NAMESPACE,
        "provider_handle": handle,
        "provider_key_fingerprint": sha256_hex(handle.encode() + b"-fingerprint"),
        "intent_id": sha256_hex(handle.encode() + b"-intent"),
        "artifact_id": sha256_hex(handle.encode() + b"-artifact"),
        "revision_id": sha256_hex(handle.encode() + b"-revision"),
        "semantic_digest": sha256_hex(handle.encode() + b"-semantic"),
        "metadata_digest": sha256_hex(handle.encode() + b"-metadata"),
        "status": status,
        "activation_generation_id": sha256_hex(handle.encode() + b"-generation") if status == "ACTIVE" else None,
    }


def _build_registry() -> BindingRegistry:
    """Registry with 3 signed leaves, mirroring test_gate3_integration_extra.py's
    ``_build_registry``: provider-a (PREPARED), provider-b (ACTIVE, the
    queried identity below), provider-c (LOSER)."""
    registry = BindingRegistry("ws-gate5-restore")
    for handle, status in [
        ("provider-a", "PREPARED"),
        ("provider-b", "ACTIVE"),
        ("provider-c", "LOSER"),
    ]:
        registry.append_leaf(
            **_leaf_fields(handle, status),
            signing_key=SIGNING_KEY_1,
            key_id=SIGNER_KEY_ID_1,
        )
    return registry


def _build_checkpoint(registry: BindingRegistry) -> tuple[dict, dict]:
    return registry.checkpoint(
        generation_id=sha256_hex(b"gate5-restore-generation-1"),
        created_at="2026-07-24T00:05:00Z",
        signing_key=SIGNING_KEY_1,
        key_id=SIGNER_KEY_ID_1,
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
        signer_key_id=SIGNER_KEY_ID_1,
        issued_at=issued_at,
        expires_at=expires_at,
        signing_key=SIGNING_KEY_1,
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


def _restore_kwargs(*, artifact_id: str, registry: BindingRegistry, proof_set: dict, now: str) -> dict:
    return dict(
        artifact_id=artifact_id,
        mode=RecoveryMode.AUTHORITATIVE_SNAPSHOT,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace=REGISTRY_NAMESPACE,
        expected_provider_handle="provider-b",
        now=now,
    )


def _event_kinds(pipeline: EncryptedLifecyclePipeline) -> list[str]:
    return [row["event_kind"] for row in pipeline.db.event_log_rows()]


# ---------------------------------------------------------------------------
# (a) Happy restore: floor bootstrapped, valid proof -> RECOVERED + ACTIVE +
#     ARTIFACT_RESTORED event.
# ---------------------------------------------------------------------------


def test_restore_happy_path_activates_and_appends_event(pipeline):
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"restore me please", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate5-restore-nonce-happy")

    result = pipeline.restore(
        **_restore_kwargs(
            artifact_id=r.artifact_semantic_digest,
            registry=registry,
            proof_set=proof_set,
            now=WITHIN_WINDOW_NOW,
        )
    )

    assert result == {
        "artifact_id": r.artifact_semantic_digest,
        "decision": "RECOVERED",
        "restored": True,
    }

    with pipeline.db.unit_of_work() as uow:
        ks = uow.get_key_state(r.artifact_semantic_digest)
    assert ks["custody_state"] == "ACTIVE"

    assert "ARTIFACT_RESTORED" in _event_kinds(pipeline)


# ---------------------------------------------------------------------------
# (b) Veto dominates: a deletion_state row for the artifact blocks restore
#     even with an otherwise-valid, RECOVERED-able proof set.
# ---------------------------------------------------------------------------


def test_restore_raises_when_artifact_is_vetoed(pipeline):
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"forgotten artifact", project_id="proj-1")

    with pipeline.db.unit_of_work() as uow:
        uow.insert_deletion_state(
            deletion_id="ab" * 32,
            artifact_id=r.artifact_semantic_digest,
            phase_state="REQUESTED",
            updated_at="2026-07-24T00:01:00Z",
        )

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate5-restore-nonce-veto")

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(
            **_restore_kwargs(
                artifact_id=r.artifact_semantic_digest,
                registry=registry,
                proof_set=proof_set,
                now=WITHIN_WINDOW_NOW,
            )
        )
    assert excinfo.value.code == "restore_vetoed"

    # No visibility was released: key_state was never touched by restore.
    with pipeline.db.unit_of_work() as uow:
        ks = uow.get_key_state(r.artifact_semantic_digest)
    assert ks is None or ks["custody_state"] != "ACTIVE"
    assert "ARTIFACT_RESTORED" not in _event_kinds(pipeline)


# ---------------------------------------------------------------------------
# (c) Quarantined proof: tampered checkpoint history_root and expired
#     attestation both fail closed to restore_quarantined.
# ---------------------------------------------------------------------------


def test_restore_raises_when_proof_is_tampered(pipeline):
    import json

    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"tampered proof artifact", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate5-restore-nonce-tampered")
    tampered = json.loads(json.dumps(proof_set))
    root = tampered["checkpoint"]["history_root"]
    tampered["checkpoint"]["history_root"] = ("0" if root[0] != "0" else "1") + root[1:]

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(
            **_restore_kwargs(
                artifact_id=r.artifact_semantic_digest,
                registry=registry,
                proof_set=tampered,
                now=WITHIN_WINDOW_NOW,
            )
        )
    assert excinfo.value.code == "restore_quarantined"

    with pipeline.db.unit_of_work() as uow:
        ks = uow.get_key_state(r.artifact_semantic_digest)
    assert ks is None or ks["custody_state"] != "ACTIVE"
    assert "ARTIFACT_RESTORED" not in _event_kinds(pipeline)


def test_restore_raises_when_attestation_is_expired(pipeline):
    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"expired proof artifact", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate5-restore-nonce-expired")

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(
            **_restore_kwargs(
                artifact_id=r.artifact_semantic_digest,
                registry=registry,
                proof_set=proof_set,
                now="2026-07-24T09:00:00Z",  # long after expires_at
            )
        )
    assert excinfo.value.code == "restore_quarantined"

    with pipeline.db.unit_of_work() as uow:
        ks = uow.get_key_state(r.artifact_semantic_digest)
    assert ks is None or ks["custody_state"] != "ACTIVE"
    assert "ARTIFACT_RESTORED" not in _event_kinds(pipeline)


# ---------------------------------------------------------------------------
# (d) Serve withheld: floor not bootstrapped / freshness serve gate is not
#     CLEAR -> a RECOVERED, non-vetoed restore is still withheld.
# ---------------------------------------------------------------------------


def test_restore_raises_when_serve_gate_withholds(pipeline):
    # Deliberately do NOT bootstrap_workspace(); force the freshness serve
    # gate directly into a withholding state instead.
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

    r = pipeline.remember(raw_body=b"serve withheld artifact", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate5-restore-nonce-servewithheld")

    with pytest.raises(PipelineError) as excinfo:
        pipeline.restore(
            **_restore_kwargs(
                artifact_id=r.artifact_semantic_digest,
                registry=registry,
                proof_set=proof_set,
                now=WITHIN_WINDOW_NOW,
            )
        )
    assert excinfo.value.code == "restore_serve_withheld"

    # The RECOVERED decision was reached (and its event appended) before the
    # serve gate withheld visibility, but no ACTIVE custody was granted.
    assert "RECOVERY_RECOVERED" in _event_kinds(pipeline)
    with pipeline.db.unit_of_work() as uow:
        ks = uow.get_key_state(r.artifact_semantic_digest)
    assert ks is None or ks["custody_state"] != "ACTIVE"
    assert "ARTIFACT_RESTORED" not in _event_kinds(pipeline)


# ---------------------------------------------------------------------------
# (e) Never recreates a destroyed ARK: restore succeeds unchanged for a
#     pipeline built with NO keystores at all (platform/recovery None),
#     proving restore() performs no keystore/ARK-creation work.
# ---------------------------------------------------------------------------


def test_restore_never_recreates_ark_pipeline_has_no_keystores(pipeline):
    assert pipeline.platform_keystore is None
    assert pipeline.recovery_keystore is None

    pipeline.bootstrap_workspace()
    r = pipeline.remember(raw_body=b"no keystore restore artifact", project_id="proj-1")

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate5-restore-nonce-nokeystore")

    result = pipeline.restore(
        **_restore_kwargs(
            artifact_id=r.artifact_semantic_digest,
            registry=registry,
            proof_set=proof_set,
            now=WITHIN_WINDOW_NOW,
        )
    )

    assert result["restored"] is True
    assert result["decision"] == "RECOVERED"
    with pipeline.db.unit_of_work() as uow:
        ks = uow.get_key_state(r.artifact_semantic_digest)
    assert ks["custody_state"] == "ACTIVE"
