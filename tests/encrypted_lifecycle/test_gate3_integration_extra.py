"""Gate 3 close-out integration tests: the two previously-untested
pipeline paths flagged by the close-out review.

(A)/(B)/(C) exercise ``EncryptedLifecyclePipeline.recover()`` (ADR-0027
§4 crash-recovery entry point): the DELTA_CONTINUITY / AUTHORITATIVE_SNAPSHOT
happy paths, the fail-closed tamper-quarantine path, and the
RECOVERY_<decision> event-chain wiring. Construction of the local trusted
``BindingRegistry`` + proof set mirrors
``tests/encrypted_lifecycle/test_gate3_recovery.py`` exactly (deterministic
TEST-ONLY Ed25519 seeds, ``append_leaf``/``checkpoint``/``attest``/
``build_proof_set``); every ``recover()`` call consumes a fresh attestation
nonce, so each assertion that calls ``recover()`` more than once builds a
fresh proof set with a distinct nonce seed.

(D) exercises ``EncryptedLifecyclePipeline.create_generation(...,
binding_registry=<a real BindingRegistry>)`` — the per-delta
``append_leaf`` + ``checkpoint`` branch that all other Gate 3 pipeline
tests skip by passing ``binding_registry=None``.

Both source-level defects discovered while writing this file have since been
FIXED in ``src/wiki_spike/applications/encrypted_lifecycle_pipeline.py`` and
are pinned here by positive assertions (no xfail):

1. ``recover()`` now reads the recovery event's ``ref_digest`` from
   ``proof_set["checkpoint_signature"]["checkpoint_sha256"]`` (not from
   ``proof_set["checkpoint"]``), so
   ``test_recover_authoritative_snapshot_recovers_and_appends_event`` asserts
   the real checkpoint identity.
2. ``create_generation(..., binding_registry=<registry>)`` now passes the
   required ``activation_generation_id``/``signing_key``/``key_id`` kwargs to
   ``append_leaf`` (and ``created_at``/``key_id`` to ``checkpoint``), so
   ``test_create_generation_with_binding_registry_appends_leaves_and_checkpoint``
   asserts a non-``None`` ``binding_checkpoint_id`` + per-delta leaves + a
   verifying generation signature.

One KNOWN GAP is documented (not fixed) as an explicit ``xfail(strict=True)``:
``test_expired_attestation_recovery_should_quarantine_gate5_gap`` records that
attestation ``issued_at``/``expires_at``/skew freshness is NOT enforced by
``verify_proof_set``/``recover()`` in the Gate 3 deterministic vertical — a
validly-signed but time-expired attestation currently returns ``RECOVERED``.
Enforcement is deferred to the Gate 5 deletion/crash runtime (which must
inject a trusted clock + skew policy under the Escalation/Risk Gate) under the
tracked requirement ``G5-ATTESTATION-TIME-CHECK``.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    GENERATION_DOMAIN,
    EncryptedLifecyclePipeline,
)
from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.binding_registry import BindingRegistry
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.recovery import RecoveryDecision, RecoveryMode

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()

TEST_ONLY_ED25519_SEED_1 = hashlib.sha256(
    b"WIKI-SPIKE-GATE3-INTEGRATION-EXTRA-TEST-ONLY-ED25519-SEED-1"
).digest()
SIGNING_KEY_1 = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_ED25519_SEED_1)
SIGNER_KEY_ID_1 = "gate3-extra-signer-1"

FLOOR_CHECKPOINT_ID = hashlib.sha256(b"gate3-extra-floor-checkpoint-genesis").hexdigest()

REGISTRY_NAMESPACE = "encrypted-lifecycle"


@pytest.fixture()
def pipeline(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-gate3-extra",
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
    """Registry with 3 signed leaves, mirroring test_gate3_recovery.py's
    ``_build_registry``: provider-a (PREPARED), provider-b (ACTIVE,
    the queried identity below), provider-c (LOSER)."""
    registry = BindingRegistry("ws-gate3-extra")
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
        generation_id=sha256_hex(b"gate3-extra-generation-1"),
        created_at="2026-07-24T00:05:00Z",
        signing_key=SIGNING_KEY_1,
        key_id=SIGNER_KEY_ID_1,
        registry_sequence="3",
    )


def _build_attestation(registry: BindingRegistry, checkpoint: dict, *, nonce_seed: bytes) -> dict:
    return registry.attest(
        request_nonce=sha256_hex(nonce_seed),
        challenge_counter="1",
        request_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        signer_key_id=SIGNER_KEY_ID_1,
        issued_at="2026-07-24T00:00:00Z",
        expires_at="2026-07-24T00:05:00Z",
        signing_key=SIGNING_KEY_1,
        checkpoint=checkpoint,
    )


def _build_proof_set(registry: BindingRegistry, *, nonce_seed: bytes, provider_handle: str = "provider-b") -> dict:
    checkpoint, checkpoint_signature = _build_checkpoint(registry)
    attestation = _build_attestation(registry, checkpoint, nonce_seed=nonce_seed)
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


def _local_old_root_hex(registry: BindingRegistry) -> str:
    """The genuine locally trusted history root at size 2, matching the
    fixed ``old_size=2`` used by ``_build_proof_set``."""
    return crypto.merkle_root(registry._history_entry_hashes[:2]).hex()


def _event_kinds(pipeline: EncryptedLifecyclePipeline) -> list[str]:
    return [row["event_kind"] for row in pipeline.db.event_log_rows()]


# ---------------------------------------------------------------------------
# (A) recover() AUTHORITATIVE_SNAPSHOT happy path -> RECOVERED, event appended.
# ---------------------------------------------------------------------------


def test_recover_authoritative_snapshot_recovers_and_appends_event(pipeline):
    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate3-extra-nonce-a")
    real_checkpoint_sha256 = proof_set["checkpoint_signature"]["checkpoint_sha256"]

    decision = pipeline.recover(
        mode=RecoveryMode.AUTHORITATIVE_SNAPSHOT,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace=REGISTRY_NAMESPACE,
        expected_provider_handle="provider-b",
    )
    assert decision == RecoveryDecision.RECOVERED

    rows = pipeline.db.event_log_rows()
    assert len(rows) == 1
    event = rows[0]
    assert event["event_kind"] == "RECOVERY_RECOVERED"

    assert event["ref_digest"] == real_checkpoint_sha256


# ---------------------------------------------------------------------------
# (B) recover() fail-closed quarantine on a tampered proof set: never raises,
#     returns QUARANTINE_UNKNOWN, and still appends a RECOVERY_* event.
# ---------------------------------------------------------------------------


def test_recover_authoritative_snapshot_tampered_proof_quarantines_without_raising(pipeline):
    import json

    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate3-extra-nonce-b")
    tampered = json.loads(json.dumps(proof_set))
    root = tampered["checkpoint"]["history_root"]
    tampered["checkpoint"]["history_root"] = ("0" if root[0] != "0" else "1") + root[1:]

    decision = pipeline.recover(
        mode=RecoveryMode.AUTHORITATIVE_SNAPSHOT,
        registry=registry,
        proof_set=tampered,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace=REGISTRY_NAMESPACE,
        expected_provider_handle="provider-b",
    )
    assert decision == RecoveryDecision.QUARANTINE_UNKNOWN

    kinds = _event_kinds(pipeline)
    assert kinds == ["RECOVERY_QUARANTINE_UNKNOWN"]


# ---------------------------------------------------------------------------
# (C) recover() DELTA_CONTINUITY: exact local continuity -> RECOVERED;
#     wrong local_history_root_hex on a second, freshly-nonced call ->
#     QUARANTINE_UNKNOWN. Both calls append their own event.
# ---------------------------------------------------------------------------


def test_recover_delta_continuity_recovers_then_quarantines_on_wrong_local_root(pipeline):
    registry = _build_registry()
    local_root_hex = _local_old_root_hex(registry)

    proof_set_1 = _build_proof_set(registry, nonce_seed=b"gate3-extra-nonce-c1")
    decision_1 = pipeline.recover(
        mode=RecoveryMode.DELTA_CONTINUITY,
        registry=registry,
        proof_set=proof_set_1,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace=REGISTRY_NAMESPACE,
        expected_provider_handle="provider-b",
        local_history_size=2,
        local_history_root_hex=local_root_hex,
    )
    assert decision_1 == RecoveryDecision.RECOVERED

    # Fresh proof set (fresh attestation nonce) for the second recover()
    # call -- verify_proof_set's replay protection consumes nonces.
    proof_set_2 = _build_proof_set(registry, nonce_seed=b"gate3-extra-nonce-c2")
    decision_2 = pipeline.recover(
        mode=RecoveryMode.DELTA_CONTINUITY,
        registry=registry,
        proof_set=proof_set_2,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace=REGISTRY_NAMESPACE,
        expected_provider_handle="provider-b",
        local_history_size=2,
        local_history_root_hex="00" * 32,  # wrong local root
    )
    assert decision_2 == RecoveryDecision.QUARANTINE_UNKNOWN

    assert _event_kinds(pipeline) == [
        "RECOVERY_RECOVERED",
        "RECOVERY_QUARANTINE_UNKNOWN",
    ]


# ---------------------------------------------------------------------------
# (D) create_generation(..., binding_registry=<real registry>): the
#     per-delta append_leaf + checkpoint branch.
# ---------------------------------------------------------------------------


def test_create_generation_with_binding_registry_appends_leaves_and_checkpoint(pipeline):
    """The binding-checkpoint branch of create_generation() appends one
    signed binding leaf per changeset delta and produces a signed checkpoint,
    returning a non-None binding_checkpoint_id; the generation signature
    verifies under the frozen wiki.generation.v1 domain (R10-2)."""
    r = pipeline.remember(raw_body=b"binding checkpoint generation test", project_id="proj-1")
    cs = pipeline.build_changeset(command_ids=[r.command_id])
    pipeline.persist_changeset(cs)
    n_deltas = len(cs["deltas"])
    assert n_deltas >= 1

    signing_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"gate3-extra-gen-key").digest())
    registry = BindingRegistry(pipeline.workspace_id)

    gen = pipeline.create_generation(
        changeset_id=cs["changeset_id"],
        signing_key=signing_key,
        signer_key_id="test-signer-1",
        binding_registry=registry,
        namespace=REGISTRY_NAMESPACE,
        provider_handle="default",
    )

    assert gen["binding_checkpoint_id"] is not None
    assert registry.history_size == n_deltas
    assert registry.current_map_size >= 1
    crypto.verify(signing_key.public_key(), GENERATION_DOMAIN, gen["payload"], gen["signature"])
    assert "GENERATION_SIGNED" in _event_kinds(pipeline)


def test_generation_signature_verifies_under_generation_domain_without_binding_registry(pipeline):
    """Sanity-anchor for the signature contract that (D) would also need
    to hold once the binding-registry wiring defect above is fixed:
    create_generation()'s signature must verify under GENERATION_DOMAIN
    for the exact payload it returns."""
    r = pipeline.remember(raw_body=b"generation signature test", project_id="proj-1")
    cs = pipeline.build_changeset(command_ids=[r.command_id])
    pipeline.persist_changeset(cs)

    signing_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"gate3-extra-gen-key-2").digest())
    gen = pipeline.create_generation(
        changeset_id=cs["changeset_id"],
        signing_key=signing_key,
        signer_key_id="test-signer-2",
    )
    assert gen["binding_checkpoint_id"] is None
    crypto.verify(signing_key.public_key(), GENERATION_DOMAIN, gen["payload"], gen["signature"])

# ---------------------------------------------------------------------------
# (E) KNOWN GAP (deferred to Gate 5): attestation clock-window/skew freshness
#     is not enforced, so a validly-signed but time-expired attestation is
#     currently accepted. Pinned as xfail(strict=True) under
#     G5-ATTESTATION-TIME-CHECK; will pass once Gate 5 enforces expiry.
# ---------------------------------------------------------------------------


def _build_expired_proof_set(registry: BindingRegistry, *, nonce_seed: bytes) -> dict:
    checkpoint, checkpoint_signature = _build_checkpoint(registry)
    attestation = registry.attest(
        request_nonce=sha256_hex(nonce_seed),
        challenge_counter="1",
        request_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        signer_key_id=SIGNER_KEY_ID_1,
        issued_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-01T00:05:00Z",  # long past: an expired attestation
        signing_key=SIGNING_KEY_1,
        checkpoint=checkpoint,
    )
    return registry.build_proof_set(
        attestation=attestation,
        checkpoint=checkpoint,
        checkpoint_signature=checkpoint_signature,
        namespace=REGISTRY_NAMESPACE,
        provider_handle="provider-b",
        old_size=2,
        inclusion_indices=[1],
        predecessor_leaf_indices=[],
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "G5-ATTESTATION-TIME-CHECK: attestation issued_at/expires_at/skew "
        "freshness is NOT enforced by verify_proof_set/recover() in the Gate 3 "
        "deterministic vertical, so a validly-signed but time-expired "
        "attestation currently returns RECOVERED (fail-open on time). "
        "Enforcement is deferred to the Gate 5 deletion/crash runtime (requires "
        "an injected clock + skew policy under the Escalation/Risk Gate). This "
        "asserts the required Gate-5 behavior and will pass once the check lands."
    ),
)
def test_expired_attestation_recovery_should_quarantine_gate5_gap(pipeline):
    registry = _build_registry()
    proof_set = _build_expired_proof_set(registry, nonce_seed=b"gate3-extra-nonce-expired")
    decision = pipeline.recover(
        mode=RecoveryMode.AUTHORITATIVE_SNAPSHOT,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace=REGISTRY_NAMESPACE,
        expected_provider_handle="provider-b",
    )
    # REQUIRED Gate-5 behavior: an expired attestation must fail closed.
    assert decision == RecoveryDecision.QUARANTINE_UNKNOWN
