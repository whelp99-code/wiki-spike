"""Gate 3 tests: ADR-0027 §4 recovery-proof modes (DELTA_CONTINUITY /
AUTHORITATIVE_SNAPSHOT) built on top of the frozen
``wiki_spike.infrastructure.binding_registry.BindingRegistry`` proof set.

Reuses the exact registry-construction pattern from
``test_binding_registry.py`` (deterministic TEST-ONLY Ed25519 seeds,
``append_leaf`` / ``checkpoint`` / ``attest`` / ``build_proof_set``).
Every ``recover()`` call under test consumes a fresh attestation nonce
(verify_proof_set's replay protection), so each test case builds its own
registry + attestation rather than sharing state across assertions.

Fail-closed is the property under test throughout: no assertion in this
file ever expects ``RECOVERED`` from an invalid, tampered, identity-
mismatched, or under-specified proof.
"""
from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.binding_registry import BindingRegistry
from wiki_spike.infrastructure.recovery import RecoveryDecision, RecoveryMode, recover

WORKSPACE_ID = "ws-gate3-recovery"

TEST_ONLY_ED25519_SEED_1 = hashlib.sha256(
    b"WIKI-SPIKE-GATE3-RECOVERY-TEST-ONLY-ED25519-SEED-1"
).digest()
TEST_ONLY_ED25519_SEED_2 = hashlib.sha256(
    b"WIKI-SPIKE-GATE3-RECOVERY-TEST-ONLY-ED25519-SEED-2"
).digest()

SIGNING_KEY_1 = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_ED25519_SEED_1)
SIGNING_KEY_2 = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_ED25519_SEED_2)
SIGNER_KEY_ID_1 = "gate3-signer-1"

FLOOR_CHECKPOINT_ID = hashlib.sha256(b"gate3-floor-checkpoint-genesis").hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _leaf_fields(handle: str, status: str) -> dict:
    return {
        "namespace": "encrypted-lifecycle",
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
    """Registry with 3 signed leaves: provider-a (PREPARED), provider-b
    (ACTIVE), provider-c (LOSER) — provider-b is the queried identity in
    every positive-path test below."""
    registry = BindingRegistry(WORKSPACE_ID)
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
        generation_id=sha256_hex(b"gate3-generation-1"),
        created_at="2026-07-24T00:05:00Z",
        signing_key=SIGNING_KEY_1,
        key_id=SIGNER_KEY_ID_1,
        registry_sequence="3",
    )


def _build_attestation(registry: BindingRegistry, checkpoint: dict, *, nonce_seed: bytes) -> dict:
    """Attests to the given checkpoint via ``checkpoint=`` so
    ``checkpoint_id == checkpoint_sha256 == sha256(canonical checkpoint)``
    holds (R10-4), which AUTHORITATIVE_SNAPSHOT depends on. Each call
    takes a distinct ``nonce_seed`` so replay protection never collides
    across test cases."""
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
        namespace="encrypted-lifecycle",
        provider_handle=provider_handle,
        old_size=2,
        inclusion_indices=[1],
        predecessor_leaf_indices=[],
    )


def _local_old_root_hex(registry: BindingRegistry) -> str:
    """The genuine locally trusted history root at size 2 (i.e. before
    the provider-b/provider-c leaves that the proof set's consistency
    proof continues from), matching the fixed ``old_size=2`` used by
    ``_build_proof_set``."""
    return crypto.merkle_root(registry._history_entry_hashes[:2]).hex()


# ---------------------------------------------------------------------------
# (a) DELTA_CONTINUITY with a valid proof-set continuing the exact local
#     (history_size, history_root) -> RECOVERED.
# ---------------------------------------------------------------------------


def test_delta_continuity_recovers_on_exact_local_continuity():
    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate3-nonce-a")
    decision = recover(
        mode=RecoveryMode.DELTA_CONTINUITY,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace="encrypted-lifecycle",
        expected_provider_handle="provider-b",
        local_history_size=2,
        local_history_root_hex=_local_old_root_hex(registry),
    )
    assert decision == RecoveryDecision.RECOVERED


# ---------------------------------------------------------------------------
# (b) DELTA_CONTINUITY where local_history_root_hex is wrong (or old_size
#     mismatched) -> QUARANTINE_UNKNOWN.
# ---------------------------------------------------------------------------


def test_delta_continuity_quarantines_on_wrong_local_root():
    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate3-nonce-b1")
    decision = recover(
        mode=RecoveryMode.DELTA_CONTINUITY,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace="encrypted-lifecycle",
        expected_provider_handle="provider-b",
        local_history_size=2,
        local_history_root_hex="00" * 32,  # wrong root
    )
    assert decision == RecoveryDecision.QUARANTINE_UNKNOWN


def test_delta_continuity_quarantines_on_mismatched_local_old_size():
    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate3-nonce-b2")
    decision = recover(
        mode=RecoveryMode.DELTA_CONTINUITY,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace="encrypted-lifecycle",
        expected_provider_handle="provider-b",
        local_history_size=1,  # proof continues from old_size=2, not 1
        local_history_root_hex=_local_old_root_hex(registry),
    )
    assert decision == RecoveryDecision.QUARANTINE_UNKNOWN


# ---------------------------------------------------------------------------
# (c) AUTHORITATIVE_SNAPSHOT with a valid fresh checkpoint proof-set
#     -> RECOVERED (no local_history_* anchoring required).
# ---------------------------------------------------------------------------


def test_authoritative_snapshot_recovers_without_local_anchor():
    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate3-nonce-c")
    decision = recover(
        mode=RecoveryMode.AUTHORITATIVE_SNAPSHOT,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace="encrypted-lifecycle",
        expected_provider_handle="provider-b",
        # deliberately no local_history_size / local_history_root_hex
    )
    assert decision == RecoveryDecision.RECOVERED


# ---------------------------------------------------------------------------
# (d) Tampered proof-set -> QUARANTINE_UNKNOWN under BOTH modes.
# ---------------------------------------------------------------------------


def test_tampered_checkpoint_history_root_quarantines_both_modes():
    for mode, nonce_seed in (
        (RecoveryMode.DELTA_CONTINUITY, b"gate3-nonce-d1-delta"),
        (RecoveryMode.AUTHORITATIVE_SNAPSHOT, b"gate3-nonce-d1-auth"),
    ):
        registry = _build_registry()
        proof_set = _build_proof_set(registry, nonce_seed=nonce_seed)
        tampered = json.loads(json.dumps(proof_set))
        root = tampered["checkpoint"]["history_root"]
        tampered["checkpoint"]["history_root"] = ("0" if root[0] != "0" else "1") + root[1:]
        decision = recover(
            mode=mode,
            registry=registry,
            proof_set=tampered,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
            expected_namespace="encrypted-lifecycle",
            expected_provider_handle="provider-b",
            local_history_size=2,
            local_history_root_hex=_local_old_root_hex(registry),
        )
        assert decision == RecoveryDecision.QUARANTINE_UNKNOWN


def test_tampered_sparse_sibling_quarantines_both_modes():
    for mode, nonce_seed in (
        (RecoveryMode.DELTA_CONTINUITY, b"gate3-nonce-d2-delta"),
        (RecoveryMode.AUTHORITATIVE_SNAPSHOT, b"gate3-nonce-d2-auth"),
    ):
        registry = _build_registry()
        proof_set = _build_proof_set(registry, nonce_seed=nonce_seed)
        tampered = json.loads(json.dumps(proof_set))
        sib = tampered["current_sparse_proof"]["siblings"][0]
        tampered["current_sparse_proof"]["siblings"][0] = ("0" if sib[0] != "0" else "1") + sib[1:]
        decision = recover(
            mode=mode,
            registry=registry,
            proof_set=tampered,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
            expected_namespace="encrypted-lifecycle",
            expected_provider_handle="provider-b",
            local_history_size=2,
            local_history_root_hex=_local_old_root_hex(registry),
        )
        assert decision == RecoveryDecision.QUARANTINE_UNKNOWN


def test_wrong_signer_key_quarantines_both_modes():
    """Substituting the trusted signer's public key (as if the proof set
    were signed by an untrusted party) must fail closed under both
    modes, independent of any tampering to the wire bytes themselves."""
    for mode, nonce_seed in (
        (RecoveryMode.DELTA_CONTINUITY, b"gate3-nonce-d3-delta"),
        (RecoveryMode.AUTHORITATIVE_SNAPSHOT, b"gate3-nonce-d3-auth"),
    ):
        registry = _build_registry()
        proof_set = _build_proof_set(registry, nonce_seed=nonce_seed)
        decision = recover(
            mode=mode,
            registry=registry,
            proof_set=proof_set,
            trusted_signer_pub=SIGNING_KEY_2.public_key(),  # wrong signer
            local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
            expected_namespace="encrypted-lifecycle",
            expected_provider_handle="provider-b",
            local_history_size=2,
            local_history_root_hex=_local_old_root_hex(registry),
        )
        assert decision == RecoveryDecision.QUARANTINE_UNKNOWN


# ---------------------------------------------------------------------------
# (e) Proof-set for a different (namespace, provider_handle) than queried
#     -> QUARANTINE_UNKNOWN (identity binding) under both modes.
# ---------------------------------------------------------------------------


def test_identity_substitution_quarantines_both_modes():
    for mode, nonce_seed in (
        (RecoveryMode.DELTA_CONTINUITY, b"gate3-nonce-e-delta"),
        (RecoveryMode.AUTHORITATIVE_SNAPSHOT, b"gate3-nonce-e-auth"),
    ):
        registry = _build_registry()
        # Proof set genuinely proves provider-b's binding...
        proof_set = _build_proof_set(registry, nonce_seed=nonce_seed, provider_handle="provider-b")
        decision = recover(
            mode=mode,
            registry=registry,
            proof_set=proof_set,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
            # ...but the caller is asking about provider-a.
            expected_namespace="encrypted-lifecycle",
            expected_provider_handle="provider-a",
            local_history_size=2,
            local_history_root_hex=_local_old_root_hex(registry),
        )
        assert decision == RecoveryDecision.QUARANTINE_UNKNOWN


# ---------------------------------------------------------------------------
# (f) Missing local_history_* for DELTA_CONTINUITY -> QUARANTINE_UNKNOWN.
# ---------------------------------------------------------------------------


def test_delta_continuity_quarantines_on_missing_local_history_size():
    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate3-nonce-f1")
    decision = recover(
        mode=RecoveryMode.DELTA_CONTINUITY,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace="encrypted-lifecycle",
        expected_provider_handle="provider-b",
        local_history_size=None,
        local_history_root_hex=_local_old_root_hex(registry),
    )
    assert decision == RecoveryDecision.QUARANTINE_UNKNOWN


def test_delta_continuity_quarantines_on_missing_local_history_root():
    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate3-nonce-f2")
    decision = recover(
        mode=RecoveryMode.DELTA_CONTINUITY,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace="encrypted-lifecycle",
        expected_provider_handle="provider-b",
        local_history_size=2,
        local_history_root_hex=None,
    )
    assert decision == RecoveryDecision.QUARANTINE_UNKNOWN


def test_delta_continuity_quarantines_on_both_local_history_fields_missing():
    registry = _build_registry()
    proof_set = _build_proof_set(registry, nonce_seed=b"gate3-nonce-f3")
    decision = recover(
        mode=RecoveryMode.DELTA_CONTINUITY,
        registry=registry,
        proof_set=proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=FLOOR_CHECKPOINT_ID,
        expected_namespace="encrypted-lifecycle",
        expected_provider_handle="provider-b",
    )
    assert decision == RecoveryDecision.QUARANTINE_UNKNOWN
