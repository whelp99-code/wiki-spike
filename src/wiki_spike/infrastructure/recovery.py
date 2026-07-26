"""ADR-0027 §4 recovery-proof modes over the binding-registry proof set.

Implements the two plan-mandated recovery decisions for the Encrypted
Single-Memory Lifecycle:

- ``DELTA_CONTINUITY`` — proves generation continuity from the last locally
  trusted checkpoint forward through an unbroken history-consistency proof
  to the terminal current leaf.
- ``AUTHORITATIVE_SNAPSHOT`` — accepts a freshly issued, independently
  authoritative signed checkpoint directly, without requiring continuity
  from any local trust anchor (the clean-room / no-local-baseline path).

Fail-closed is the overriding rule throughout this module: any exception,
missing proof, tampered proof, replayed nonce, forked/gapped history,
root/floor mismatch, or identity mismatch resolves to
:class:`RecoveryDecision.QUARANTINE_UNKNOWN`, never ``RECOVERED``. An
incomplete proof can never be treated as an implicit pass (ADR-0027 §4).

NOTE (``G5-ATTESTATION-TIME-CHECK``, delivered in Gate 5): clock-window/skew
freshness enforcement of the attestation's ``issued_at``/``expires_at`` IS now
performed by ``verify_proof_set`` (and thus by ``recover``) whenever a trusted
clock ``now`` (ISO-8601 UTC) is injected, with a default 300-second freshness
window and ±60-second skew. A validly-signed but stale/expired/not-yet-valid
attestation then fails closed to ``QUARANTINE_UNKNOWN``. When ``now`` is omitted
(e.g. Gate-3 callers with no trusted clock) the staleness guards are the R10-5
``request_floor_checkpoint_id`` binding, the in-registry nonce/counter replay
guard, and the signature/root/consistency binding; a Gate-5 deletion/restore
caller MUST inject ``now`` so time freshness is enforced before visibility.
"""
from __future__ import annotations

import hashlib
from enum import Enum
from typing import Mapping

from wiki_spike.infrastructure.binding_registry import (
    BindingRegistry,
    _verify_consistency,
)
from wiki_spike.memory_core.contracts import canonical_bytes


class RecoveryMode(str, Enum):
    """ADR-0027 §4 recovery-proof modes."""

    DELTA_CONTINUITY = "DELTA_CONTINUITY"
    AUTHORITATIVE_SNAPSHOT = "AUTHORITATIVE_SNAPSHOT"


class RecoveryDecision(str, Enum):
    """Outcome of :func:`recover`. Fail-closed: any doubt resolves to
    ``QUARANTINE_UNKNOWN``, never ``RECOVERED``."""

    RECOVERED = "RECOVERED"
    QUARANTINE_UNKNOWN = "QUARANTINE_UNKNOWN"


def recover(
    *,
    mode: RecoveryMode,
    registry: BindingRegistry,
    proof_set: Mapping,
    trusted_signer_pub,
    local_floor_checkpoint_id: str,
    expected_namespace: str,
    expected_provider_handle: str,
    local_history_size: int | None = None,
    local_history_root_hex: str | None = None,
    now: str | None = None,
    freshness_seconds: int = 300,
    skew_seconds: int = 60,
) -> RecoveryDecision:
    """Evaluates ``proof_set`` under ``mode`` and returns a
    :class:`RecoveryDecision`.

    Always first runs the registry's full ordered proof-set verification
    pipeline (signature/nonce/counter/signer chain, floor binding,
    checkpoint identity, history consistency, every inclusion/predecessor
    leaf, sparse membership/non-membership, and the queried-identity
    binding). Any failure there — tampered, replayed, omitted, forked,
    gapped, root-mismatched, or floor-mismatched — is caught here and mapped
    to ``QUARANTINE_UNKNOWN``. When a trusted clock ``now`` (ISO-8601 UTC) is
    injected, the attestation's ``issued_at``/``expires_at``/skew freshness is
    also enforced (G5-ATTESTATION-TIME-CHECK): a stale/expired/not-yet-valid
    attestation likewise maps to ``QUARANTINE_UNKNOWN``.

    ``DELTA_CONTINUITY`` additionally requires the proof's history
    consistency segment to continue the caller's locally trusted
    ``(local_history_size, local_history_root_hex)`` exactly.

    ``AUTHORITATIVE_SNAPSHOT`` additionally requires the attestation's
    ``checkpoint_id``/``checkpoint_sha256`` to equal the independently
    recomputed ``sha256(canonical checkpoint)`` (authoritative identity,
    ADR-0026 §4/R10-4) but does *not* require any local-history anchoring.

    This function never raises: every exception is caught and mapped to
    ``QUARANTINE_UNKNOWN`` (fail-closed).
    """
    try:
        registry.verify_proof_set(
            proof_set,
            trusted_signer_pub=trusted_signer_pub,
            local_floor_checkpoint_id=local_floor_checkpoint_id,
            expected_namespace=expected_namespace,
            expected_provider_handle=expected_provider_handle,
            now=now,
            freshness_seconds=freshness_seconds,
            skew_seconds=skew_seconds,
        )

        if mode == RecoveryMode.DELTA_CONTINUITY:
            return _recover_delta_continuity(proof_set, local_history_size, local_history_root_hex)
        if mode == RecoveryMode.AUTHORITATIVE_SNAPSHOT:
            return _recover_authoritative_snapshot(proof_set)
        return RecoveryDecision.QUARANTINE_UNKNOWN
    except Exception:
        return RecoveryDecision.QUARANTINE_UNKNOWN


def _recover_delta_continuity(
    proof_set: Mapping,
    local_history_size: int | None,
    local_history_root_hex: str | None,
) -> RecoveryDecision:
    if local_history_size is None or local_history_root_hex is None:
        return RecoveryDecision.QUARANTINE_UNKNOWN

    consistency = proof_set["history_consistency_proof"]
    old_size = int(consistency["old_size"])
    new_size = int(consistency["new_size"])
    if old_size != local_history_size:
        return RecoveryDecision.QUARANTINE_UNKNOWN

    audit_path = [bytes.fromhex(h) for h in consistency["audit_path"]]
    ok, reconstructed_old_root, _reconstructed_new_root = _verify_consistency(old_size, new_size, audit_path)
    if not ok:
        # Covers the old_size == 0 and old_size == new_size edge cases too:
        # _verify_consistency only reconstructs a genuine old-root
        # membership for 0 < old_size < new_size, so any case it cannot
        # positively reconstruct is treated conservatively as unproven
        # continuity rather than an implicit pass.
        return RecoveryDecision.QUARANTINE_UNKNOWN
    if reconstructed_old_root.hex() != local_history_root_hex:
        return RecoveryDecision.QUARANTINE_UNKNOWN

    return RecoveryDecision.RECOVERED


def _recover_authoritative_snapshot(proof_set: Mapping) -> RecoveryDecision:
    attestation = proof_set["attestation"]
    checkpoint = proof_set["checkpoint"]
    checkpoint_signature = proof_set["checkpoint_signature"]
    payload = attestation["payload"]

    recomputed_checkpoint_sha256 = hashlib.sha256(canonical_bytes(checkpoint)).hexdigest()
    if payload.get("checkpoint_id") != recomputed_checkpoint_sha256:
        return RecoveryDecision.QUARANTINE_UNKNOWN
    if payload.get("checkpoint_sha256") != recomputed_checkpoint_sha256:
        return RecoveryDecision.QUARANTINE_UNKNOWN
    if checkpoint_signature.get("checkpoint_sha256") != recomputed_checkpoint_sha256:
        return RecoveryDecision.QUARANTINE_UNKNOWN

    return RecoveryDecision.RECOVERED
