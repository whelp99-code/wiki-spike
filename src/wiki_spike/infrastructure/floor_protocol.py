"""Forward-only floor protocol and freshness serve gate.

Implements the ``FloorStateV1`` state machine (R9-1 exact-A immutable
completion, R10-1 no adoption/supersession) and ``FreshnessServeGateV1``
(R9-2/R10-3 three valid pairs) per
``schemas/encrypted-lifecycle/floor-state-v1.schema.json`` and
``schemas/encrypted-lifecycle/freshness-serve-gate-v1.schema.json``.

Architecture-boundary contract: infrastructure layer; may import
``wiki_spike.memory_core`` and intra-infrastructure only.
"""
from __future__ import annotations

import hashlib
from enum import Enum
from typing import Mapping

from wiki_spike.memory_core.contracts import canonical_bytes

FLOOR_STATE_SCHEMA = "wiki-floor-state-v1"
FLOOR_CANDIDATE_SCHEMA = "wiki-floor-candidate-v1"
SERVE_GATE_SCHEMA = "wiki-freshness-serve-gate-v1"


class FloorState(str, Enum):
    FLOOR_STABLE = "FLOOR_STABLE"
    CHALLENGE_RESERVED = "CHALLENGE_RESERVED"
    COUNTER_UPDATE_PREPARED = "COUNTER_UPDATE_PREPARED"
    FLOOR_UPDATE_PREPARED = "FLOOR_UPDATE_PREPARED"
    KEYCHAIN_COMMITTED = "KEYCHAIN_COMMITTED"
    QUARANTINED_FLOOR_CONFLICT = "QUARANTINED_FLOOR_CONFLICT"


class CandidateKind(str, Enum):
    COUNTER_ONLY = "COUNTER_ONLY"
    VALIDATED_ADVANCE = "VALIDATED_ADVANCE"


class CandidateDisposition(str, Enum):
    RESERVED = "RESERVED"
    ACCEPTED_PREPARED = "ACCEPTED_PREPARED"
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"
    QUARANTINED = "QUARANTINED"


class FloorProtocolError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_VALID_TRANSITIONS: dict[FloorState, frozenset[FloorState]] = {
    FloorState.FLOOR_STABLE: frozenset({FloorState.CHALLENGE_RESERVED}),
    FloorState.CHALLENGE_RESERVED: frozenset({
        FloorState.COUNTER_UPDATE_PREPARED,
        FloorState.FLOOR_UPDATE_PREPARED,
    }),
    FloorState.COUNTER_UPDATE_PREPARED: frozenset({FloorState.KEYCHAIN_COMMITTED}),
    FloorState.FLOOR_UPDATE_PREPARED: frozenset({FloorState.KEYCHAIN_COMMITTED}),
    FloorState.KEYCHAIN_COMMITTED: frozenset({FloorState.FLOOR_STABLE}),
    FloorState.QUARANTINED_FLOOR_CONFLICT: frozenset(),
}

_QUARANTINE_REACHABLE_FROM = frozenset({
    FloorState.CHALLENGE_RESERVED,
    FloorState.COUNTER_UPDATE_PREPARED,
    FloorState.FLOOR_UPDATE_PREPARED,
    FloorState.KEYCHAIN_COMMITTED,
})


def _assert_transition(current: FloorState, target: FloorState) -> None:
    if target == FloorState.QUARANTINED_FLOOR_CONFLICT:
        if current not in _QUARANTINE_REACHABLE_FROM:
            raise FloorProtocolError(
                "illegal_transition",
                f"cannot quarantine from {current.value}",
            )
        return
    if target not in _VALID_TRANSITIONS.get(current, frozenset()):
        raise FloorProtocolError(
            "illegal_transition",
            f"{current.value} -> {target.value} is not a valid floor transition",
        )


def advance(current: FloorState, target: FloorState) -> FloorState:
    """Public forward-only transition helper. Raises FloorProtocolError on
    an illegal transition; otherwise returns ``target``."""
    _assert_transition(current, target)
    return target


def floor_hash(floor_bytes: Mapping) -> str:
    return hashlib.sha256(canonical_bytes(floor_bytes)).hexdigest()


def build_floor_candidate(
    *,
    candidate_kind: CandidateKind,
    expected_old_floor_hash: str,
    expected_keychain_generation: str,
    candidate_floor: Mapping,
    attempt_id: str,
    counter: str,
    nonce_digest: str,
    disposition: CandidateDisposition = CandidateDisposition.RESERVED,
    reason_code: str | None = None,
) -> dict:
    candidate_floor_hash = floor_hash(candidate_floor)
    return {
        "schema": FLOOR_CANDIDATE_SCHEMA,
        "candidate_kind": candidate_kind.value,
        "expected_old_floor_hash": expected_old_floor_hash,
        "expected_keychain_generation": expected_keychain_generation,
        "candidate_floor": dict(candidate_floor),
        "candidate_floor_hash": candidate_floor_hash,
        "attempt_id": attempt_id,
        "counter": counter,
        "nonce_digest": nonce_digest,
        "disposition": disposition.value,
        "reason_code": reason_code,
    }


def verify_cas_readback(
    candidate: Mapping,
    keychain_bytes: Mapping,
) -> None:
    """R9-1: Keychain readback must byte-equal candidate A.

    Any B != A triggers QUARANTINED_FLOOR_CONFLICT (R10-1).
    """
    expected_hash = candidate["candidate_floor_hash"]
    actual_hash = floor_hash(keychain_bytes)
    if actual_hash != expected_hash:
        raise FloorProtocolError(
            "quarantined_floor_conflict",
            f"Keychain readback hash {actual_hash} does not match "
            f"immutable candidate A hash {expected_hash}; "
            f"no adoption/supersession exists (R10-1)",
        )


# ---------------------------------------------------------------------------
# FreshnessServeGateV1 (R9-2 / R10-3)
# ---------------------------------------------------------------------------

_VALID_SERVE_GATE_PAIRS = frozenset({
    ("CLEAR", "NONE"),
    ("FRESH_CHALLENGE_REQUIRED", "ATTESTATION_EXPIRED_BEFORE_STABILIZE"),
    ("FRESH_CHALLENGE_REQUIRED", "CLOCK_WINDOW_EXPIRED"),
})


class ServeGateError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def build_freshness_serve_gate(
    *,
    workspace_id: str,
    state: str,
    stable_floor_generation: str,
    stable_checkpoint_id: str,
    source_candidate_digest: str,
    reason: str,
    updated_at: str,
) -> dict:
    if (state, reason) not in _VALID_SERVE_GATE_PAIRS:
        raise ServeGateError(
            "invalid_serve_gate_pair",
            f"({state}, {reason}) is not one of the three R10-3 valid pairs",
        )
    return {
        "schema": SERVE_GATE_SCHEMA,
        "workspace_id": workspace_id,
        "state": state,
        "stable_floor_generation": stable_floor_generation,
        "stable_checkpoint_id": stable_checkpoint_id,
        "source_candidate_digest": source_candidate_digest,
        "reason": reason,
        "updated_at": updated_at,
    }


def serve_gate_allows_serving(gate: Mapping | None) -> bool:
    """Missing/malformed/non-CLEAR state always means no-serve."""
    if gate is None:
        return False
    return gate.get("state") == "CLEAR" and gate.get("reason") == "NONE"
