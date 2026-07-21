"""Data models (v3.3 §4).

Highlights of the corrections baked in:
- ClaimIdentity.claim_id INCLUDES polarity, so "A supports X (positive)" and
  "A supports X (negative)" get different ids (Codex round 4 fix).
- ResolutionDecision has NO generation_id -> accepted_claim_set_root is acyclic
  (Codex round 5 fix N1).
- SourceManifest is a strict state machine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .hashing import canonical_hash, merkle_root
from .canonical import canonical_bytes

IDENTITY_SCHEMA_VERSION = "1"


# --------------------------------------------------------------------------- #
# Source manifest state machine
# --------------------------------------------------------------------------- #
_LEGAL_TRANSITIONS: dict[str, set[str]] = {
    "received": {"staged", "quarantined"},
    "staged": {"validated", "quarantined"},
    "validated": {"accepted", "quarantined"},
    "accepted": {"revoked"},
    "quarantined": set(),
    "revoked": set(),
}


class StateError(RuntimeError):
    pass


@dataclass
class SourceManifest:
    source_id: str
    content_hash: str
    license: str = "unspecified"
    duplicate_cluster_id: str | None = None
    status: str = "received"
    # temporal_provenance kept as canonical strings (no raw numbers)
    temporal_provenance: dict[str, str] = field(default_factory=dict)
    lineage: list[str] = field(default_factory=list)

    def transition(self, to: str) -> None:
        allowed = _LEGAL_TRANSITIONS.get(self.status, set())
        if to not in allowed:
            raise StateError(
                f"illegal transition {self.status!r} -> {to!r}; allowed: {sorted(allowed)}"
            )
        self.status = to


# --------------------------------------------------------------------------- #
# Claim IR
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source_object_hash: str
    representation_hash: str
    quote_hash: str
    locators: tuple[dict[str, str], ...]  # each locator uses canonical string fields


def compute_claim_id(
    subject_id: str,
    predicate_id: str,
    obj: str,
    polarity: str,
    scope: dict[str, str],
) -> str:
    if polarity not in ("positive", "negative"):
        raise ValueError("polarity must be 'positive' or 'negative'")
    payload: dict[str, Any] = {
        "identity_schema_version": IDENTITY_SCHEMA_VERSION,
        "canonical_subject_id": subject_id,
        "predicate_id": predicate_id,
        "canonical_object": obj,
        "polarity": polarity,
        "normalized_scope": scope,
    }
    return canonical_hash(payload)


@dataclass(frozen=True)
class ClaimIdentity:
    claim_id: str
    subject_id: str
    predicate_id: str
    obj: str
    polarity: str
    scope: dict[str, str]

    @staticmethod
    def create(
        subject_id: str, predicate_id: str, obj: str, polarity: str, scope: dict[str, str]
    ) -> "ClaimIdentity":
        cid = compute_claim_id(subject_id, predicate_id, obj, polarity, scope)
        return ClaimIdentity(cid, subject_id, predicate_id, obj, polarity, dict(scope))


@dataclass(frozen=True)
class ClaimAssertion:
    assertion_id: str
    claim_id: str
    source_id: str
    evidence_ids: tuple[str, ...]
    modality: str  # asserted | likely | possible


@dataclass(frozen=True)
class ResolutionDecision:
    """generation-id-free decision record -> feeds accepted_claim_set_root."""

    claim_id: str
    state: str  # accepted | competing | superseded | retracted | unresolved
    assertion_ids: tuple[str, ...]
    policy_version: str
    rationale_code: str

    def canonical(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "state": self.state,
            "assertion_ids": list(self.assertion_ids),
            "policy_version": self.policy_version,
            "rationale_code": self.rationale_code,
        }


def accepted_claim_set_root(decisions: list[ResolutionDecision]) -> str:
    """Order-independent Merkle root over generation-id-free decisions (acyclic)."""
    leaves = [canonical_bytes(d.canonical()) for d in decisions]
    return merkle_root(leaves)
