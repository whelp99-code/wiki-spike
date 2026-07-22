"""Fail-closed Phase 3 capability, provenance, and sensitivity policy."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"
    SECRET_DATA = "secret"
    SECRET = SECRET_DATA

    @property
    def rank(self) -> int:
        return {
            Sensitivity.PUBLIC: 0,
            Sensitivity.INTERNAL: 1,
            Sensitivity.PRIVATE: 2,
            Sensitivity.SECRET_DATA: 3,
        }[self]


class ProvenanceMode(str, Enum):
    EVIDENCE_BACKED = "evidence_backed"
    SELF_AUTHORED = "self_authored"
    SYSTEM_INFERRED = "system_inferred"
    IMPORTED_UNVERIFIED = "imported_unverified"


class PolicyReason(str, Enum):
    ALLOW = "allow"
    WORKSPACE_MISMATCH = "workspace_mismatch"
    CAPABILITY_MISSING = "capability_missing"
    CAPABILITY_EXPIRED = "capability_expired"
    SENSITIVITY_EXCEEDED = "sensitivity_exceeded"
    PROVENANCE_PROMOTION_DENIED = "provenance_promotion_denied"
    DECLASSIFICATION_DENIED = "declassification_denied"
    INVALID_REQUEST = "invalid_request"


@dataclass(frozen=True)
class CapabilityToken:
    token_id: str
    workspace_id: str
    actor_id: str
    actions: frozenset[str]
    max_sensitivity: Sensitivity
    expires_at: str


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: PolicyReason


@dataclass(frozen=True)
class PolicyRequest:
    workspace_id: str
    actor_id: str
    action: str
    now: str
    object_sensitivity: Sensitivity = Sensitivity.PUBLIC


class PolicyEngine:
    def authorize(self, token: CapabilityToken, request: PolicyRequest) -> PolicyDecision:
        if token.workspace_id != request.workspace_id or token.actor_id != request.actor_id:
            return PolicyDecision(False, PolicyReason.WORKSPACE_MISMATCH)
        if request.now >= token.expires_at:
            return PolicyDecision(False, PolicyReason.CAPABILITY_EXPIRED)
        if request.action not in token.actions:
            return PolicyDecision(False, PolicyReason.CAPABILITY_MISSING)
        if request.object_sensitivity.rank > token.max_sensitivity.rank:
            return PolicyDecision(False, PolicyReason.SENSITIVITY_EXCEEDED)
        return PolicyDecision(True, PolicyReason.ALLOW)

    def authorize_provenance_transition(
        self,
        token: CapabilityToken,
        request: PolicyRequest,
        source: ProvenanceMode,
        target: ProvenanceMode,
        evidence_refs: Iterable[str] = (),
    ) -> PolicyDecision:
        base = self.authorize(token, request)
        if not base.allowed:
            return base
        if source == target:
            return PolicyDecision(True, PolicyReason.ALLOW)
        if target is ProvenanceMode.EVIDENCE_BACKED:
            refs = tuple(ref for ref in evidence_refs if ref)
            if request.action != "provenance.attest" or not refs:
                return PolicyDecision(False, PolicyReason.PROVENANCE_PROMOTION_DENIED)
        return PolicyDecision(True, PolicyReason.ALLOW)

    def authorize_declassification(
        self,
        token: CapabilityToken,
        request: PolicyRequest,
        source: Sensitivity,
        target: Sensitivity,
        reason: str,
    ) -> PolicyDecision:
        base = self.authorize(token, request)
        if not base.allowed:
            return base
        if target.rank >= source.rank:
            return PolicyDecision(True, PolicyReason.ALLOW)
        if request.action != "sensitivity.declassify" or not reason.strip():
            return PolicyDecision(False, PolicyReason.DECLASSIFICATION_DENIED)
        return PolicyDecision(True, PolicyReason.ALLOW)


def derived_sensitivity(inputs: Iterable[Sensitivity]) -> Sensitivity:
    values = tuple(inputs)
    if not values:
        return Sensitivity.PUBLIC
    return max(values, key=lambda item: item.rank)
