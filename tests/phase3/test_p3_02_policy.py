from __future__ import annotations

import pytest

from wiki_spike.memory_core import (
    CapabilityToken,
    PolicyEngine,
    PolicyReason,
    PolicyRequest,
    ProvenanceMode,
    Sensitivity,
    derived_sensitivity,
)


def token(**overrides):
    value = {
        "token_id": "tok-1",
        "workspace_id": "ws-1",
        "actor_id": "user-1",
        "actions": frozenset({"memory.read", "memory.write", "provenance.attest", "sensitivity.declassify"}),
        "max_sensitivity": Sensitivity.PRIVATE,
        "expires_at": "2026-07-23T00:00:00Z",
    }
    value.update(overrides)
    return CapabilityToken(**value)


def request(**overrides):
    value = {
        "workspace_id": "ws-1",
        "actor_id": "user-1",
        "action": "memory.read",
        "now": "2026-07-22T00:00:00Z",
        "object_sensitivity": Sensitivity.INTERNAL,
    }
    value.update(overrides)
    return PolicyRequest(**value)


def test_cross_workspace_token_is_denied_without_disclosure():
    decision = PolicyEngine().authorize(token(), request(workspace_id="ws-2"))
    assert decision.allowed is False
    assert decision.reason is PolicyReason.WORKSPACE_MISMATCH


def test_missing_capability_denies_privilege_escalation():
    decision = PolicyEngine().authorize(token(actions=frozenset({"memory.read"})), request(action="memory.write"))
    assert decision == decision.__class__(False, PolicyReason.CAPABILITY_MISSING)


def test_expired_token_is_denied():
    decision = PolicyEngine().authorize(token(expires_at="2026-07-22T00:00:00Z"), request())
    assert decision.reason is PolicyReason.CAPABILITY_EXPIRED


def test_sensitivity_above_clearance_is_denied():
    decision = PolicyEngine().authorize(token(max_sensitivity=Sensitivity.INTERNAL), request(object_sensitivity=Sensitivity.PRIVATE))
    assert decision.reason is PolicyReason.SENSITIVITY_EXCEEDED


@pytest.mark.parametrize("source", [
    ProvenanceMode.SYSTEM_INFERRED,
    ProvenanceMode.SELF_AUTHORED,
    ProvenanceMode.IMPORTED_UNVERIFIED,
])
def test_provenance_cannot_be_promoted_to_evidence_backed_without_attestation(source):
    decision = PolicyEngine().authorize_provenance_transition(
        token(actions=frozenset({"memory.write"})),
        request(action="memory.write"),
        source,
        ProvenanceMode.EVIDENCE_BACKED,
        evidence_refs=("evidence-1",),
    )
    assert decision.reason is PolicyReason.PROVENANCE_PROMOTION_DENIED


def test_attestation_requires_nonempty_evidence_refs():
    decision = PolicyEngine().authorize_provenance_transition(
        token(),
        request(action="provenance.attest"),
        ProvenanceMode.SYSTEM_INFERRED,
        ProvenanceMode.EVIDENCE_BACKED,
        evidence_refs=(),
    )
    assert decision.reason is PolicyReason.PROVENANCE_PROMOTION_DENIED


def test_explicit_attestation_with_evidence_is_allowed():
    decision = PolicyEngine().authorize_provenance_transition(
        token(),
        request(action="provenance.attest"),
        ProvenanceMode.IMPORTED_UNVERIFIED,
        ProvenanceMode.EVIDENCE_BACKED,
        evidence_refs=("evidence-1",),
    )
    assert decision.allowed is True


def test_derived_sensitivity_is_monotonic_maximum():
    assert derived_sensitivity([Sensitivity.PUBLIC, Sensitivity.SECRET, Sensitivity.INTERNAL]) is Sensitivity.SECRET
    assert derived_sensitivity([]) is Sensitivity.PUBLIC


def test_declassification_requires_capability_and_reason():
    engine = PolicyEngine()
    denied_action = engine.authorize_declassification(
        token(actions=frozenset({"memory.write"})),
        request(action="memory.write", object_sensitivity=Sensitivity.SECRET),
        Sensitivity.SECRET,
        Sensitivity.INTERNAL,
        "approved",
    )
    assert denied_action.reason is PolicyReason.CAPABILITY_MISSING

    denied_reason = engine.authorize_declassification(
        token(max_sensitivity=Sensitivity.SECRET),
        request(action="sensitivity.declassify", object_sensitivity=Sensitivity.SECRET),
        Sensitivity.SECRET,
        Sensitivity.INTERNAL,
        "   ",
    )
    assert denied_reason.reason is PolicyReason.DECLASSIFICATION_DENIED


def test_explicit_declassification_with_clearance_is_allowed():
    decision = PolicyEngine().authorize_declassification(
        token(max_sensitivity=Sensitivity.SECRET),
        request(action="sensitivity.declassify", object_sensitivity=Sensitivity.SECRET),
        Sensitivity.SECRET,
        Sensitivity.PRIVATE,
        "owner-approved",
    )
    assert decision.allowed is True
