from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest
from test_decision_contracts import TRUSTED, aggregate, expected, records, scope
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1

from wiki_spike.infrastructure.capability_store import CapabilityStore
from wiki_spike.memory_core.operability import RetryBudget
from wiki_spike.memory_core.second_brain_capabilities import (
    CapabilityDenied,
    CapabilityService,
    DelegationService,
    DeviceTrustService,
    _digest,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    CapabilityRequestV1, DelegatedReviewGrantV1, DeviceEnrollmentV1, TrustRootV1,
    SecurityContextAuthority, mint_security_context_authority,
)

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
def ref(kind: str, digit: str) -> str: return f"{kind}:{digit * 64}"
def digest(digit: str) -> str: return digit * 64
CREDENTIAL_REF = ref("credential", "a")
CREDENTIAL_ACTION = "source.read"
def authority():
    items = records()
    envelope = aggregate(items)
    return mint_security_context_authority(
        items, ResolvedScopeV1.from_mapping(scope()), expected(), envelope, TRUSTED
    )
def test_authority_rejects_unresolved_and_direct_forgery():
    with pytest.raises(Exception):
        mint_security_context_authority(None, None, None, None, None)  # type: ignore[arg-type]
    with pytest.raises(Exception):
        SecurityContextAuthority(object(), (), None, None, None, None)  # type: ignore[arg-type]
def test_authority_minted_before_expiry_denies_use_after_expiry():
    minted = authority()
    assert minted.require(now=datetime(2029, 1, 1, tzinfo=timezone.utc)).outcome == "RESOLVED"
    with pytest.raises(Exception):
        minted.require(now=datetime(2031, 1, 1, tzinfo=timezone.utc))


def root() -> TrustRootV1:
    return TrustRootV1.from_mapping({"security_version": "second-brain-security-foundation-v1", "trust_root_ref": ref("root", "1"), "root_revision": "1", "owner_key_ref": ref("key", "c"), "approver_key_ref": ref("key", "3"), "root_digest": digest("4")})

def device(root_ref: str, key: str = "5") -> DeviceEnrollmentV1:
    return DeviceEnrollmentV1.from_mapping({"security_version": "second-brain-security-foundation-v1", "enrollment_ref": ref("enrollment", key), "device_key_ref": ref("device", key), "trust_root_ref": root_ref, "enrolled_at": "2029-01-01T00:00:00Z", "expires_at": "2031-01-01T00:00:00Z", "enrollment_digest": digest("6")})

def request() -> CapabilityRequestV1:
    return CapabilityRequestV1.from_mapping(json.loads((Path(__file__).parents[1] / "fixtures/second_brain/security/capability-v1.json").read_text()))

def issued(*, actor: str | None = None, actions: tuple[str, ...] | None = None, credential_refs: tuple[str, ...] = (CREDENTIAL_REF,), credential_actions: tuple[str, ...] = (CREDENTIAL_ACTION,), budget: RetryBudget | None = None):
    store, trust = CapabilityStore(), root()
    DeviceTrustService(store, now=lambda: NOW).enroll(authority(), trust.owner_key_ref, trust, device(trust.trust_root_ref))
    req = request()
    actor = actor or trust.owner_key_ref
    actions = actions or req.scope_refs
    service = CapabilityService(store, retry_budget=budget, now=lambda: NOW)
    scope = _digest({"workspace_ref": ref("workspace", "7"), "actions": list(actions), "credential_refs": list(credential_refs), "credential_actions": list(credential_actions), "scope_refs": list(req.scope_refs)})
    grant = service.issue(authority(), req, trust_root_ref=trust.trust_root_ref, device_key_ref=ref("device", "5"), workspace_ref=ref("workspace", "7"), actor_key_ref=actor, actions=actions, credential_refs=credential_refs, credential_actions=credential_actions, scope_digest=scope, expires_at="2030-02-01T00:00:00Z", nonce="nonce")
    return store, trust, req, service, grant


def test_fixture_is_valid_request():
    assert request().capability_ref == ref("capability", "b")


@pytest.mark.parametrize("field,value", [("trust_root_ref", ref("root", "8")), ("device_key_ref", ref("device", "8")), ("workspace_ref", ref("workspace", "8"))])
def test_altered_binding_is_denied_before_invocation(field, value):
    store, trust, req, service, _ = issued()
    kwargs = dict(trust_root_ref=trust.trust_root_ref, device_key_ref=ref("device", "5"), workspace_ref=ref("workspace", "7"), actor_key_ref=trust.owner_key_ref, actions=req.scope_refs, credential_refs=(CREDENTIAL_REF,), credential_actions=(CREDENTIAL_ACTION,), scope_digest="0" * 64, expires_at="2030-02-01T00:00:00Z", nonce="n")
    kwargs[field] = value
    invoked = []
    with pytest.raises(CapabilityDenied): service.issue_and_consume(authority(), req, invoke=lambda: invoked.append(True), **kwargs)
    assert invoked == []


def test_unknown_device_expiry_revocation_and_nonce_replay_are_denied():
    store, trust, req, service, grant = issued()
    with pytest.raises(CapabilityDenied):
        service.issue(authority(), req, trust_root_ref=trust.trust_root_ref, device_key_ref=ref("device", "9"), workspace_ref=ref("workspace", "7"), actor_key_ref=trust.owner_key_ref, actions=req.scope_refs, credential_refs=(CREDENTIAL_REF,), credential_actions=(CREDENTIAL_ACTION,), scope_digest="0" * 64, expires_at="2030-02-01T00:00:00Z", nonce="n")
    assert service.consume(authority(), grant.capability_ref, req.request_digest, "nonce", lambda: "ok") == "ok"
    with pytest.raises(CapabilityDenied): service.consume(authority(), grant.capability_ref, req.request_digest, "nonce", lambda: pytest.fail("replayed"))
    store2, trust2, req2, service2, grant2 = issued()
    DeviceTrustService(store2, now=lambda: NOW).revoke(authority(), trust2.owner_key_ref, trust2.trust_root_ref, ref("device", "5"))
    with pytest.raises(CapabilityDenied):
        service2.consume(authority(), grant2.capability_ref, req2.request_digest, "nonce", lambda: pytest.fail("revoked"))


def test_delegate_cannot_transfer_redelegate_or_escalate_actions():
    store, trust, req, service, _ = issued()
    reviewer = ref("key", "8")
    grant = DelegatedReviewGrantV1.from_mapping({"security_version": "second-brain-security-foundation-v1", "grant_ref": ref("grant", "9"), "grant_revision": "1", "grantor_key_ref": trust.owner_key_ref, "reviewer_key_ref": reviewer, "scope_refs": list(req.scope_refs), "expires_at": "2030-02-01T00:00:00Z", "grant_digest": digest("a")})
    DelegationService(store, now=lambda: NOW).delegate(authority(), trust.owner_key_ref, trust.trust_root_ref, grant)
    with pytest.raises(CapabilityDenied): DelegationService(store, now=lambda: NOW).delegate(authority(), reviewer, trust.trust_root_ref, grant)
    with pytest.raises(CapabilityDenied):
        escalated = (ref("scope", "0"), *req.scope_refs)
        reviewer_request = replace(req, subject_key_ref=reviewer, capability_ref=ref("capability", "f"), request_digest=digest("f"))
        scope = _digest({"workspace_ref": ref("workspace", "7"), "actions": list(escalated), "credential_refs": [CREDENTIAL_REF], "credential_actions": [CREDENTIAL_ACTION], "scope_refs": list(reviewer_request.scope_refs)})
        service.issue(authority(), reviewer_request, trust_root_ref=trust.trust_root_ref, device_key_ref=ref("device", "5"), workspace_ref=ref("workspace", "7"), actor_key_ref=reviewer, actions=escalated, credential_refs=(CREDENTIAL_REF,), credential_actions=(CREDENTIAL_ACTION,), scope_digest=scope, expires_at="2030-02-01T00:00:00Z", nonce="n")


def test_quota_and_concurrent_compare_consume_allow_at_most_one_invocation():
    budget = RetryBudget(max_operations=1, max_attempts=1, max_total_cost_units=1)
    _, _, req, service, grant = issued(budget=budget)
    calls: list[int] = []
    def consume() -> bool:
        try:
            service.consume(authority(), grant.capability_ref, req.request_digest, "nonce", lambda: calls.append(1))
            return True
        except CapabilityDenied:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _: consume(), range(8))) == 1
    assert calls == [1]
