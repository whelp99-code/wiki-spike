"""DB-01 V2 authorization behavior, revocation, audit, and zero-write proofs."""
from __future__ import annotations

import pytest

from wiki_spike.infrastructure.identity_auth_v2_store import (
    IdentityAuthorizationStoreV2,
)
from wiki_spike.memory_core.identity_auth_v2_conformance import (
    FIXTURE_LATER,
    fixture_context,
    fixture_device_revocation,
    fixture_enrollment,
    fixture_grant,
    fixture_grant_revocation,
    fixture_ref,
    fixture_request,
    fixture_root,
)
from wiki_spike.memory_core.identity_auth_v2_errors import IdentityAuthorizationDenied
from wiki_spike.memory_core.identity_auth_v2_policy import IdentityAuthorizationPolicyV2
from wiki_spike.memory_core.identity_auth_v2_state import IdentityAuditFactoryV2
from wiki_spike.memory_core.operability import AuditCapacityExceeded, ReferenceHasher


def _policy(
    max_audits: int = 16,
    *,
    now: str = "2030-01-01T00:00:00Z",
) -> tuple[IdentityAuthorizationStoreV2, IdentityAuthorizationPolicyV2]:
    store = IdentityAuthorizationStoreV2(max_audit_records=max_audits)
    audit = IdentityAuditFactoryV2(
        ReferenceHasher(b"audit-reference-key-material"),
        policy_version="identity-auth-v2",
    )
    return store, IdentityAuthorizationPolicyV2(store, audit, now=lambda: now)


def _bootstrap_owner(
    store: IdentityAuthorizationStoreV2,
    policy: IdentityAuthorizationPolicyV2,
) -> None:
    policy.enroll(fixture_context(), fixture_root(), fixture_enrollment())
    assert len(store.audit_records()) == 1


def test_owner_enrollment_is_audited_and_nonowner_denial_is_zero_write() -> None:
    store, policy = _policy()
    root = fixture_root()
    before = store.authority_state_digest(root.workspace_ref, root.profile_ref)
    with pytest.raises(IdentityAuthorizationDenied):
        policy.enroll(
            fixture_context(actor=fixture_ref("key", "8")),
            root,
            fixture_enrollment(),
        )
    assert store.authority_state_digest(root.workspace_ref, root.profile_ref) == before
    assert not store.audit_records()

    policy.enroll(fixture_context(), root, fixture_enrollment())

    assert store.authority_state_digest(root.workspace_ref, root.profile_ref) != before
    assert store.audit_records()[0].action == "identity.device.enroll"


def test_expired_first_device_enrollment_is_zero_write() -> None:
    store, policy = _policy(now="2030-03-01T00:00:00Z")
    root = fixture_root()
    before = store.authority_state_digest(root.workspace_ref, root.profile_ref)
    with pytest.raises(IdentityAuthorizationDenied, match="expired"):
        policy.enroll(fixture_context(), root, fixture_enrollment())
    assert store.authority_state_digest(root.workspace_ref, root.profile_ref) == before
    assert not store.audit_records()


def test_wrong_workspace_valid_digest_and_ungranted_action_deny_zero_write() -> None:
    store, policy = _policy()
    _bootstrap_owner(store, policy)
    reviewer = fixture_ref("key", "8")
    reviewer_device = fixture_ref("device", "9")
    policy.enroll(
        fixture_context(),
        fixture_root(),
        fixture_enrollment(subject=reviewer, device=reviewer_device),
    )
    root = fixture_root()
    before = store.authority_state_digest(root.workspace_ref, root.profile_ref)
    with pytest.raises(IdentityAuthorizationDenied, match="workspace"):
        _ = policy.issue(
            fixture_context(actor=reviewer, device=reviewer_device),
            fixture_request(workspace=fixture_ref("workspace", "f")),
            expires_at=FIXTURE_LATER,
        )
    with pytest.raises(IdentityAuthorizationDenied, match="delegation"):
        _ = policy.issue(
            fixture_context(actor=reviewer, device=reviewer_device),
            fixture_request(),
            expires_at=FIXTURE_LATER,
        )
    assert store.authority_state_digest(root.workspace_ref, root.profile_ref) == before


def test_delegated_action_one_shot_then_revocation_denies_without_callback() -> None:
    store, policy = _policy()
    _bootstrap_owner(store, policy)
    reviewer = fixture_ref("key", "8")
    reviewer_device = fixture_ref("device", "9")
    policy.enroll(
        fixture_context(),
        fixture_root(),
        fixture_enrollment(subject=reviewer, device=reviewer_device),
    )
    policy.delegate(fixture_context(), fixture_grant())
    context = fixture_context(actor=reviewer, device=reviewer_device)
    grant = policy.issue(context, fixture_request(), expires_at=FIXTURE_LATER)
    calls: list[str] = []
    assert policy.consume(
        context,
        grant.capability_ref,
        "review.approve",
        lambda: calls.append("ok"),
    ) is None
    with pytest.raises(IdentityAuthorizationDenied):
        policy.consume(
            context,
            grant.capability_ref,
            "review.approve",
            lambda: calls.append("bad"),
        )
    assert calls == ["ok"]

    second = policy.issue(
        context,
        fixture_request(capability_digit="e"),
        expires_at=FIXTURE_LATER,
    )
    policy.revoke_delegation(fixture_context(), fixture_grant_revocation())
    with pytest.raises(IdentityAuthorizationDenied, match="revoked"):
        policy.consume(
            context,
            second.capability_ref,
            "review.approve",
            lambda: calls.append("bad"),
        )
    assert calls == ["ok"]


def test_device_revoke_and_audit_capacity_fail_closed() -> None:
    store, policy = _policy(max_audits=1)
    _bootstrap_owner(store, policy)
    root = fixture_root()
    before = store.authority_state_digest(root.workspace_ref, root.profile_ref)
    with pytest.raises(AuditCapacityExceeded, match="bounded audit store is full"):
        policy.revoke_device(fixture_context(), fixture_device_revocation())
    assert store.authority_state_digest(root.workspace_ref, root.profile_ref) == before


def test_revoked_device_denies_preexisting_capability_without_callback() -> None:
    store, policy = _policy()
    _bootstrap_owner(store, policy)
    owner = fixture_ref("key", "4")
    owner_device = fixture_ref("device", "6")
    context = fixture_context()
    capability = policy.issue(
        context,
        fixture_request(
            actor=owner,
            device=owner_device,
            capability_digit="f",
        ),
        expires_at=FIXTURE_LATER,
    )
    policy.revoke_device(context, fixture_device_revocation())
    calls: list[str] = []

    with pytest.raises(IdentityAuthorizationDenied, match="revoked"):
        policy.consume(
            context,
            capability.capability_ref,
            "review.approve",
            lambda: calls.append("bad"),
        )

    assert calls == []
