"""Revocation and expiry denials for fixture-only DB-01 evidence."""
from __future__ import annotations

from wiki_spike.applications.identity_auth_v2_evidence_support import (
    REVIEWER,
    REVIEWER_DEVICE,
    bootstrap,
    denied,
    digest,
    enroll_reviewer,
    policy,
    record,
)
from wiki_spike.infrastructure.identity_auth_v2_store import (
    IdentityAuthorizationStoreV2,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.identity_auth_v2_conformance import (
    FIXTURE_LATER,
    fixture_context,
    fixture_device_revocation,
    fixture_grant,
    fixture_grant_revocation,
    fixture_ref,
    fixture_request,
)
from wiki_spike.memory_core.identity_auth_v2_policy import IdentityAuthorizationPolicyV2
from wiki_spike.memory_core.identity_auth_v2_state import IdentityAuditFactoryV2
from wiki_spike.memory_core.operability import ReferenceHasher


def expired_delegation_denied() -> dict[str, JsonValue]:
    clock = ["2030-01-01T00:00:00Z"]
    store = IdentityAuthorizationStoreV2(max_audit_records=16)
    audit = IdentityAuditFactoryV2(
        ReferenceHasher(b"audit-reference-key-material"),
        policy_version="identity-auth-v2",
    )
    current = IdentityAuthorizationPolicyV2(store, audit, now=lambda: clock[0])
    bootstrap(store, current)
    enroll_reviewer(current)
    current.delegate(fixture_context(), fixture_grant(expires_at="2030-01-01T00:00:01Z"))
    clock[0] = "2030-01-01T00:00:02Z"
    before = digest(store)

    def _run() -> object:
        return current.issue(
            fixture_context(actor=REVIEWER, device=REVIEWER_DEVICE),
            fixture_request(),
            expires_at=FIXTURE_LATER,
        )

    denied(_run)
    return record(
        "expired_delegation_denied_zero_write",
        "rejected",
        before,
        digest(store),
        "0",
        None,
    )


def revoked_delegation_denied() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    enroll_reviewer(current)
    current.delegate(fixture_context(), fixture_grant())
    current.revoke_delegation(fixture_context(), fixture_grant_revocation())
    before = digest(store)

    def _run() -> object:
        return current.issue(
            fixture_context(actor=REVIEWER, device=REVIEWER_DEVICE),
            fixture_request(),
            expires_at=FIXTURE_LATER,
        )

    denied(_run)
    return record(
        "revoked_delegation_denied_zero_write",
        "rejected",
        before,
        digest(store),
        "0",
        None,
    )


def revoked_device_denied() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    owner = fixture_ref("key", "4")
    owner_device = fixture_ref("device", "6")
    context = fixture_context()
    capability = current.issue(
        context,
        fixture_request(actor=owner, device=owner_device, capability_digit="f"),
        expires_at=FIXTURE_LATER,
    )
    current.revoke_device(context, fixture_device_revocation())
    before = digest(store)
    writes: list[str] = []

    def _run() -> object:
        return current.consume(
            context,
            capability.capability_ref,
            "review.approve",
            lambda: writes.append("bad"),
        )

    denied(_run)
    return record(
        "revoked_device_denied_zero_write",
        "rejected",
        before,
        digest(store),
        str(len(writes)),
        None,
    )


def audit_failure_rolls_back() -> dict[str, JsonValue]:
    store, current = policy(max_audits=1)
    bootstrap(store, current)
    before = digest(store)

    def _run() -> None:
        current.revoke_device(fixture_context(), fixture_device_revocation())

    denied(_run)
    return record(
        "audit_failure_rolls_back_transition",
        "rejected",
        before,
        digest(store),
        "0",
        None,
    )
