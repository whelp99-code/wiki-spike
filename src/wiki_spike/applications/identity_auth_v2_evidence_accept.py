"""Accepted DB-01 V2 authorization cases for fixture-only evidence."""
from __future__ import annotations

from wiki_spike.applications.identity_auth_v2_evidence_support import (
    REVIEWER,
    REVIEWER_DEVICE,
    bootstrap,
    digest,
    enroll_reviewer,
    policy,
    record,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.identity_auth_v2_conformance import (
    FIXTURE_LATER,
    fixture_context,
    fixture_device_revocation,
    fixture_enrollment,
    fixture_grant,
    fixture_grant_revocation,
    fixture_request,
    fixture_root,
)


def owner_enroll_allowed() -> dict[str, JsonValue]:
    store, current = policy()
    before = digest(store)
    current.enroll(fixture_context(), fixture_root(), fixture_enrollment())
    return record(
        "owner_enroll_allowed",
        "accepted",
        before,
        digest(store),
        "0",
        store.audit_records()[-1].audit_id,
    )


def owner_device_revoke_allowed() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    before = digest(store)
    current.revoke_device(fixture_context(), fixture_device_revocation())
    return record(
        "owner_device_revoke_allowed",
        "accepted",
        before,
        digest(store),
        "0",
        store.audit_records()[-1].audit_id,
    )


def delegation_grant_audited() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    enroll_reviewer(current)
    before = digest(store)
    current.delegate(fixture_context(), fixture_grant())
    return record(
        "delegation_grant_audited",
        "accepted",
        before,
        digest(store),
        "0",
        store.audit_records()[-1].audit_id,
    )


def delegated_action_allowed() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    enroll_reviewer(current)
    current.delegate(fixture_context(), fixture_grant())
    context = fixture_context(actor=REVIEWER, device=REVIEWER_DEVICE)
    grant = current.issue(context, fixture_request(), expires_at=FIXTURE_LATER)
    before = digest(store)
    writes: list[str] = []
    current.consume(
        context,
        grant.capability_ref,
        "review.approve",
        lambda: writes.append("ok"),
    )
    return record(
        "delegated_action_allowed_one_write",
        "accepted",
        before,
        digest(store),
        str(len(writes)),
        None,
    )


def delegation_revoke_audited() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    enroll_reviewer(current)
    current.delegate(fixture_context(), fixture_grant())
    before = digest(store)
    current.revoke_delegation(fixture_context(), fixture_grant_revocation())
    return record(
        "delegation_revoke_audited",
        "accepted",
        before,
        digest(store),
        "0",
        store.audit_records()[-1].audit_id,
    )
