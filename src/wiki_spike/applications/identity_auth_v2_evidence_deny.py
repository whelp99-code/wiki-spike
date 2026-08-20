"""Denied DB-01 V2 authorization cases for fixture-only evidence."""
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
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.identity_auth_v2_conformance import (
    FIXTURE_LATER,
    fixture_context,
    fixture_device_revocation,
    fixture_enrollment,
    fixture_grant,
    fixture_ref,
    fixture_request,
    fixture_root,
)
from wiki_spike.memory_core.identity_auth_v2_delegation import DelegatedReviewGrantV2


def nonowner_enroll_denied() -> dict[str, JsonValue]:
    store, current = policy()
    before = digest(store)

    def _run() -> None:
        current.enroll(
            fixture_context(actor=REVIEWER),
            fixture_root(),
            fixture_enrollment(),
        )

    denied(_run)
    return record(
        "nonowner_enroll_denied_zero_write",
        "rejected",
        before,
        digest(store),
        "0",
        None,
    )


def nonowner_device_revoke_denied() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    before = digest(store)

    def _run() -> None:
        current.revoke_device(
            fixture_context(actor=REVIEWER, device=REVIEWER_DEVICE),
            fixture_device_revocation(),
        )

    denied(_run)
    return record(
        "nonowner_device_revoke_denied_zero_write",
        "rejected",
        before,
        digest(store),
        "0",
        None,
    )


def wrong_workspace_denied() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    enroll_reviewer(current)
    before = digest(store)

    def _run() -> object:
        return current.issue(
            fixture_context(actor=REVIEWER, device=REVIEWER_DEVICE),
            fixture_request(workspace=fixture_ref("workspace", "f")),
            expires_at=FIXTURE_LATER,
        )

    denied(_run)
    return record(
        "wrong_workspace_denied_zero_write",
        "rejected",
        before,
        digest(store),
        "0",
        None,
    )


def ungranted_action_denied() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    enroll_reviewer(current)
    before = digest(store)

    def _run() -> object:
        return current.issue(
            fixture_context(actor=REVIEWER, device=REVIEWER_DEVICE),
            fixture_request(),
            expires_at=FIXTURE_LATER,
        )

    denied(_run)
    return record(
        "ungranted_action_denied_zero_write",
        "rejected",
        before,
        digest(store),
        "0",
        None,
    )


def ownership_transfer_denied() -> dict[str, JsonValue]:
    store, _current = policy()
    del _current
    before = digest(store)
    body = dict(fixture_grant().to_mapping())
    body["actions"] = ["workspace.owner.transfer"]

    def _run() -> object:
        return DelegatedReviewGrantV2.from_mapping(body)

    denied(_run)
    return record(
        "ownership_transfer_denied_zero_write",
        "rejected",
        before,
        digest(store),
        "0",
        None,
    )


def redelegation_denied() -> dict[str, JsonValue]:
    store, current = policy()
    bootstrap(store, current)
    enroll_reviewer(current)
    current.delegate(fixture_context(), fixture_grant())
    before = digest(store)

    def _run() -> None:
        current.delegate(
            fixture_context(actor=REVIEWER, device=REVIEWER_DEVICE),
            fixture_grant(),
        )

    denied(_run)
    return record(
        "redelegation_denied_zero_write",
        "rejected",
        before,
        digest(store),
        "0",
        None,
    )
