"""Shared fixture runners for DB-01 V2 evidence cases."""
from __future__ import annotations

from collections.abc import Callable

from wiki_spike.infrastructure.identity_auth_v2_store import (
    IdentityAuthorizationStoreV2,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.identity_auth_v2_conformance import (
    fixture_context,
    fixture_enrollment,
    fixture_ref,
    fixture_root,
)
from wiki_spike.memory_core.identity_auth_v2_errors import IdentityAuthorizationDenied
from wiki_spike.memory_core.identity_auth_v2_policy import IdentityAuthorizationPolicyV2
from wiki_spike.memory_core.identity_auth_v2_state import IdentityAuditFactoryV2
from wiki_spike.memory_core.operability import AuditCapacityExceeded, ReferenceHasher

REQUIRED_CASE_IDS: tuple[str, ...] = (
    "owner_enroll_allowed",
    "nonowner_enroll_denied_zero_write",
    "owner_device_revoke_allowed",
    "nonowner_device_revoke_denied_zero_write",
    "delegation_grant_audited",
    "delegated_action_allowed_one_write",
    "wrong_workspace_denied_zero_write",
    "ungranted_action_denied_zero_write",
    "ownership_transfer_denied_zero_write",
    "redelegation_denied_zero_write",
    "expired_delegation_denied_zero_write",
    "delegation_revoke_audited",
    "revoked_delegation_denied_zero_write",
    "revoked_device_denied_zero_write",
    "audit_failure_rolls_back_transition",
)

REVIEWER = fixture_ref("key", "8")
REVIEWER_DEVICE = fixture_ref("device", "9")


def policy(
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


def digest(store: IdentityAuthorizationStoreV2) -> str:
    root = fixture_root()
    return store.authority_state_digest(root.workspace_ref, root.profile_ref)


def record(
    case_id: str,
    expected: str,
    before: str,
    after: str,
    writes: str,
    audit_id: str | None,
) -> dict[str, JsonValue]:
    return {
        "after_authority_digest": after,
        "audit_id": audit_id,
        "before_authority_digest": before,
        "case_id": case_id,
        "downstream_write_count": writes,
        "expected_outcome": expected,
        "observed_outcome": expected,
    }


def bootstrap(
    store: IdentityAuthorizationStoreV2,
    current: IdentityAuthorizationPolicyV2,
) -> None:
    current.enroll(fixture_context(), fixture_root(), fixture_enrollment())
    _ = store


def enroll_reviewer(current: IdentityAuthorizationPolicyV2) -> None:
    current.enroll(
        fixture_context(),
        fixture_root(),
        fixture_enrollment(subject=REVIEWER, device=REVIEWER_DEVICE),
    )


def denied(run: Callable[[], object]) -> None:
    try:
        _ = run()
    except (IdentityAuthorizationDenied, InvalidContractValue, AuditCapacityExceeded):
        return
    raise AssertionError("expected authorization denial")
