"""Assemble the closed DB-01 V2 authorization case matrix."""
from __future__ import annotations

from wiki_spike.applications.identity_auth_v2_evidence_accept import (
    delegated_action_allowed,
    delegation_grant_audited,
    delegation_revoke_audited,
    owner_device_revoke_allowed,
    owner_enroll_allowed,
)
from wiki_spike.applications.identity_auth_v2_evidence_deny import (
    nonowner_device_revoke_denied,
    nonowner_enroll_denied,
    ownership_transfer_denied,
    redelegation_denied,
    ungranted_action_denied,
    wrong_workspace_denied,
)
from wiki_spike.applications.identity_auth_v2_evidence_deny_revoke import (
    audit_failure_rolls_back,
    expired_delegation_denied,
    revoked_delegation_denied,
    revoked_device_denied,
)
from wiki_spike.applications.identity_auth_v2_evidence_support import REQUIRED_CASE_IDS
from wiki_spike.memory_core.contracts import JsonValue

__all__ = ["REQUIRED_CASE_IDS", "run_identity_auth_v2_cases"]


def run_identity_auth_v2_cases() -> tuple[dict[str, JsonValue], ...]:
    """Return the closed 15-case matrix with live fixture digests."""
    return (
        owner_enroll_allowed(),
        nonowner_enroll_denied(),
        owner_device_revoke_allowed(),
        nonowner_device_revoke_denied(),
        delegation_grant_audited(),
        delegated_action_allowed(),
        wrong_workspace_denied(),
        ungranted_action_denied(),
        ownership_transfer_denied(),
        redelegation_denied(),
        expired_delegation_denied(),
        delegation_revoke_audited(),
        revoked_delegation_denied(),
        revoked_device_denied(),
        audit_failure_rolls_back(),
    )
