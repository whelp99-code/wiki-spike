"""Deterministic fixture records for neutral DB-01 machine evidence."""
from __future__ import annotations

from .contracts import JsonValue
from .identity_auth_v2_contracts import (
    DeviceRevocationV2,
    TrustedDeviceEnrollmentV2,
    WorkspaceTrustRootV2,
)
from .identity_auth_v2_delegation import (
    DelegatedReviewGrantV2,
    DelegatedReviewRevocationV2,
)
from .identity_auth_v2_parse import identity_auth_digest
from .identity_auth_v2_request import CapabilityRequestV2
from .identity_auth_v2_state import AuthenticatedDeviceContextV2

FIXTURE_NOW = "2030-01-01T00:00:00Z"
FIXTURE_LATER = "2030-02-01T00:00:00Z"


def fixture_ref(kind: str, digit: str) -> str:
    return f"{kind}:{digit * 64}"


def _sealed(
    kind: str,
    digest_field: str,
    body: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    return {**body, digest_field: identity_auth_digest(kind, body)}


def fixture_root() -> WorkspaceTrustRootV2:
    return WorkspaceTrustRootV2.from_mapping(
        _sealed(
            "workspace-trust-root",
            "root_digest",
            {
                "identity_auth_version": "second-brain-identity-auth-v2",
                "trust_root_ref": fixture_ref("trust-root", "1"),
                "root_revision": "1",
                "workspace_ref": fixture_ref("workspace", "2"),
                "profile_ref": fixture_ref("profile", "3"),
                "owner_key_ref": fixture_ref("key", "4"),
                "approver_key_ref": fixture_ref("key", "5"),
            },
        )
    )


def fixture_enrollment(
    *,
    subject: str | None = None,
    device: str | None = None,
) -> TrustedDeviceEnrollmentV2:
    subject = subject or fixture_ref("key", "4")
    device = device or fixture_ref("device", "6")
    return TrustedDeviceEnrollmentV2.from_mapping(
        _sealed(
            "trusted-device-enrollment",
            "enrollment_digest",
            {
                "identity_auth_version": "second-brain-identity-auth-v2",
                "enrollment_ref": fixture_ref("enrollment", device[-1]),
                "trust_root_ref": fixture_ref("trust-root", "1"),
                "workspace_ref": fixture_ref("workspace", "2"),
                "profile_ref": fixture_ref("profile", "3"),
                "device_key_ref": device,
                "subject_key_ref": subject,
                "enrolled_by_key_ref": fixture_ref("key", "4"),
                "enrolled_at": FIXTURE_NOW,
                "expires_at": FIXTURE_LATER,
            },
        )
    )


def fixture_context(
    *,
    actor: str | None = None,
    device: str | None = None,
    workspace: str | None = None,
) -> AuthenticatedDeviceContextV2:
    return AuthenticatedDeviceContextV2(
        workspace or fixture_ref("workspace", "2"),
        fixture_ref("profile", "3"),
        actor or fixture_ref("key", "4"),
        device or fixture_ref("device", "6"),
        FIXTURE_NOW,
        FIXTURE_LATER,
    )


def fixture_grant(*, expires_at: str = FIXTURE_LATER) -> DelegatedReviewGrantV2:
    body: dict[str, JsonValue] = {
        "identity_auth_version": "second-brain-identity-auth-v2",
        "grant_ref": fixture_ref("grant", "7"),
        "grant_revision": "1",
        "trust_root_ref": fixture_ref("trust-root", "1"),
        "workspace_ref": fixture_ref("workspace", "2"),
        "profile_ref": fixture_ref("profile", "3"),
        "grantor_key_ref": fixture_ref("key", "4"),
        "reviewer_key_ref": fixture_ref("key", "8"),
        "actions": ["review.approve"],
        "granted_at": FIXTURE_NOW,
        "expires_at": expires_at,
    }
    return DelegatedReviewGrantV2.from_mapping(
        _sealed("delegated-review-grant", "grant_digest", body)
    )


def fixture_request(
    *,
    workspace: str | None = None,
    actor: str | None = None,
    device: str | None = None,
    capability_digit: str = "b",
) -> CapabilityRequestV2:
    body: dict[str, JsonValue] = {
        "identity_auth_version": "second-brain-identity-auth-v2",
        "request_ref": fixture_ref("request", capability_digit),
        "capability_ref": fixture_ref("capability", capability_digit),
        "workspace_ref": workspace or fixture_ref("workspace", "2"),
        "profile_ref": fixture_ref("profile", "3"),
        "subject_key_ref": actor or fixture_ref("key", "8"),
        "device_key_ref": device or fixture_ref("device", "9"),
        "actions": ["review.approve"],
        "requested_at": "2030-01-01T00:00:01Z",
    }
    return CapabilityRequestV2.from_mapping(
        _sealed("capability-request", "request_digest", body)
    )


def fixture_grant_revocation() -> DelegatedReviewRevocationV2:
    body: dict[str, JsonValue] = {
        "identity_auth_version": "second-brain-identity-auth-v2",
        "revocation_ref": fixture_ref("revocation", "c"),
        "grant_ref": fixture_ref("grant", "7"),
        "trust_root_ref": fixture_ref("trust-root", "1"),
        "workspace_ref": fixture_ref("workspace", "2"),
        "profile_ref": fixture_ref("profile", "3"),
        "revoked_by_key_ref": fixture_ref("key", "4"),
        "revoked_at": "2030-01-01T00:00:02Z",
        "reason_code": "owner_revoked",
    }
    return DelegatedReviewRevocationV2.from_mapping(
        _sealed("delegated-review-revocation", "revocation_digest", body)
    )


def fixture_device_revocation() -> DeviceRevocationV2:
    body: dict[str, JsonValue] = {
        "identity_auth_version": "second-brain-identity-auth-v2",
        "revocation_ref": fixture_ref("revocation", "d"),
        "trust_root_ref": fixture_ref("trust-root", "1"),
        "workspace_ref": fixture_ref("workspace", "2"),
        "profile_ref": fixture_ref("profile", "3"),
        "device_key_ref": fixture_ref("device", "6"),
        "revoked_by_key_ref": fixture_ref("key", "4"),
        "revoked_at": "2030-01-01T00:00:02Z",
        "reason_code": "retired",
        "revocation_epoch": "1",
    }
    return DeviceRevocationV2.from_mapping(
        _sealed("device-revocation", "revocation_digest", body)
    )
