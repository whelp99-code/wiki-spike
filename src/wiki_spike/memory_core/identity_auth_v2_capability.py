"""Capability issue and consume policy for identity authorization V2."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from .identity_auth_v2_contracts import (
    TrustedDeviceEnrollmentV2,
    WorkspaceTrustRootV2,
)
from .identity_auth_v2_errors import IdentityAuthorizationDenied
from .identity_auth_v2_request import CapabilityRequestV2
from .identity_auth_v2_state import (
    AuthenticatedDeviceContextV2,
    CapabilityGrantV2,
    IdentityAuthorizationStatePort,
)


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value)


def issue_capability(
    store: IdentityAuthorizationStatePort,
    context: AuthenticatedDeviceContextV2,
    request: CapabilityRequestV2,
    root: WorkspaceTrustRootV2,
    enrollment: TrustedDeviceEnrollmentV2,
    *,
    expires_at: str,
    now: str,
) -> CapabilityGrantV2:
    if (
        request.workspace_ref != context.workspace_ref
        or request.profile_ref != context.profile_ref
    ):
        raise IdentityAuthorizationDenied("request workspace or profile is invalid")
    if (
        request.subject_key_ref != context.actor_key_ref
        or request.device_key_ref != context.device_key_ref
    ):
        raise IdentityAuthorizationDenied("request actor or device is invalid")
    expiry = _instant(expires_at)
    if expiry <= _instant(now) or expiry > _instant(enrollment.expires_at):
        raise IdentityAuthorizationDenied("capability expiry is invalid")
    grant_ref: str | None = None
    grant_revision: str | None = None
    if context.actor_key_ref != root.owner_key_ref:
        candidates = tuple(
            grant
            for grant in store.grants_for(
                context.workspace_ref,
                context.profile_ref,
                context.actor_key_ref,
            )
            if store.delegation_revocation(grant.grant_ref) is None
            and _instant(now) < _instant(grant.expires_at)
            and set(request.actions).issubset(grant.actions)
        )
        if len(candidates) != 1:
            raise IdentityAuthorizationDenied("delegation does not authorize request")
        selected = candidates[0]
        if expiry > _instant(selected.expires_at):
            raise IdentityAuthorizationDenied("capability exceeds delegation expiry")
        grant_ref = selected.grant_ref
        grant_revision = selected.grant_revision
    capability = CapabilityGrantV2(
        request.capability_ref,
        request.request_digest,
        root.root_digest,
        request.workspace_ref,
        request.profile_ref,
        request.subject_key_ref,
        request.device_key_ref,
        enrollment.enrollment_ref,
        request.actions,
        expires_at,
        grant_ref,
        grant_revision,
        store.device_revocation_epoch(root.trust_root_ref),
    )
    store.save_capability(capability)
    return capability


def consume_capability[Result](
    store: IdentityAuthorizationStatePort,
    context: AuthenticatedDeviceContextV2,
    capability_ref: str,
    action: str,
    operation: Callable[[], Result],
    root: WorkspaceTrustRootV2,
    enrollment: TrustedDeviceEnrollmentV2,
    *,
    now: str,
) -> Result:
    capability = store.capability(capability_ref)
    if capability is None:
        raise IdentityAuthorizationDenied("capability is absent")
    if (
        capability.workspace_ref != context.workspace_ref
        or capability.profile_ref != context.profile_ref
        or capability.subject_key_ref != context.actor_key_ref
        or capability.device_key_ref != context.device_key_ref
        or capability.enrollment_ref != enrollment.enrollment_ref
        or capability.root_digest != root.root_digest
        or action not in capability.actions
        or _instant(now) >= _instant(capability.expires_at)
        or capability.device_revocation_epoch
        != store.device_revocation_epoch(root.trust_root_ref)
    ):
        raise IdentityAuthorizationDenied("capability binding is invalid")
    if capability.delegation_grant_ref is not None:
        grant = store.delegation(capability.delegation_grant_ref)
        if (
            grant is None
            or grant.grant_revision != capability.delegation_grant_revision
            or store.delegation_revocation(grant.grant_ref) is not None
            or _instant(now) >= _instant(grant.expires_at)
            or action not in grant.actions
        ):
            raise IdentityAuthorizationDenied("delegation is revoked or expired")
    if not store.consume_capability(capability_ref):
        raise IdentityAuthorizationDenied("capability is already consumed")
    return operation()
