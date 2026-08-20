"""Fixture-safe workspace-bound identity authorization V2 policy."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import TypeVar

from .identity_auth_v2_capability import consume_capability, issue_capability
from .identity_auth_v2_contracts import (
    DeviceRevocationV2,
    TrustedDeviceEnrollmentV2,
    WorkspaceTrustRootV2,
)
from .identity_auth_v2_delegation import (
    DelegatedReviewGrantV2,
    DelegatedReviewRevocationV2,
)
from .identity_auth_v2_errors import IdentityAuthorizationDenied
from .identity_auth_v2_request import CapabilityRequestV2
from .identity_auth_v2_state import (
    AuthenticatedDeviceContextV2,
    CapabilityGrantV2,
    IdentityAuditFactoryV2,
    IdentityAuthorizationStatePort,
)

_Result = TypeVar("_Result")

def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value)


class IdentityAuthorizationPolicyV2:
    store: IdentityAuthorizationStatePort
    audit: IdentityAuditFactoryV2
    now: Callable[[], str]

    def __init__(
        self,
        store: IdentityAuthorizationStatePort,
        audit: IdentityAuditFactoryV2,
        *,
        now: Callable[[], str],
    ) -> None:
        self.store = store
        self.audit = audit
        self.now = now

    def _active_context(
        self,
        context: AuthenticatedDeviceContextV2,
    ) -> tuple[WorkspaceTrustRootV2, TrustedDeviceEnrollmentV2]:
        current = _instant(self.now())
        if current >= _instant(context.expires_at):
            raise IdentityAuthorizationDenied("authenticated device context is expired")
        root = self.store.trust_root(context.workspace_ref, context.profile_ref)
        if root is None:
            raise IdentityAuthorizationDenied("workspace trust root is absent")
        enrollment = self.store.enrollment(context.device_key_ref)
        if (
            enrollment is None
            or enrollment.workspace_ref != context.workspace_ref
            or enrollment.profile_ref != context.profile_ref
            or enrollment.trust_root_ref != root.trust_root_ref
            or enrollment.subject_key_ref != context.actor_key_ref
        ):
            raise IdentityAuthorizationDenied("authenticated device is not enrolled")
        if self.store.device_revocation(context.device_key_ref) is not None:
            raise IdentityAuthorizationDenied("authenticated device is revoked")
        if current >= _instant(enrollment.expires_at):
            raise IdentityAuthorizationDenied("device enrollment is expired")
        return root, enrollment

    def _active_owner(
        self,
        context: AuthenticatedDeviceContextV2,
    ) -> WorkspaceTrustRootV2:
        root, _ = self._active_context(context)
        if context.actor_key_ref != root.owner_key_ref:
            raise IdentityAuthorizationDenied("owner device authority is required")
        return root

    def enroll(
        self,
        context: AuthenticatedDeviceContextV2,
        root: WorkspaceTrustRootV2,
        enrollment: TrustedDeviceEnrollmentV2,
    ) -> None:
        current = _instant(self.now())
        if (
            current < _instant(context.authenticated_at)
            or current >= _instant(context.expires_at)
            or current < _instant(enrollment.enrolled_at)
            or current >= _instant(enrollment.expires_at)
        ):
            raise IdentityAuthorizationDenied(
                "authenticated context or enrollment is expired"
            )
        current_root = self.store.trust_root(root.workspace_ref, root.profile_ref)
        if (
            context.workspace_ref != root.workspace_ref
            or context.profile_ref != root.profile_ref
            or context.actor_key_ref != root.owner_key_ref
            or enrollment.trust_root_ref != root.trust_root_ref
            or enrollment.workspace_ref != root.workspace_ref
            or enrollment.profile_ref != root.profile_ref
            or enrollment.enrolled_by_key_ref != root.owner_key_ref
        ):
            raise IdentityAuthorizationDenied("owner enrollment binding is invalid")
        if current_root is None:
            if (
                enrollment.subject_key_ref != root.owner_key_ref
                or enrollment.device_key_ref != context.device_key_ref
            ):
                raise IdentityAuthorizationDenied("first device must enroll the owner")
        else:
            if current_root != root:
                raise IdentityAuthorizationDenied("workspace trust root changed")
            _ = self._active_owner(context)
        audit = self.audit.prepare(
            workspace_ref=root.workspace_ref,
            actor_key_ref=context.actor_key_ref,
            operation_ref=enrollment.enrollment_ref,
            action="identity.device.enroll",
            occurred_at=self.now(),
            object_refs=(
                root.trust_root_ref,
                enrollment.enrollment_ref,
                enrollment.device_key_ref,
            ),
        )
        self.store.commit_enrollment(root, enrollment, audit)

    def revoke_device(
        self,
        context: AuthenticatedDeviceContextV2,
        revocation: DeviceRevocationV2,
    ) -> None:
        root = self._active_owner(context)
        if (
            revocation.trust_root_ref != root.trust_root_ref
            or revocation.workspace_ref != root.workspace_ref
            or revocation.profile_ref != root.profile_ref
            or revocation.revoked_by_key_ref != root.owner_key_ref
        ):
            raise IdentityAuthorizationDenied("device revocation binding is invalid")
        audit = self.audit.prepare(
            workspace_ref=root.workspace_ref,
            actor_key_ref=context.actor_key_ref,
            operation_ref=revocation.revocation_ref,
            action="identity.device.revoke",
            occurred_at=revocation.revoked_at,
            object_refs=(
                root.trust_root_ref,
                revocation.revocation_ref,
                revocation.device_key_ref,
            ),
        )
        self.store.commit_device_revocation(revocation, audit)

    def delegate(
        self,
        context: AuthenticatedDeviceContextV2,
        grant: DelegatedReviewGrantV2,
    ) -> None:
        root = self._active_owner(context)
        if (
            grant.trust_root_ref != root.trust_root_ref
            or grant.workspace_ref != root.workspace_ref
            or grant.profile_ref != root.profile_ref
            or grant.grantor_key_ref != root.owner_key_ref
            or grant.reviewer_key_ref == root.owner_key_ref
            or _instant(self.now()) >= _instant(grant.expires_at)
        ):
            raise IdentityAuthorizationDenied("delegation binding is invalid")
        audit = self.audit.prepare(
            workspace_ref=root.workspace_ref,
            actor_key_ref=context.actor_key_ref,
            operation_ref=grant.grant_ref,
            action="identity.delegation.grant",
            occurred_at=grant.granted_at,
            object_refs=(root.trust_root_ref, grant.grant_ref, *grant.actions),
        )
        self.store.commit_delegation(grant, audit)

    def revoke_delegation(
        self,
        context: AuthenticatedDeviceContextV2,
        revocation: DelegatedReviewRevocationV2,
    ) -> None:
        root = self._active_owner(context)
        grant = self.store.delegation(revocation.grant_ref)
        if (
            grant is None
            or revocation.trust_root_ref != root.trust_root_ref
            or revocation.workspace_ref != root.workspace_ref
            or revocation.profile_ref != root.profile_ref
            or revocation.revoked_by_key_ref != root.owner_key_ref
        ):
            raise IdentityAuthorizationDenied("delegation revocation binding is invalid")
        audit = self.audit.prepare(
            workspace_ref=root.workspace_ref,
            actor_key_ref=context.actor_key_ref,
            operation_ref=revocation.revocation_ref,
            action="identity.delegation.revoke",
            occurred_at=revocation.revoked_at,
            object_refs=(
                root.trust_root_ref,
                grant.grant_ref,
                revocation.revocation_ref,
            ),
        )
        self.store.commit_delegation_revocation(revocation, audit)

    def issue(
        self,
        context: AuthenticatedDeviceContextV2,
        request: CapabilityRequestV2,
        *,
        expires_at: str,
    ) -> CapabilityGrantV2:
        root, enrollment = self._active_context(context)
        return issue_capability(
            self.store,
            context,
            request,
            root,
            enrollment,
            expires_at=expires_at,
            now=self.now(),
        )

    def consume(
        self,
        context: AuthenticatedDeviceContextV2,
        capability_ref: str,
        action: str,
        operation: Callable[[], _Result],
    ) -> _Result:
        root, enrollment = self._active_context(context)
        return consume_capability(
            self.store,
            context,
            capability_ref,
            action,
            operation,
            root,
            enrollment,
            now=self.now(),
        )
