"""Internal state, audit, and port contracts for identity authorization V2."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

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
from .identity_auth_v2_parse import (
    parse_actions,
    parse_decimal,
    parse_instant,
    parse_positive,
    parse_ref,
    require_before,
)
from .operability import AuditReference, ReferenceHasher


@dataclass(frozen=True, slots=True)
class AuthenticatedDeviceContextV2:
    workspace_ref: str
    profile_ref: str
    actor_key_ref: str
    device_key_ref: str
    authenticated_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _ = parse_ref(self.workspace_ref, "workspace_ref", "workspace")
        _ = parse_ref(self.profile_ref, "profile_ref", "profile")
        _ = parse_ref(self.actor_key_ref, "actor_key_ref", "key")
        _ = parse_ref(self.device_key_ref, "device_key_ref", "device")
        _ = parse_instant(self.authenticated_at, "authenticated_at")
        _ = parse_instant(self.expires_at, "expires_at")
        require_before(self.authenticated_at, self.expires_at, "expires_at")


@dataclass(frozen=True, slots=True)
class CapabilityGrantV2:
    capability_ref: str
    request_digest: str
    root_digest: str
    workspace_ref: str
    profile_ref: str
    subject_key_ref: str
    device_key_ref: str
    enrollment_ref: str
    actions: tuple[str, ...]
    expires_at: str
    delegation_grant_ref: str | None
    delegation_grant_revision: str | None
    device_revocation_epoch: str

    def __post_init__(self) -> None:
        _ = parse_ref(self.capability_ref, "capability_ref", "capability")
        _ = parse_ref(self.workspace_ref, "workspace_ref", "workspace")
        _ = parse_ref(self.profile_ref, "profile_ref", "profile")
        _ = parse_ref(self.subject_key_ref, "subject_key_ref", "key")
        _ = parse_ref(self.device_key_ref, "device_key_ref", "device")
        _ = parse_ref(self.enrollment_ref, "enrollment_ref", "enrollment")
        _ = parse_actions(list(self.actions), "actions")
        _ = parse_instant(self.expires_at, "expires_at")
        _ = parse_decimal(self.device_revocation_epoch, "device_revocation_epoch")
        if self.delegation_grant_ref is None:
            if self.delegation_grant_revision is not None:
                raise ValueError("delegation revision requires a grant")
        else:
            _ = parse_ref(self.delegation_grant_ref, "delegation_grant_ref", "grant")
            if self.delegation_grant_revision is None:
                raise ValueError("delegation grant requires a revision")
            _ = parse_positive(
                self.delegation_grant_revision,
                "delegation_grant_revision",
            )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "capability_ref": self.capability_ref,
            "request_digest": self.request_digest,
            "root_digest": self.root_digest,
            "workspace_ref": self.workspace_ref,
            "profile_ref": self.profile_ref,
            "subject_key_ref": self.subject_key_ref,
            "device_key_ref": self.device_key_ref,
            "enrollment_ref": self.enrollment_ref,
            "actions": list(self.actions),
            "expires_at": self.expires_at,
            "delegation_grant_ref": self.delegation_grant_ref,
            "delegation_grant_revision": self.delegation_grant_revision,
            "device_revocation_epoch": self.device_revocation_epoch,
        }


class IdentityAuditFactoryV2:
    hasher: ReferenceHasher
    policy_version: str

    def __init__(self, hasher: ReferenceHasher, *, policy_version: str) -> None:
        self.hasher = hasher
        self.policy_version = policy_version

    def prepare(
        self,
        *,
        workspace_ref: str,
        actor_key_ref: str,
        operation_ref: str,
        action: str,
        occurred_at: str,
        object_refs: tuple[str, ...],
    ) -> AuditReference:
        return AuditReference.create(
            workspace_ref_hash=self.hasher.digest(workspace_ref),
            actor_ref_hash=self.hasher.digest(actor_key_ref),
            operation_ref_hash=self.hasher.digest(operation_ref),
            correlation_ref_hash=self.hasher.digest(operation_ref),
            action=action,
            outcome="accepted",
            reason_code="owner_authorized",
            generation_id=None,
            object_ref_digests=tuple(
                sorted({self.hasher.digest(reference) for reference in object_refs})
            ),
            policy_version=self.policy_version,
            occurred_at=occurred_at,
        )


class IdentityAuthorizationStatePort(Protocol):
    def commit_enrollment(
        self,
        root: WorkspaceTrustRootV2,
        enrollment: TrustedDeviceEnrollmentV2,
        audit: AuditReference,
    ) -> None: ...

    def commit_device_revocation(
        self,
        revocation: DeviceRevocationV2,
        audit: AuditReference,
    ) -> None: ...

    def commit_delegation(
        self,
        grant: DelegatedReviewGrantV2,
        audit: AuditReference,
    ) -> None: ...

    def commit_delegation_revocation(
        self,
        revocation: DelegatedReviewRevocationV2,
        audit: AuditReference,
    ) -> None: ...

    def trust_root(
        self, workspace_ref: str, profile_ref: str
    ) -> WorkspaceTrustRootV2 | None: ...

    def enrollment(self, device_key_ref: str) -> TrustedDeviceEnrollmentV2 | None: ...
    def device_revocation(self, device_key_ref: str) -> DeviceRevocationV2 | None: ...
    def delegation(self, grant_ref: str) -> DelegatedReviewGrantV2 | None: ...

    def delegation_revocation(
        self, grant_ref: str
    ) -> DelegatedReviewRevocationV2 | None: ...

    def grants_for(
        self,
        workspace_ref: str,
        profile_ref: str,
        reviewer_key_ref: str,
    ) -> tuple[DelegatedReviewGrantV2, ...]: ...

    def device_revocation_epoch(self, trust_root_ref: str) -> str: ...
    def save_capability(self, grant: CapabilityGrantV2) -> None: ...
    def capability(self, capability_ref: str) -> CapabilityGrantV2 | None: ...
    def consume_capability(self, capability_ref: str) -> bool: ...
    def authority_state_digest(self, workspace_ref: str, profile_ref: str) -> str: ...
    def audit_records(self) -> tuple[AuditReference, ...]: ...


type Invocation = Callable[[], None]
