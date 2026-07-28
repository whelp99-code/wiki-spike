"""Core-owned, inert Stage-1 Second Brain security port contracts.

Callers MUST run ``require_resolved_security_context`` before invoking any port.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .second_brain_capabilities import CapabilityGrantV1, ConsumptionReceipt

from .second_brain_security_contracts import (
    CapabilityReceiptV1,
    CapabilityRequestV1,
    CredentialLeaseRequestV1,
    DelegatedReviewGrantV1,
    DeviceEnrollmentV1,
    EgressPolicyV1,
    SourceConsentRetentionV1,
    SourceDeletionRecoveryMapV1,
    SourceFixtureManifestV1,
    TelemetryAllowlistV1,
    TrustRootV1,
)


@runtime_checkable
class TrustRootPort(Protocol):
    def record_trust_root(self, trust_root: TrustRootV1) -> None: ...


@runtime_checkable
class DeviceEnrollmentPort(Protocol):
    def record_device_enrollment(self, enrollment: DeviceEnrollmentV1) -> None: ...


@runtime_checkable
class DelegatedReviewGrantPort(Protocol):
    def record_delegated_review_grant(self, grant: DelegatedReviewGrantV1) -> None: ...


@runtime_checkable
class CapabilityAuthorizationPort(Protocol):
    def record_capability_request(self, request: CapabilityRequestV1) -> None: ...
    def record_capability_receipt(self, receipt: CapabilityReceiptV1) -> None: ...


@runtime_checkable
class CredentialLeasePort(Protocol):
    def record_credential_lease_request(self, request: CredentialLeaseRequestV1) -> None: ...


@runtime_checkable
class SourceGovernancePort(Protocol):
    def record_source_consent_retention(self, policy: SourceConsentRetentionV1) -> None: ...
    def record_source_fixture_manifest(self, manifest: SourceFixtureManifestV1) -> None: ...
    def record_source_deletion_recovery_map(self, recovery_map: SourceDeletionRecoveryMapV1) -> None: ...


@runtime_checkable
class EgressPolicyPort(Protocol):
    def record_egress_policy(self, policy: EgressPolicyV1) -> None: ...


@runtime_checkable
class CapabilityStatePort(
    TrustRootPort, DeviceEnrollmentPort, DelegatedReviewGrantPort, CapabilityAuthorizationPort, Protocol
):
    """Atomic persistence boundary for Stage-1 capability state."""
    def trust_root(self, trust_root_ref: str) -> TrustRootV1 | None: ...
    def device(self, device_key_ref: str) -> DeviceEnrollmentV1 | None: ...
    def grants_for(self, reviewer_key_ref: str) -> tuple[DelegatedReviewGrantV1, ...]: ...
    def revoke_device(self, trust_root_ref: str, device_key_ref: str) -> str: ...
    def revocation_epoch(self, trust_root_ref: str) -> str: ...
    def save_capability(self, capability: "CapabilityGrantV1") -> None: ...
    def compare_consume(self, capability_ref: str, request_digest: str, nonce_digest: str, credential_ref: str, action: str) -> "ConsumptionReceipt | None": ...