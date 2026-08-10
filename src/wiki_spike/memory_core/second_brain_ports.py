"""Core-owned, inert Stage-1 Second Brain security port contracts.

Callers MUST run ``require_resolved_security_context`` before invoking any port.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Protocol, runtime_checkable
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .second_brain_capabilities import CapabilityGrantV1, ConsumptionReceipt, ConsumptionReceiptEvidence

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
from .second_brain_contracts import (
    ActivationReceiptV1,
    ConsentTransferReceiptV1,
    DecommissionCertificateRequestV1,
    DecommissionCertificateV1,
    RouteSwitchReceiptV1,
    SourceCheckpointV1,
    SourceItemDispositionV1,
    SourcePageV1,
)
from .second_brain_cutover import MigrationCohortManifestV1


@dataclass(frozen=True)
class CohortBoundaryScanRequestV1:
    """Hash-only evidence supplied to a fail-closed cohort boundary verifier."""

    scanner_version: str
    deny_schema_digest: str
    surface_digests: tuple[tuple[str, str, str], ...]

    def __post_init__(self) -> None:
        required = ("cas", "cohort_payload", "cohort_receipt", "db", "log", "manifest", "source_export", "wal")
        if self.scanner_version != "second-brain-cohort-boundary-scan-v1" or not re.fullmatch(r"[0-9a-f]{64}", self.deny_schema_digest):
            raise ValueError("invalid cohort boundary scan request version or deny schema digest")
        if tuple(name for name, _, _ in self.surface_digests) != required or len(set(self.surface_digests)) != len(self.surface_digests):
            raise ValueError("cohort boundary request surfaces must be complete, sorted, and unique")
        if any(not path or not re.fullmatch(r"[0-9a-f]{64}", digest) for _, path, digest in self.surface_digests):
            raise ValueError("cohort boundary request surfaces must be hash-only canonical entries")


@dataclass(frozen=True)
class CohortBoundaryScanFindingV1:
    """A class/rule hit or incomplete surface; never carries matched content."""

    surface_id: str
    relative_path: str
    sha256: str | None
    class_id: str | None
    rule_id: str

    def __post_init__(self) -> None:
        allowed = {"source_export", "manifest", "cohort_payload", "db", "wal", "cas", "log", "cohort_receipt"}
        if self.surface_id not in allowed or not self.relative_path or not self.rule_id:
            raise ValueError("cohort boundary finding must identify only a surface, path, and rule")
        if self.sha256 is not None and re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None:
            raise ValueError("cohort boundary finding digest must be a SHA-256 value")
        mandatory = {"credential", "keychain", "secret-token", "private-key", "session-cookie", "hidden-reasoning"}
        if self.class_id is None and (self.sha256 is not None or self.rule_id != "surface-incomplete"):
            raise ValueError("incomplete finding must not claim a digest or deny class")
        if self.class_id is not None and (self.class_id not in mandatory or self.sha256 is None or self.rule_id == "surface-incomplete"):
            raise ValueError("cohort boundary finding class must be non-empty when present")


@dataclass(frozen=True)
class CohortBoundaryScanResultV1:
    """Fail-closed scan result. ``no_import`` must remain true unless PASS."""

    result: str
    no_import: bool
    findings: tuple[CohortBoundaryScanFindingV1, ...]

    def __post_init__(self) -> None:
        if (self.result == "PASS" and not self.no_import and not self.findings) or (self.result == "QUARANTINED" and self.no_import and self.findings):
            return
        raise ValueError("cohort boundary result must be a complete PASS or fail-closed QUARANTINED state")


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
class CohortBoundaryScanPort(Protocol):
    """Verifies a bounded cohort evidence set without returning its contents."""

    def verify_cohort_boundary(
        self, request: CohortBoundaryScanRequestV1
    ) -> CohortBoundaryScanResultV1: ...


@runtime_checkable
class RouteSwitchAuthority(Protocol):
    """The sole Core route mutation boundary.

    Callers must validate the signed runbook before this call.  The authority
    then atomically accepts or rejects the complete set: it has no partial
    update, legacy fallback, or dual-write method shape.
    """

    def switch_atomic(
        self,
        *,
        cohort_manifest: MigrationCohortManifestV1,
        resolved_scope_digest: str,
        contract_digest: str,
        source_manifest_digest: str,
        capability_manifest_digest: str,
        benchmark_manifest_digest: str,
        generation_digest: str,
        checkpoint_digest: str,
        route_version: str,
        capability_epoch: str,
        visibility: str,
        pre_mutation_rollback_receipt: str,
    ) -> RouteSwitchReceiptV1: ...


@runtime_checkable
class DecommissionCertificateVerifierPort(Protocol):
    """Deployment-only decommission evidence boundary.

    The adapter verifies activation and consent-transfer Ed25519 signatures
    against out-of-band trusted registries, verifies every external approval by
    exact digest, role, scope, and freshness using trusted time, proves its
    trusted ``now`` is not before ``retention_end``, then signs this certificate.
    It never receives a boolean bypass and never deletes or revokes anything.
    """

    def issue_decommission_certificate(
        self,
        request: DecommissionCertificateRequestV1,
        *,
        activation: ActivationReceiptV1,
        consent_transfer: ConsentTransferReceiptV1,
    ) -> DecommissionCertificateV1: ...

    def verify_issued_decommission_certificate(
        self, certificate: DecommissionCertificateV1,
    ) -> bool:
        """Verify the returned certificate against the same trusted registry.

        This intentionally makes the adapter prove its own emitted Ed25519
        evidence before the application publishes it.  The public boundary
        receives only a boolean result, never public keys or registry state.
        """
        ...


@runtime_checkable
class SourceApiClientPort(Protocol):
    """Injected low-level read-only API transport; it cannot checkpoint or mutate."""
    read_only: bool
    def read_page(self, *, source_scope: str, cursor: str | None, watermark: str | None, limit: int, credential: object) -> Mapping[str, Any]: ...


@runtime_checkable
class FilesystemSourceClientPort(Protocol):
    """Injected low-level read-only filesystem transport; it has no write shape."""
    read_only: bool
    def read_page(self, *, source_scope: str, cursor: str | None, watermark: str | None, limit: int, credential: object) -> Mapping[str, Any]: ...


@runtime_checkable
class CredentialProviderPort(Protocol):
    """Provides an ephemeral capability only; callers must never persist it."""
    def read_only_credential(self, *, source_scope: str) -> object: ...


@runtime_checkable
class SourceReaderPort(Protocol):
    def read_page(self, *, source_scope: str, cursor: str | None, watermark: str | None, limit: int) -> SourcePageV1: ...


@runtime_checkable
class SourceCheckpointPort(Protocol):
    def load(self, *, source_scope: str) -> SourceCheckpointV1 | None: ...
    def commit(self, *, source_scope: str, prior_checkpoint: SourceCheckpointV1 | None, observed_page_digest: str, next_cursor: str | None, next_watermark: str | None, dispositions: tuple[SourceItemDispositionV1, ...], tombstones: tuple[tuple[str, str], ...]) -> SourceCheckpointV1: ...


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
    def capability(self, capability_ref: str) -> "CapabilityGrantV1 | None": ...
    def compare_consume(self, capability_ref: str, request_digest: str, nonce_digest: str, credential_ref: str, action: str) -> "ConsumptionReceipt | None": ...
    def redeem_consumption_receipt(self, token: "ConsumptionReceipt") -> "ConsumptionReceiptEvidence | None": ...
