"""Locked process-local state for identity authorization V2 conformance."""
from __future__ import annotations

from hashlib import sha256
from threading import RLock

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.identity_auth_v2_contracts import (
    DeviceRevocationV2,
    TrustedDeviceEnrollmentV2,
    WorkspaceTrustRootV2,
)
from wiki_spike.memory_core.identity_auth_v2_delegation import (
    DelegatedReviewGrantV2,
    DelegatedReviewRevocationV2,
)
from wiki_spike.memory_core.identity_auth_v2_state import CapabilityGrantV2
from wiki_spike.memory_core.operability import AuditCapacityExceeded, AuditReference


class IdentityAuthorizationStoreV2:
    """Atomic fixture store; no production composition installs this adapter."""

    _max_audits: int
    _lock: RLock

    def __init__(self, *, max_audit_records: int) -> None:
        if max_audit_records < 1:
            raise ValueError("max_audit_records must be positive")
        self._max_audits = max_audit_records
        self._roots: dict[tuple[str, str], WorkspaceTrustRootV2] = {}
        self._enrollments: dict[str, TrustedDeviceEnrollmentV2] = {}
        self._device_revocations: dict[str, DeviceRevocationV2] = {}
        self._device_epochs: dict[str, int] = {}
        self._grants: dict[str, DelegatedReviewGrantV2] = {}
        self._grant_revocations: dict[str, DelegatedReviewRevocationV2] = {}
        self._capabilities: dict[str, CapabilityGrantV2] = {}
        self._consumed: set[str] = set()
        self._audits: dict[str, AuditReference] = {}
        self._lock = RLock()

    def _require_audit_capacity(self, audit: AuditReference) -> None:
        existing = self._audits.get(audit.audit_id)
        if existing is not None:
            if existing != audit:
                raise ValueError("audit binding conflict")
            return
        if len(self._audits) >= self._max_audits:
            raise AuditCapacityExceeded()

    def _store_audit(self, audit: AuditReference) -> None:
        self._audits[audit.audit_id] = audit

    def commit_enrollment(
        self,
        root: WorkspaceTrustRootV2,
        enrollment: TrustedDeviceEnrollmentV2,
        audit: AuditReference,
    ) -> None:
        key = (root.workspace_ref, root.profile_ref)
        with self._lock:
            current = self._roots.get(key)
            if current is not None and current != root:
                raise ValueError("workspace trust root binding changed")
            if enrollment.device_key_ref in self._enrollments:
                raise ValueError("device is already enrolled")
            self._require_audit_capacity(audit)
            self._roots[key] = root
            self._enrollments[enrollment.device_key_ref] = enrollment
            _ = self._device_epochs.setdefault(root.trust_root_ref, 0)
            self._store_audit(audit)

    def commit_device_revocation(
        self,
        revocation: DeviceRevocationV2,
        audit: AuditReference,
    ) -> None:
        with self._lock:
            if revocation.device_key_ref not in self._enrollments:
                raise ValueError("device enrollment is absent")
            if revocation.device_key_ref in self._device_revocations:
                raise ValueError("device is already revoked")
            current = self._device_epochs.get(revocation.trust_root_ref, 0)
            if revocation.revocation_epoch != str(current + 1):
                raise ValueError("device revocation epoch is not next")
            self._require_audit_capacity(audit)
            self._device_revocations[revocation.device_key_ref] = revocation
            self._device_epochs[revocation.trust_root_ref] = current + 1
            self._store_audit(audit)

    def commit_delegation(
        self,
        grant: DelegatedReviewGrantV2,
        audit: AuditReference,
    ) -> None:
        with self._lock:
            if grant.grant_ref in self._grants:
                raise ValueError("delegation grant already exists")
            self._require_audit_capacity(audit)
            self._grants[grant.grant_ref] = grant
            self._store_audit(audit)

    def commit_delegation_revocation(
        self,
        revocation: DelegatedReviewRevocationV2,
        audit: AuditReference,
    ) -> None:
        with self._lock:
            if revocation.grant_ref not in self._grants:
                raise ValueError("delegation grant is absent")
            if revocation.grant_ref in self._grant_revocations:
                raise ValueError("delegation is already revoked")
            self._require_audit_capacity(audit)
            self._grant_revocations[revocation.grant_ref] = revocation
            self._store_audit(audit)

    def trust_root(
        self, workspace_ref: str, profile_ref: str
    ) -> WorkspaceTrustRootV2 | None:
        with self._lock:
            return self._roots.get((workspace_ref, profile_ref))

    def enrollment(self, device_key_ref: str) -> TrustedDeviceEnrollmentV2 | None:
        with self._lock:
            return self._enrollments.get(device_key_ref)

    def device_revocation(self, device_key_ref: str) -> DeviceRevocationV2 | None:
        with self._lock:
            return self._device_revocations.get(device_key_ref)

    def delegation(self, grant_ref: str) -> DelegatedReviewGrantV2 | None:
        with self._lock:
            return self._grants.get(grant_ref)

    def delegation_revocation(
        self, grant_ref: str
    ) -> DelegatedReviewRevocationV2 | None:
        with self._lock:
            return self._grant_revocations.get(grant_ref)

    def grants_for(
        self,
        workspace_ref: str,
        profile_ref: str,
        reviewer_key_ref: str,
    ) -> tuple[DelegatedReviewGrantV2, ...]:
        with self._lock:
            return tuple(
                grant
                for _, grant in sorted(self._grants.items())
                if grant.workspace_ref == workspace_ref
                and grant.profile_ref == profile_ref
                and grant.reviewer_key_ref == reviewer_key_ref
            )

    def device_revocation_epoch(self, trust_root_ref: str) -> str:
        with self._lock:
            return str(self._device_epochs.get(trust_root_ref, 0))

    def save_capability(self, grant: CapabilityGrantV2) -> None:
        with self._lock:
            if grant.capability_ref in self._capabilities:
                raise ValueError("capability already exists")
            self._capabilities[grant.capability_ref] = grant

    def capability(self, capability_ref: str) -> CapabilityGrantV2 | None:
        with self._lock:
            return self._capabilities.get(capability_ref)

    def consume_capability(self, capability_ref: str) -> bool:
        with self._lock:
            if capability_ref not in self._capabilities or capability_ref in self._consumed:
                return False
            self._consumed.add(capability_ref)
            return True

    def authority_state_digest(self, workspace_ref: str, profile_ref: str) -> str:
        with self._lock:
            roots = [
                root.to_mapping()
                for (workspace, profile), root in sorted(self._roots.items())
                if (workspace, profile) == (workspace_ref, profile_ref)
            ]
            enrollments = [
                item.to_mapping()
                for _, item in sorted(self._enrollments.items())
                if item.workspace_ref == workspace_ref and item.profile_ref == profile_ref
            ]
            grants = [
                item.to_mapping()
                for _, item in sorted(self._grants.items())
                if item.workspace_ref == workspace_ref and item.profile_ref == profile_ref
            ]
            capabilities = [
                item.to_mapping()
                for _, item in sorted(self._capabilities.items())
                if item.workspace_ref == workspace_ref and item.profile_ref == profile_ref
            ]
            body = {
                "roots": roots,
                "enrollments": enrollments,
                "device_revocations": [
                    item.to_mapping()
                    for _, item in sorted(self._device_revocations.items())
                    if item.workspace_ref == workspace_ref and item.profile_ref == profile_ref
                ],
                "grants": grants,
                "grant_revocations": [
                    item.to_mapping()
                    for _, item in sorted(self._grant_revocations.items())
                    if item.workspace_ref == workspace_ref and item.profile_ref == profile_ref
                ],
                "capabilities": capabilities,
                "consumed": sorted(
                    capability_ref
                    for capability_ref in self._consumed
                    if self._capabilities[capability_ref].workspace_ref == workspace_ref
                    and self._capabilities[capability_ref].profile_ref == profile_ref
                ),
            }
            return sha256(canonical_bytes(body)).hexdigest()

    def audit_records(self) -> tuple[AuditReference, ...]:
        with self._lock:
            return tuple(record for _, record in sorted(self._audits.items()))
