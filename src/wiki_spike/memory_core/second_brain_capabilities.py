"""Fail-closed Stage-1 device, delegation, and one-time capability services."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Callable, Protocol, TypeVar

from .contracts import canonical_bytes
from .operability import CircuitBreaker, RetryBudget
from .second_brain_security_contracts import (
    CapabilityRequestV1,
    DelegatedReviewGrantV1,
    DeviceEnrollmentV1,
    TrustRootV1,
)


class CapabilityDenied(PermissionError):
    """An authorization predicate failed before downstream invocation."""

class CapabilityStatePort(Protocol):
    def record_trust_root(self, trust_root: TrustRootV1) -> None: ...
    def record_device_enrollment(self, enrollment: DeviceEnrollmentV1) -> None: ...
    def record_delegated_review_grant(self, grant: DelegatedReviewGrantV1) -> None: ...
    def record_capability_request(self, request: CapabilityRequestV1) -> None: ...
    def trust_root(self, trust_root_ref: str) -> TrustRootV1 | None: ...
    def device(self, device_key_ref: str) -> DeviceEnrollmentV1 | None: ...
    def grants_for(self, reviewer_key_ref: str) -> tuple[DelegatedReviewGrantV1, ...]: ...
    def revoke_device(self, trust_root_ref: str, device_key_ref: str) -> str: ...
    def revocation_epoch(self, trust_root_ref: str) -> str: ...
    def save_capability(self, capability: object) -> None: ...
    def compare_consume(self, capability_ref: str, request_digest: str, nonce_digest: str) -> object | None: ...


@dataclass(frozen=True)
class CapabilityGrantV1:
    capability_ref: str
    request_digest: str
    trust_root_ref: str
    root_digest: str
    device_key_ref: str
    workspace_ref: str
    actor_key_ref: str
    actions: tuple[str, ...]
    scope_digest: str
    expires_at: str
    nonce_digest: str
    revocation_epoch: str


_Result = TypeVar("_Result")


def _now(now: datetime | None) -> datetime:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc)


def _digest(value: object) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _ordered(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    if not values or any(not isinstance(value, str) or not value for value in values):
        raise CapabilityDenied(f"{field} must be non-empty strings")
    if values != tuple(sorted(values)) or len(set(values)) != len(values):
        raise CapabilityDenied(f"{field} must be sorted and unique")
    return values


class DeviceTrustService:
    def __init__(self, store: CapabilityStatePort, *, now: Callable[[], datetime] | None = None) -> None:
        self.store = store
        self.now = now or (lambda: datetime.now(timezone.utc))

    def enroll(self, owner_key_ref: str, trust_root: TrustRootV1, enrollment: DeviceEnrollmentV1) -> None:
        if owner_key_ref != trust_root.owner_key_ref or enrollment.trust_root_ref != trust_root.trust_root_ref:
            raise CapabilityDenied("only the trust-root owner may enroll a device")
        if _now(self.now()) >= datetime.fromisoformat(enrollment.expires_at.replace("Z", "+00:00")).astimezone(timezone.utc):
            raise CapabilityDenied("device enrollment is expired")
        if self.store.trust_root(trust_root.trust_root_ref) is None:
            self.store.record_trust_root(trust_root)
        elif self.store.trust_root(trust_root.trust_root_ref) != trust_root:
            raise CapabilityDenied("trust root does not match the enrolled device")
        self.store.record_device_enrollment(enrollment)

    def revoke(self, owner_key_ref: str, trust_root_ref: str, device_key_ref: str) -> str:
        root = self.store.trust_root(trust_root_ref)
        if root is None or root.owner_key_ref != owner_key_ref:
            raise CapabilityDenied("only the trust-root owner may revoke a device")
        return self.store.revoke_device(trust_root_ref, device_key_ref)


class DelegationService:
    def __init__(self, store: CapabilityStatePort, *, now: Callable[[], datetime] | None = None) -> None:
        self.store = store
        self.now = now or (lambda: datetime.now(timezone.utc))

    def delegate(self, owner_key_ref: str, trust_root_ref: str, grant: DelegatedReviewGrantV1) -> None:
        root = self.store.trust_root(trust_root_ref)
        if (root is None or owner_key_ref != root.owner_key_ref
                or grant.grantor_key_ref != root.owner_key_ref
                or grant.reviewer_key_ref == root.owner_key_ref):
            raise CapabilityDenied("only the owner may create a non-owner review delegation")
        if _now(self.now()) >= datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")).astimezone(timezone.utc):
            raise CapabilityDenied("delegation is expired")
        self.store.record_delegated_review_grant(grant)


class CapabilityService:
    def __init__(self, store: CapabilityStatePort, *, retry_budget: RetryBudget | None = None,
                 circuit_breaker: CircuitBreaker | None = None,
                 now: Callable[[], datetime] | None = None) -> None:
        self.store = store
        self.retry_budget = retry_budget
        self.circuit_breaker = circuit_breaker
        self.now = now or (lambda: datetime.now(timezone.utc))

    def issue(self, request: CapabilityRequestV1, *, trust_root_ref: str, device_key_ref: str,
              workspace_ref: str, actor_key_ref: str, actions: tuple[str, ...],
              scope_digest: str, expires_at: str, nonce: str) -> CapabilityGrantV1:
        current = _now(self.now())
        root = self.store.trust_root(trust_root_ref)
        device = self.store.device(device_key_ref)
        ordered_actions = _ordered(actions, "actions")
        expected_scope = _digest({"workspace_ref": workspace_ref, "actions": list(ordered_actions), "scope_refs": list(request.scope_refs)})
        nonce_digest = _digest(nonce)
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        if (root is None or device is None or device.trust_root_ref != trust_root_ref
                or request.subject_key_ref != actor_key_ref or expiry <= current
                or expected_scope != scope_digest or not nonce
                or ordered_actions != request.scope_refs):
            raise CapabilityDenied("capability binding is invalid")
        device_expiry = datetime.fromisoformat(device.expires_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        if device_expiry <= current:
            raise CapabilityDenied("device enrollment is expired")
        if actor_key_ref != root.owner_key_ref:
            grants = self.store.grants_for(actor_key_ref)
            if not any(grant.grantor_key_ref == root.owner_key_ref and grant.expires_at > current.isoformat() and set(request.scope_refs).issubset(grant.scope_refs) for grant in grants):
                raise CapabilityDenied("delegation does not authorize this exact scope")
        grant = CapabilityGrantV1(request.capability_ref, request.request_digest, trust_root_ref,
            root.root_digest, device_key_ref, workspace_ref, actor_key_ref, ordered_actions,
            scope_digest, expires_at, nonce_digest, self.store.revocation_epoch(trust_root_ref))
        self.store.record_capability_request(request)
        self.store.save_capability(grant)
        return grant

    def consume(self, capability_ref: str, request_digest: str, nonce: str,
                invoke: Callable[[], _Result]) -> _Result:
        current = _now(self.now())
        if self.circuit_breaker is not None:
            decision = self.circuit_breaker.before_call(now=current.isoformat())
            if not decision.allowed:
                raise CapabilityDenied(decision.error_code or "circuit denied")
        if self.retry_budget is not None:
            budget = self.retry_budget.reserve(request_digest, "1")
            if not budget.allowed:
                if self.circuit_breaker is not None:
                    self.circuit_breaker.cancel_probe()
                raise CapabilityDenied(budget.error_code or "quota denied")
        capability = self.store.compare_consume(capability_ref, request_digest, _digest(nonce))
        if capability is None:
            if self.circuit_breaker is not None:
                self.circuit_breaker.cancel_probe()
            raise CapabilityDenied("capability is missing, replayed, or tampered")
        root = self.store.trust_root(capability.trust_root_ref)
        device = self.store.device(capability.device_key_ref)
        if (root is None or device is None or root.root_digest != capability.root_digest
                or self.store.revocation_epoch(capability.trust_root_ref) != capability.revocation_epoch
                or current >= datetime.fromisoformat(capability.expires_at.replace("Z", "+00:00")).astimezone(timezone.utc)):
            if self.circuit_breaker is not None:
                self.circuit_breaker.cancel_probe()
            raise CapabilityDenied("capability is expired or revoked")
        try:
            result = invoke()
        except Exception:
            if self.circuit_breaker is not None:
                self.circuit_breaker.record_failure(now=current.isoformat())
            raise
        if self.circuit_breaker is not None:
            self.circuit_breaker.record_success()
        return result

    def issue_and_consume(self, request: CapabilityRequestV1, *, invoke: Callable[[], _Result], **binding: object) -> _Result:
        grant = self.issue(request, **binding)
        nonce = binding.get("nonce")
        if not isinstance(nonce, str):
            raise CapabilityDenied("nonce must be a string")
        return self.consume(grant.capability_ref, request.request_digest, nonce, invoke)
