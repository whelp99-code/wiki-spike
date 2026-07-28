"""Fail-closed Stage-1 device, delegation, and one-time capability services."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Callable, TypeVar

from .contracts import canonical_bytes
from .operability import CircuitBreaker, RetryBudget
from .second_brain_ports import CapabilityStatePort
from .second_brain_security_contracts import (
    CapabilityRequestV1, DelegatedReviewGrantV1, DeviceEnrollmentV1,
    SecurityContextAuthority, TrustRootV1, require_security_context_authority,
)


class CapabilityDenied(PermissionError):
    """An authorization predicate failed before downstream invocation."""


@dataclass(frozen=True)
class CapabilityGrantV1:
    capability_ref: str; request_digest: str; trust_root_ref: str; root_digest: str
    device_key_ref: str; workspace_ref: str; actor_key_ref: str; actions: tuple[str, ...]
    credential_refs: tuple[str, ...]; credential_actions: tuple[str, ...]
    scope_digest: str; expires_at: str; nonce_digest: str; revocation_epoch: str


_RECEIPT_MINT = object()


class ConsumptionReceipt:
    """Opaque, immutable, store-bound handle for one capability consumption."""

    __slots__ = ("__token", "__minted")

    def __init__(self, mint: object, token: str) -> None:
        if mint is not _RECEIPT_MINT:
            raise CapabilityDenied("ConsumptionReceipt must be minted by a capability store")
        object.__setattr__(self, "_ConsumptionReceipt__token", token)
        object.__setattr__(self, "_ConsumptionReceipt__minted", True)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ConsumptionReceipt is immutable")

    def _token_for_store(self) -> str:
        return self.__token


@dataclass(frozen=True)
class ConsumptionReceiptEvidence:
    """Immutable non-authority evidence returned only by the owning store."""

    credential_ref: str
    action: str
    device_key_ref: str
    expires_at: str


def mint_consumption_receipt(token: str) -> ConsumptionReceipt:
    """Internal store-only opaque receipt minting hook."""
    if not isinstance(token, str) or not token:
        raise CapabilityDenied("receipt token is required")
    return ConsumptionReceipt(_RECEIPT_MINT, token)

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


def _require(authority: object) -> SecurityContextAuthority:
    try:
        return require_security_context_authority(authority)
    except Exception as error:
        raise CapabilityDenied("resolved security authority is required") from error


class DeviceTrustService:
    def __init__(self, store: CapabilityStatePort, *, now: Callable[[], datetime] | None = None) -> None:
        self.store, self.now = store, now or (lambda: datetime.now(timezone.utc))

    def enroll(self, authority: SecurityContextAuthority, owner_key_ref: str, trust_root: TrustRootV1, enrollment: DeviceEnrollmentV1) -> None:
        _require(authority)
        if owner_key_ref != trust_root.owner_key_ref or enrollment.trust_root_ref != trust_root.trust_root_ref:
            raise CapabilityDenied("only the trust-root owner may enroll a device")
        if _now(self.now()) >= datetime.fromisoformat(enrollment.expires_at.replace("Z", "+00:00")).astimezone(timezone.utc):
            raise CapabilityDenied("device enrollment is expired")
        current = self.store.trust_root(trust_root.trust_root_ref)
        if current is None: self.store.record_trust_root(trust_root)
        elif current != trust_root: raise CapabilityDenied("trust root does not match the enrolled device")
        self.store.record_device_enrollment(enrollment)

    def revoke(self, authority: SecurityContextAuthority, owner_key_ref: str, trust_root_ref: str, device_key_ref: str) -> str:
        _require(authority)
        root = self.store.trust_root(trust_root_ref)
        if root is None or root.owner_key_ref != owner_key_ref: raise CapabilityDenied("only the trust-root owner may revoke a device")
        return self.store.revoke_device(trust_root_ref, device_key_ref)


class DelegationService:
    def __init__(self, store: CapabilityStatePort, *, now: Callable[[], datetime] | None = None) -> None:
        self.store, self.now = store, now or (lambda: datetime.now(timezone.utc))

    def delegate(self, authority: SecurityContextAuthority, owner_key_ref: str, trust_root_ref: str, grant: DelegatedReviewGrantV1) -> None:
        _require(authority)
        root = self.store.trust_root(trust_root_ref)
        if root is None or owner_key_ref != root.owner_key_ref or grant.grantor_key_ref != root.owner_key_ref or grant.reviewer_key_ref == root.owner_key_ref:
            raise CapabilityDenied("only the owner may create a non-owner review delegation")
        if _now(self.now()) >= datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")).astimezone(timezone.utc): raise CapabilityDenied("delegation is expired")
        self.store.record_delegated_review_grant(grant)


class CapabilityService:
    def __init__(self, store: CapabilityStatePort, *, retry_budget: RetryBudget | None = None, circuit_breaker: CircuitBreaker | None = None, now: Callable[[], datetime] | None = None) -> None:
        self.store, self.retry_budget, self.circuit_breaker, self.now = store, retry_budget, circuit_breaker, now or (lambda: datetime.now(timezone.utc))

    def issue(self, authority: SecurityContextAuthority, request: CapabilityRequestV1, *, trust_root_ref: str, device_key_ref: str, workspace_ref: str, actor_key_ref: str, actions: tuple[str, ...], credential_refs: tuple[str, ...], credential_actions: tuple[str, ...], scope_digest: str, expires_at: str, nonce: str) -> CapabilityGrantV1:
        _require(authority); current = _now(self.now()); root, device = self.store.trust_root(trust_root_ref), self.store.device(device_key_ref)
        ordered_actions = _ordered(actions, "actions")
        ordered_credential_refs = _ordered(credential_refs, "credential_refs")
        ordered_credential_actions = _ordered(credential_actions, "credential_actions")
        expected_scope = _digest({"workspace_ref": workspace_ref, "actions": list(ordered_actions), "credential_refs": list(ordered_credential_refs), "credential_actions": list(ordered_credential_actions), "scope_refs": list(request.scope_refs)})
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        if root is None or device is None or device.trust_root_ref != trust_root_ref or request.subject_key_ref != actor_key_ref or expiry <= current or expected_scope != scope_digest or not nonce or ordered_actions != request.scope_refs:
            raise CapabilityDenied("capability binding is invalid")
        if datetime.fromisoformat(device.expires_at.replace("Z", "+00:00")).astimezone(timezone.utc) <= current: raise CapabilityDenied("device enrollment is expired")
        if actor_key_ref != root.owner_key_ref and not any(g.grantor_key_ref == root.owner_key_ref and g.expires_at > current.isoformat() and set(request.scope_refs).issubset(g.scope_refs) for g in self.store.grants_for(actor_key_ref)):
            raise CapabilityDenied("delegation does not authorize this exact scope")
        grant = CapabilityGrantV1(request.capability_ref, request.request_digest, trust_root_ref, root.root_digest, device_key_ref, workspace_ref, actor_key_ref, ordered_actions, ordered_credential_refs, ordered_credential_actions, scope_digest, expires_at, _digest(nonce), self.store.revocation_epoch(trust_root_ref))
        self.store.record_capability_request(request); self.store.save_capability(grant); return grant

    def consume_for_credential(self, authority: SecurityContextAuthority, capability_ref: str, request_digest: str, nonce: str, *, credential_ref: str, action: str) -> ConsumptionReceipt:
        _require(authority)
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
        capability = self.store.capability(capability_ref)
        if capability is None:
            raise CapabilityDenied("capability is missing, replayed, or tampered")
        root, device = self.store.trust_root(capability.trust_root_ref), self.store.device(capability.device_key_ref)
        if root is None or device is None or root.root_digest != capability.root_digest or self.store.revocation_epoch(capability.trust_root_ref) != capability.revocation_epoch or current >= datetime.fromisoformat(capability.expires_at.replace("Z", "+00:00")).astimezone(timezone.utc):
            raise CapabilityDenied("capability is expired or revoked")
        receipt = self.store.compare_consume(capability_ref, request_digest, _digest(nonce), credential_ref, action)
        if receipt is None: raise CapabilityDenied("capability is missing, replayed, tampered, or out of scope")
        return receipt

    def consume(self, authority: SecurityContextAuthority, capability_ref: str, request_digest: str, nonce: str, invoke: Callable[[], _Result]) -> _Result:
        capability = self.store.capability(capability_ref)
        if capability is None:
            raise CapabilityDenied("capability is missing, replayed, or tampered")
        receipt = self.consume_for_credential(authority, capability_ref, request_digest, nonce, credential_ref=capability.credential_refs[0], action=capability.credential_actions[0])
        try:
            result = invoke()
        except Exception:
            if self.circuit_breaker is not None:
                self.circuit_breaker.record_failure(now=_now(self.now()).isoformat())
            raise
        if self.circuit_breaker is not None:
            self.circuit_breaker.record_success()
        return result
    def issue_and_consume(self, authority: SecurityContextAuthority, request: CapabilityRequestV1, *, invoke: Callable[[], _Result], **binding: object) -> _Result:
        grant = self.issue(authority, request, **binding)
        nonce = binding.get("nonce")
        if not isinstance(nonce, str):
            raise CapabilityDenied("nonce must be a string")
        return self.consume(authority, grant.capability_ref, request.request_digest, nonce, invoke)
