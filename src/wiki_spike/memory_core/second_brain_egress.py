"""Local-first Stage-1 egress authorization with no provider fallback.

This module only decides whether an already-configured external operation may be
invoked.  It neither resolves providers nor performs network I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, TypeVar

from .errors import InvalidContractValue
from .second_brain_contracts import (
    ContractResolutionV1,
    SignedSecondBrainContractEnvelopeV1,
    TrustedDecisionKeyBindingsV1,
    _digest,
    _timestamp,
)
from .second_brain_security_contracts import (
    CapabilityReceiptV1,
    EgressPolicyV1,
    SourceConsentRetentionV1,
    require_resolved_security_context,
)


@dataclass(frozen=True)
class EgressAuthorizationRequest:
    """Opaque, pre-projected references needed for one egress decision."""

    data_class_ref: str
    provider_ref: str
    route_ref: str
    consent_ref: str
    capability_ref: str
    policy_digest: str
    receipt_intent_ref: str


@dataclass(frozen=True)
class EgressAuthorizationDecision:
    allowed: bool
    reason_code: str | None


_Result = TypeVar("_Result")


class LocalFirstEgressPolicy:
    """Fail-closed egress gate; denied requests cannot reach an external callable."""

    def __init__(
        self,
        policy: EgressPolicyV1 | None = None,
        consent: SourceConsentRetentionV1 | None = None,
        receipt: CapabilityReceiptV1 | None = None,
        *,
        resolution: ContractResolutionV1 | None = None,
        aggregate: SignedSecondBrainContractEnvelopeV1 | None = None,
        trusted_keys: TrustedDecisionKeyBindingsV1 | None = None,
    ) -> None:
        self.policy = policy
        self.consent = consent
        self.receipt = receipt
        self.resolution = resolution
        self.aggregate = aggregate
        self.trusted_keys = trusted_keys

    def authorize(self, request: EgressAuthorizationRequest, *, now: str) -> EgressAuthorizationDecision:
        """Return a decision without invoking or selecting a provider."""
        try:
            current = _timestamp(now, "now")
            for value, field in (
                (request.data_class_ref, "data_class_ref"),
                (request.provider_ref, "provider_ref"),
                (request.route_ref, "route_ref"),
                (request.consent_ref, "consent_ref"),
                (request.capability_ref, "capability_ref"),
                (request.receipt_intent_ref, "receipt_intent_ref"),
            ):
                if not isinstance(value, str) or not value:
                    raise InvalidContractValue(f"{field} is required")
            _digest(request.policy_digest, "policy_digest")
            if self.policy is None or self.consent is None or self.receipt is None:
                return EgressAuthorizationDecision(False, "local_only_default")
            require_resolved_security_context(
                self.resolution,
                self.aggregate,
                self.trusted_keys,
                scope_kind="external_model_route",
                scope_name=request.route_ref,
                now=current,
            )
        except Exception:
            return EgressAuthorizationDecision(False, "db06_route_unverified")

        if request.provider_ref != self.policy.destination_ref:
            return EgressAuthorizationDecision(False, "provider_not_allowed")
        if request.policy_digest != self.policy.policy_digest or self.consent.policy_digest != request.policy_digest:
            return EgressAuthorizationDecision(False, "policy_digest_mismatch")
        if request.consent_ref != self.consent.consent_ref or current >= _timestamp(self.consent.retention_until, "retention_until"):
            return EgressAuthorizationDecision(False, "consent_not_current")
        if request.capability_ref != self.receipt.capability_ref:
            return EgressAuthorizationDecision(False, "capability_mismatch")
        if request.receipt_intent_ref != self.receipt.receipt_ref:
            return EgressAuthorizationDecision(False, "receipt_intent_mismatch")
        # The policy and receipt must independently bind the exact class and route.
        if request.data_class_ref not in self.policy.allowed_scope_refs:
            return EgressAuthorizationDecision(False, "data_class_not_allowed")
        if request.route_ref not in self.policy.allowed_scope_refs:
            return EgressAuthorizationDecision(False, "route_not_allowed")
        if request.data_class_ref not in self.receipt.authorized_scope_refs or request.route_ref not in self.receipt.authorized_scope_refs:
            return EgressAuthorizationDecision(False, "capability_scope_mismatch")
        return EgressAuthorizationDecision(True, None)

    def invoke(
        self,
        request: EgressAuthorizationRequest,
        operation: Callable[[], _Result],
        *,
        now: str,
    ) -> _Result | None:
        """Invoke exactly one supplied operation only after authorization succeeds.

        No alternate route or fallback callable is accepted by this API.
        """
        if not self.authorize(request, now=now).allowed:
            return None
        return operation()
