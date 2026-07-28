"""Local-first Stage-1 egress authorization with no provider fallback.

This module only decides whether an already-configured external operation may be
invoked.  It neither resolves providers nor performs network I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Protocol, TypeVar

from .errors import InvalidContractValue
from .second_brain_contracts import _digest, _timestamp
from .second_brain_security_contracts import (
    CapabilityReceiptV1,
    EgressPolicyV1,
    SecurityContextAuthority,
    SourceConsentRetentionV1,
    require_security_context_authority,
)


class TrustedEgressReceiptVerifier(Protocol):
    """Trusted boundary which loads and digest-verifies current egress records."""

    def verify_current(
        self, request: "EgressAuthorizationRequest", *, now: datetime,
    ) -> tuple[EgressPolicyV1, SourceConsentRetentionV1, CapabilityReceiptV1] | None: ...


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
        authority: SecurityContextAuthority | None = None,
        trusted_verifier: TrustedEgressReceiptVerifier | None = None,
        resolution: object | None = None,
        aggregate: object | None = None,
        trusted_keys: object | None = None,
    ) -> None:
        # Caller-supplied records and raw Stage-0 evidence are deliberately inert:
        # only a minted authority plus a trusted, digest-verifying resolver can grant.
        self.authority = authority
        self.trusted_verifier = trusted_verifier

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
            if self.trusted_verifier is None:
                return EgressAuthorizationDecision(False, "local_only_default")
            require_security_context_authority(
                self.authority,
                scope_kind="external_model_route",
                scope_name=request.route_ref,
                now=current,
            )
            records = self.trusted_verifier.verify_current(request, now=current)
            if records is None:
                return EgressAuthorizationDecision(False, "db06_route_unverified")
            policy, consent, receipt = records
            # Treat verifier output as wire data too: direct forged dataclasses cannot
            # bypass strict Stage-1 parsing at this authorization boundary.
            policy = EgressPolicyV1.from_mapping(policy.to_mapping())
            consent = SourceConsentRetentionV1.from_mapping(consent.to_mapping())
            receipt = CapabilityReceiptV1.from_mapping(receipt.to_mapping(), now=current)
        except Exception:
            return EgressAuthorizationDecision(False, "db06_route_unverified")

        if request.provider_ref != policy.destination_ref:
            return EgressAuthorizationDecision(False, "provider_not_allowed")
        if request.policy_digest != policy.policy_digest or consent.policy_digest != request.policy_digest:
            return EgressAuthorizationDecision(False, "policy_digest_mismatch")
        if request.consent_ref != consent.consent_ref or current >= _timestamp(consent.retention_until, "retention_until"):
            return EgressAuthorizationDecision(False, "consent_not_current")
        if request.capability_ref != receipt.capability_ref:
            return EgressAuthorizationDecision(False, "capability_mismatch")
        if request.receipt_intent_ref != receipt.receipt_ref:
            return EgressAuthorizationDecision(False, "receipt_intent_mismatch")
        if request.data_class_ref not in policy.allowed_scope_refs:
            return EgressAuthorizationDecision(False, "data_class_not_allowed")
        if request.route_ref not in policy.allowed_scope_refs:
            return EgressAuthorizationDecision(False, "route_not_allowed")
        if request.data_class_ref not in receipt.authorized_scope_refs or request.route_ref not in receipt.authorized_scope_refs:
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
