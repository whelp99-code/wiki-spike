"""Local-first Stage-1 egress authorization with Core-owned receipts."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from secrets import token_urlsafe
from typing import Callable, TypeVar

from .contracts import canonical_bytes
from .errors import InvalidContractValue
from .second_brain_contracts import _canonical_utc_timestamp, _digest
from .second_brain_security_contracts import (
    CapabilityReceiptV1,
    EgressPolicyV1,
    SecurityContextAuthority,
    SourceConsentRetentionV1,
    require_security_context_authority,
)


_STORE_MINT = object()
_RECEIPT_MINT = object()


@dataclass(frozen=True)
class EgressAuthorizationRequest:
    """References needed for one egress decision; no authority is caller asserted."""

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


@dataclass(frozen=True)
class _StoredEgressReceipt:
    """Private store record; construction requires the module-private sentinel."""

    receipt_id: str
    policy_body: bytes
    consent_body: bytes
    capability_body: bytes
    policy_body_digest: str
    consent_body_digest: str
    capability_body_digest: str
    policy_revision: str
    retention_revision: str
    receipt_ref: str
    authority_body: bytes
    authority_body_digest: str
    external_model_route: str
    route_ref: str
    contract_digest: str

    @classmethod
    def mint(
        cls, mint: object, *, receipt_id: str, policy: EgressPolicyV1,
        consent: SourceConsentRetentionV1, capability: CapabilityReceiptV1,
        route_ref: str, external_model_route: str, contract_digest: str,
    ) -> "_StoredEgressReceipt":
        if mint is not _RECEIPT_MINT:
            raise InvalidContractValue("egress receipts must be minted by EgressAuthorityStore")
        policy_body = canonical_bytes(policy.to_mapping())
        consent_body = canonical_bytes(consent.to_mapping())
        capability_body = canonical_bytes(capability.to_mapping())
        authority_body = canonical_bytes(
            {
                "route_ref": route_ref,
                "external_model_route": external_model_route,
                "contract_digest": contract_digest,
            }
        )
        return cls(
            receipt_id, policy_body, consent_body, capability_body,
            sha256(policy_body).hexdigest(), sha256(consent_body).hexdigest(),
            sha256(capability_body).hexdigest(), policy.policy_revision,
            consent.retention_revision, capability.receipt_ref, authority_body,
            sha256(authority_body).hexdigest(), external_model_route, route_ref,
            contract_digest,
        )


class EgressAuthorityStore:
    """Concrete Core-owned storage for canonical egress authority records."""

    __slots__ = ("__authority", "__receipts", "__current_revisions")

    def __init__(self, mint: object, authority: SecurityContextAuthority) -> None:
        if mint is not _STORE_MINT:
            raise InvalidContractValue("EgressAuthorityStore must be minted by Core")
        self.__authority = authority
        self.__receipts: dict[str, _StoredEgressReceipt] = {}
        self.__current_revisions: dict[tuple[str, str], tuple[str, str]] = {}

    def mint_receipt(
        self, policy: EgressPolicyV1, consent: SourceConsentRetentionV1,
        capability: CapabilityReceiptV1, *, route_ref: str, external_model_route: str,
    ) -> str:
        """Persist parsed canonical bodies and return an opaque receipt identifier."""
        resolution = self.__authority.require(
            scope_kind="external_model_route", scope_name=external_model_route
        )
        assert resolution.contract is not None
        policy = EgressPolicyV1.from_mapping(policy.to_mapping())
        consent = SourceConsentRetentionV1.from_mapping(consent.to_mapping())
        capability = CapabilityReceiptV1.from_mapping(capability.to_mapping())
        if route_ref not in policy.allowed_scope_refs or route_ref not in capability.authorized_scope_refs:
            raise InvalidContractValue("egress receipt route is not authorized by policy and capability")
        if policy.policy_digest != consent.policy_digest:
            raise InvalidContractValue("policy and consent digests must match")
        receipt_id = token_urlsafe(32)
        record = _StoredEgressReceipt.mint(
            _RECEIPT_MINT, receipt_id=receipt_id, policy=policy, consent=consent,
            capability=capability, route_ref=route_ref,
            external_model_route=external_model_route, contract_digest=resolution.contract.digest,
        )
        self.__receipts[receipt_id] = record
        self.__current_revisions[(policy.policy_ref, consent.consent_ref)] = (
            policy.policy_revision, consent.retention_revision,
        )
        return receipt_id

    def _load_current(
        self, receipt_id: str, request: EgressAuthorizationRequest, *, now: datetime,
    ) -> tuple[EgressPolicyV1, SourceConsentRetentionV1, CapabilityReceiptV1] | None:
        record = self.__receipts.get(receipt_id)
        if record is None:
            return None
        # Verify persisted body integrity before reparsing the only records this gate trusts.
        if (
            sha256(record.policy_body).hexdigest() != record.policy_body_digest
            or sha256(record.consent_body).hexdigest() != record.consent_body_digest
            or sha256(record.capability_body).hexdigest() != record.capability_body_digest
            or sha256(record.authority_body).hexdigest() != record.authority_body_digest
        ):
            return None
        try:
            import json
            policy = EgressPolicyV1.from_mapping(json.loads(record.policy_body))
            consent = SourceConsentRetentionV1.from_mapping(json.loads(record.consent_body))
            capability = CapabilityReceiptV1.from_mapping(json.loads(record.capability_body), now=now)
            authority_body = json.loads(record.authority_body)
            if authority_body != {
                "route_ref": record.route_ref,
                "external_model_route": record.external_model_route,
                "contract_digest": record.contract_digest,
            }:
                return None
            if request.route_ref != record.route_ref:
                return None
            resolution = self.__authority.require(
                scope_kind="external_model_route", scope_name=record.external_model_route, now=now
            )
            if resolution.contract is None or resolution.contract.digest != record.contract_digest:
                return None
            if self.__current_revisions.get((policy.policy_ref, consent.consent_ref)) != (
                record.policy_revision, record.retention_revision,
            ):
                return None
            if capability.receipt_ref != record.receipt_ref:
                return None
        except (TypeError, ValueError, InvalidContractValue):
            return None
        return policy, consent, capability


def mint_egress_authority_store(authority: SecurityContextAuthority) -> EgressAuthorityStore:
    """Mint a concrete store only from an already-minted security authority."""
    require_security_context_authority(authority)
    return EgressAuthorityStore(_STORE_MINT, authority)


_Result = TypeVar("_Result")


class LocalFirstEgressPolicy:
    """Fail-closed egress gate; callers supply neither verifier nor authority result."""

    def __init__(
        self, *, authority: SecurityContextAuthority | None = None,
        store: EgressAuthorityStore | None = None, receipt_id: str | None = None,
    ) -> None:
        self.authority = authority
        self.__store = store
        self.__receipt_id = receipt_id

    def authorize(self, request: EgressAuthorizationRequest, *, now: str) -> EgressAuthorizationDecision:
        try:
            current = _canonical_utc_timestamp(now, "now")
            for value, field in (
                (request.data_class_ref, "data_class_ref"), (request.provider_ref, "provider_ref"),
                (request.route_ref, "route_ref"), (request.consent_ref, "consent_ref"),
                (request.capability_ref, "capability_ref"), (request.receipt_intent_ref, "receipt_intent_ref"),
            ):
                if not isinstance(value, str) or not value:
                    raise InvalidContractValue(f"{field} is required")
            _digest(request.policy_digest, "policy_digest")
            if not isinstance(self.__store, EgressAuthorityStore) or not isinstance(self.__receipt_id, str):
                return EgressAuthorizationDecision(False, "local_only_default")
            records = self.__store._load_current(self.__receipt_id, request, now=current)
            if records is None:
                return EgressAuthorizationDecision(False, "db06_route_unverified")
            policy, consent, receipt = records
            _canonical_utc_timestamp(consent.retention_until, "retention_until")
        except Exception:
            return EgressAuthorizationDecision(False, "db06_route_unverified")

        if request.provider_ref != policy.destination_ref:
            return EgressAuthorizationDecision(False, "provider_not_allowed")
        if request.policy_digest != policy.policy_digest or consent.policy_digest != request.policy_digest:
            return EgressAuthorizationDecision(False, "policy_digest_mismatch")
        if request.consent_ref != consent.consent_ref or current >= _canonical_utc_timestamp(consent.retention_until, "retention_until"):
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

    def invoke(self, request: EgressAuthorizationRequest, operation: Callable[[], _Result], *, now: str) -> _Result | None:
        if not self.authorize(request, now=now).allowed:
            return None
        return operation()
