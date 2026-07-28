"""Strict, inert Stage-1 security wire contracts for the Second Brain."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import re
from typing import Any, Callable, ClassVar, TypeVar

from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_contracts import (
    ContractResolutionV1,
    SignedSecondBrainContractEnvelopeV1,
    TrustedDecisionKeyBindingsV1,
    _digest,
    _names,
    _positive_decimal,
    _strict,
    _text,
    _timestamp,
)

SECURITY_FOUNDATION_VERSION = "second-brain-security-foundation-v1"
_KEYED_REF = re.compile(r"^[a-z][a-z0-9_-]{0,63}:[0-9a-f]{64}$")


def _ref(value: Any, field: str) -> str:
    value = _text(value, field)
    if _KEYED_REF.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a canonical keyed digest reference")
    return value


def _refs(value: Any, field: str, *, nonempty: bool = False) -> tuple[str, ...]:
    values = _names(value, field, nonempty=nonempty)
    parsed = tuple(_ref(item, field) for item in values)
    if parsed != tuple(sorted(parsed)) or len(set(parsed)) != len(parsed):
        raise InvalidContractValue(f"{field} must be sorted and unique")
    return parsed


def _wire(cls: type["SecurityWireV1"], data: Mapping[str, Any]) -> dict[str, Any]:
    values = _strict(data, cls.FIELDS)
    if values["security_version"] != SECURITY_FOUNDATION_VERSION:
        raise UnsupportedContractVersion("unsupported security_version")
    return values


@dataclass(frozen=True)
class SecurityWireV1:
    """Base for closed, canonical and transport-safe security records."""
    security_version: str
    FIELDS: ClassVar[set[str]] = {"security_version"}
    def to_mapping(self) -> dict[str, Any]:
        return {
            field.name: list(value) if isinstance(value := getattr(self, field.name), tuple) else value
            for field in fields(self)
        }


@dataclass(frozen=True)
class TrustRootV1(SecurityWireV1):
    trust_root_ref: str; root_revision: str; owner_key_ref: str; approver_key_ref: str; root_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "trust_root_ref", "root_revision", "owner_key_ref", "approver_key_ref", "root_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "TrustRootV1":
        v = _wire(cls, data); owner, approver = _ref(v["owner_key_ref"], "owner_key_ref"), _ref(v["approver_key_ref"], "approver_key_ref")
        if owner == approver: raise InvalidContractValue("owner_key_ref and approver_key_ref must differ")
        return cls(v["security_version"], _ref(v["trust_root_ref"], "trust_root_ref"), _positive_decimal(v["root_revision"], "root_revision"), owner, approver, _digest(v["root_digest"], "root_digest"))


@dataclass(frozen=True)
class DeviceEnrollmentV1(SecurityWireV1):
    enrollment_ref: str; device_key_ref: str; trust_root_ref: str; enrolled_at: str; expires_at: str; enrollment_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "enrollment_ref", "device_key_ref", "trust_root_ref", "enrolled_at", "expires_at", "enrollment_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, now: datetime | None = None) -> "DeviceEnrollmentV1":
        v = _wire(cls, data); enrolled, expires = _text(v["enrolled_at"], "enrolled_at"), _text(v["expires_at"], "expires_at")
        if _timestamp(expires, "expires_at") <= _timestamp(enrolled, "enrolled_at") or (now is not None and _timestamp(expires, "expires_at") <= now.astimezone(timezone.utc)): raise InvalidContractValue("device enrollment is expired or invalid")
        return cls(v["security_version"], _ref(v["enrollment_ref"], "enrollment_ref"), _ref(v["device_key_ref"], "device_key_ref"), _ref(v["trust_root_ref"], "trust_root_ref"), enrolled, expires, _digest(v["enrollment_digest"], "enrollment_digest"))


@dataclass(frozen=True)
class DelegatedReviewGrantV1(SecurityWireV1):
    grant_ref: str; grant_revision: str; grantor_key_ref: str; reviewer_key_ref: str; scope_refs: tuple[str, ...]; expires_at: str; grant_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "grant_ref", "grant_revision", "grantor_key_ref", "reviewer_key_ref", "scope_refs", "expires_at", "grant_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, now: datetime | None = None) -> "DelegatedReviewGrantV1":
        v = _wire(cls, data); expires = _text(v["expires_at"], "expires_at")
        if now is not None and _timestamp(expires, "expires_at") <= now.astimezone(timezone.utc): raise InvalidContractValue("delegated review grant is expired")
        return cls(v["security_version"], _ref(v["grant_ref"], "grant_ref"), _positive_decimal(v["grant_revision"], "grant_revision"), _ref(v["grantor_key_ref"], "grantor_key_ref"), _ref(v["reviewer_key_ref"], "reviewer_key_ref"), _refs(v["scope_refs"], "scope_refs", nonempty=True), expires, _digest(v["grant_digest"], "grant_digest"))


@dataclass(frozen=True)
class CapabilityRequestV1(SecurityWireV1):
    request_ref: str; capability_ref: str; subject_key_ref: str; scope_refs: tuple[str, ...]; requested_at: str; request_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "request_ref", "capability_ref", "subject_key_ref", "scope_refs", "requested_at", "request_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CapabilityRequestV1":
        v = _wire(cls, data); requested = _text(v["requested_at"], "requested_at"); _timestamp(requested, "requested_at")
        return cls(v["security_version"], _ref(v["request_ref"], "request_ref"), _ref(v["capability_ref"], "capability_ref"), _ref(v["subject_key_ref"], "subject_key_ref"), _refs(v["scope_refs"], "scope_refs", nonempty=True), requested, _digest(v["request_digest"], "request_digest"))


@dataclass(frozen=True)
class CapabilityReceiptV1(SecurityWireV1):
    receipt_ref: str; request_ref: str; capability_ref: str; authorized_scope_refs: tuple[str, ...]; issued_at: str; expires_at: str; receipt_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "receipt_ref", "request_ref", "capability_ref", "authorized_scope_refs", "issued_at", "expires_at", "receipt_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, now: datetime | None = None) -> "CapabilityReceiptV1":
        v = _wire(cls, data); issued, expires = _text(v["issued_at"], "issued_at"), _text(v["expires_at"], "expires_at")
        if _timestamp(expires, "expires_at") <= _timestamp(issued, "issued_at") or (now is not None and _timestamp(expires, "expires_at") <= now.astimezone(timezone.utc)): raise InvalidContractValue("capability receipt is expired or invalid")
        return cls(v["security_version"], _ref(v["receipt_ref"], "receipt_ref"), _ref(v["request_ref"], "request_ref"), _ref(v["capability_ref"], "capability_ref"), _refs(v["authorized_scope_refs"], "authorized_scope_refs", nonempty=True), issued, expires, _digest(v["receipt_digest"], "receipt_digest"))


@dataclass(frozen=True)
class CredentialLeaseRequestV1(SecurityWireV1):
    lease_request_ref: str; credential_ref: str; capability_receipt_ref: str; lease_duration_seconds: str; requested_at: str; request_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "lease_request_ref", "credential_ref", "capability_receipt_ref", "lease_duration_seconds", "requested_at", "request_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CredentialLeaseRequestV1":
        v = _wire(cls, data); requested = _text(v["requested_at"], "requested_at"); _timestamp(requested, "requested_at")
        return cls(v["security_version"], _ref(v["lease_request_ref"], "lease_request_ref"), _ref(v["credential_ref"], "credential_ref"), _ref(v["capability_receipt_ref"], "capability_receipt_ref"), _positive_decimal(v["lease_duration_seconds"], "lease_duration_seconds"), requested, _digest(v["request_digest"], "request_digest"))


@dataclass(frozen=True)
class SourceConsentRetentionV1(SecurityWireV1):
    source_ref: str; consent_ref: str; retention_revision: str; retention_until: str; deletion_recovery_map_ref: str; policy_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "source_ref", "consent_ref", "retention_revision", "retention_until", "deletion_recovery_map_ref", "policy_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SourceConsentRetentionV1":
        v = _wire(cls, data); retention = _text(v["retention_until"], "retention_until"); _timestamp(retention, "retention_until")
        return cls(v["security_version"], _ref(v["source_ref"], "source_ref"), _ref(v["consent_ref"], "consent_ref"), _positive_decimal(v["retention_revision"], "retention_revision"), retention, _ref(v["deletion_recovery_map_ref"], "deletion_recovery_map_ref"), _digest(v["policy_digest"], "policy_digest"))


@dataclass(frozen=True)
class EgressPolicyV1(SecurityWireV1):
    policy_ref: str; policy_revision: str; destination_ref: str; allowed_scope_refs: tuple[str, ...]; policy_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "policy_ref", "policy_revision", "destination_ref", "allowed_scope_refs", "policy_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "EgressPolicyV1":
        v = _wire(cls, data)
        return cls(v["security_version"], _ref(v["policy_ref"], "policy_ref"), _positive_decimal(v["policy_revision"], "policy_revision"), _ref(v["destination_ref"], "destination_ref"), _refs(v["allowed_scope_refs"], "allowed_scope_refs", nonempty=True), _digest(v["policy_digest"], "policy_digest"))


@dataclass(frozen=True)
class TelemetryAllowlistV1(SecurityWireV1):
    allowlist_ref: str; allowlist_revision: str; event_type_refs: tuple[str, ...]; field_digest_refs: tuple[str, ...]; allowlist_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "allowlist_ref", "allowlist_revision", "event_type_refs", "field_digest_refs", "allowlist_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "TelemetryAllowlistV1":
        v = _wire(cls, data)
        return cls(v["security_version"], _ref(v["allowlist_ref"], "allowlist_ref"), _positive_decimal(v["allowlist_revision"], "allowlist_revision"), _refs(v["event_type_refs"], "event_type_refs", nonempty=True), _refs(v["field_digest_refs"], "field_digest_refs"), _digest(v["allowlist_digest"], "allowlist_digest"))


@dataclass(frozen=True)
class SourceFixtureManifestV1(SecurityWireV1):
    manifest_ref: str; fixture_revision: str; source_fixture_refs: tuple[str, ...]; manifest_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "manifest_ref", "fixture_revision", "source_fixture_refs", "manifest_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SourceFixtureManifestV1":
        v = _wire(cls, data)
        return cls(v["security_version"], _ref(v["manifest_ref"], "manifest_ref"), _positive_decimal(v["fixture_revision"], "fixture_revision"), _refs(v["source_fixture_refs"], "source_fixture_refs", nonempty=True), _digest(v["manifest_digest"], "manifest_digest"))


@dataclass(frozen=True)
class SourceDeletionRecoveryMapV1(SecurityWireV1):
    map_ref: str; map_revision: str; source_ref: str; deletion_ref: str; recovery_proof_ref: str; map_digest: str
    FIELDS: ClassVar[set[str]] = {"security_version", "map_ref", "map_revision", "source_ref", "deletion_ref", "recovery_proof_ref", "map_digest"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SourceDeletionRecoveryMapV1":
        v = _wire(cls, data)
        return cls(v["security_version"], _ref(v["map_ref"], "map_ref"), _positive_decimal(v["map_revision"], "map_revision"), _ref(v["source_ref"], "source_ref"), _ref(v["deletion_ref"], "deletion_ref"), _ref(v["recovery_proof_ref"], "recovery_proof_ref"), _digest(v["map_digest"], "map_digest"))


def require_resolved_security_context(resolution: ContractResolutionV1 | None, aggregate: SignedSecondBrainContractEnvelopeV1 | None, trusted_keys: TrustedDecisionKeyBindingsV1 | None, *, feature: str | None = None, scope_kind: str | None = None, scope_name: str | None = None, now: datetime | None = None) -> ContractResolutionV1:
    """Fail closed before a Stage-1 port call; never grants a capability."""
    if resolution is None or resolution.outcome != "RESOLVED" or resolution.contract is None or resolution.blocked_decisions:
        raise InvalidContractValue("a RESOLVED Stage-0 security context is required")
    if aggregate is None or trusted_keys is None:
        raise InvalidContractValue("verified Stage-0 aggregate and trusted keys are required")
    contract = resolution.contract
    reparsed = type(contract).from_mapping(contract.body(), digest=contract.digest)
    envelope = SignedSecondBrainContractEnvelopeV1.from_mapping(aggregate.to_mapping())
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if envelope.contract != reparsed or not envelope.verify(trusted_keys):
        raise InvalidContractValue("Stage-0 aggregate verification failed")
    if feature is not None and feature not in reparsed.resolved_scope.feature_flags:
        raise InvalidContractValue("Stage-0 feature scope is disabled")
    enabled = {"source_profile": reparsed.resolved_scope.enabled_source_profiles, "migration_source": reparsed.resolved_scope.enabled_migration_sources, "external_model_route": reparsed.resolved_scope.enabled_external_model_routes, "export_destination": reparsed.resolved_scope.egress_destinations}
    if scope_kind is not None and (scope_name is None or scope_name not in enabled.get(scope_kind, ())):
        raise InvalidContractValue("Stage-0 named scope is disabled")
    return resolution
_Result = TypeVar("_Result")


_AUTHORITY_MINT = object()


class SecurityContextAuthority:
    """Opaque, revalidating authority for Stage-1 security operations."""

    __slots__ = ("__resolution", "__aggregate", "__trusted_keys")

    def __init__(
        self,
        mint: object,
        resolution: ContractResolutionV1,
        aggregate: SignedSecondBrainContractEnvelopeV1,
        trusted_keys: TrustedDecisionKeyBindingsV1,
    ) -> None:
        if mint is not _AUTHORITY_MINT:
            raise InvalidContractValue("SecurityContextAuthority must be minted")
        self.__resolution = resolution
        self.__aggregate = aggregate
        self.__trusted_keys = trusted_keys

    def require(self, **scope: Any) -> ContractResolutionV1:
        """Revalidate the complete Stage-0 evidence for every protected operation."""
        return require_resolved_security_context(
            self.__resolution, self.__aggregate, self.__trusted_keys, **scope
        )


def mint_security_context_authority(
    resolution: ContractResolutionV1 | None,
    aggregate: SignedSecondBrainContractEnvelopeV1 | None,
    trusted_keys: TrustedDecisionKeyBindingsV1 | None,
) -> SecurityContextAuthority:
    """Mint opaque authority only after validating current Stage-0 evidence."""
    require_resolved_security_context(resolution, aggregate, trusted_keys)
    assert resolution is not None and aggregate is not None and trusted_keys is not None
    return SecurityContextAuthority(_AUTHORITY_MINT, resolution, aggregate, trusted_keys)


def require_security_context_authority(authority: object, **scope: Any) -> SecurityContextAuthority:
    if not isinstance(authority, SecurityContextAuthority):
        raise InvalidContractValue("a minted SecurityContextAuthority is required")
    authority.require(**scope)
    return authority


def invoke_with_resolved_security_context(
    operation: Callable[[], _Result],
    resolution: ContractResolutionV1 | None,
    aggregate: SignedSecondBrainContractEnvelopeV1 | None,
    trusted_keys: TrustedDecisionKeyBindingsV1 | None,
    **scope: Any,
) -> _Result:
    """Compatibility helper that mints and immediately uses opaque authority."""
    mint_security_context_authority(resolution, aggregate, trusted_keys).require(**scope)
    return operation()
