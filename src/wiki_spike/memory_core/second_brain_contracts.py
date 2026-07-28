"""Immutable, storage-independent Stage-0 Second Brain contracts."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, ClassVar, Mapping, Sequence
from collections.abc import Callable
import re

from .contracts import canonical_bytes
from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion

DECISION_RECORD_VERSION = "second-brain-decision-record-v1"
RESOLVED_SCOPE_VERSION = "second-brain-resolved-scope-v1"
CONTRACT_DIGEST_VERSION = "second-brain-contract-digest-v1"
DECISION_IDS = frozenset({f"DB-{number:02d}" for number in range(1, 9)})
FATAL_DECISIONS = frozenset({"DB-01", "DB-04", "DB-05", "DB-07"})
SCOPED_DECISIONS = frozenset({"DB-02", "DB-03", "DB-06", "DB-08"})
_SCOPE_KIND_BY_DECISION = {
    "DB-02": "source_profile", "DB-03": "migration_source",
    "DB-06": "external_model_route", "DB-08": "export_destination",
}
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _strict(data: Mapping[str, Any], fields: set[str]) -> dict[str, Any]:
    unknown = set(data) - fields
    if unknown:
        raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    missing = fields - set(data)
    if missing:
        raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
    return dict(data)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty string")
    return value


def _digest(value: Any, field: str) -> str:
    value = _text(value, field)
    if not _DIGEST_RE.fullmatch(value):
        raise InvalidContractValue(f"{field} must be a lowercase SHA-256 digest")
    return value


def _string_list(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty array")
    values = tuple(_text(item, field) for item in value)
    if len(set(values)) != len(values) or tuple(sorted(values)) != values:
        raise InvalidContractValue(f"{field} must be sorted and unique")
    return values


def _timestamp(value: Any, field: str) -> datetime:
    text = _text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidContractValue(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise InvalidContractValue(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class DecisionRecordV1:
    decision_version: str
    decision_id: str
    outcome: str
    scope_kind: str
    scope_name: str | None
    reason: str
    evidence_refs: tuple[str, ...]
    evidence_digest: str
    signed_by: str
    signature: str
    expires_at: str

    FIELDS: ClassVar[set[str]] = {"decision_version", "decision_id", "outcome", "scope_kind", "scope_name", "reason", "evidence_refs", "evidence_digest", "signed_by", "signature", "expires_at"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, now: datetime | None = None) -> "DecisionRecordV1":
        values = _strict(data, cls.FIELDS)
        if values["decision_version"] != DECISION_RECORD_VERSION:
            raise UnsupportedContractVersion("unsupported decision_version")
        decision_id = _text(values["decision_id"], "decision_id")
        if decision_id not in DECISION_IDS:
            raise InvalidContractValue("unsupported decision_id")
        outcome = _text(values["outcome"], "outcome")
        if outcome not in {"GO", "NO_GO"}:
            raise InvalidContractValue("outcome must be GO or NO_GO")
        scope_kind = _text(values["scope_kind"], "scope_kind")
        scope_name = values["scope_name"]
        expected_scope = _SCOPE_KIND_BY_DECISION.get(decision_id, "global")
        if scope_kind != expected_scope:
            raise InvalidContractValue("scope_kind does not match decision_id")
        if expected_scope == "global":
            if scope_name is not None:
                raise InvalidContractValue("global decisions must have null scope_name")
            if outcome != "GO":
                raise InvalidContractValue("global decisions require GO")
        elif not isinstance(scope_name, str) or not scope_name:
            raise InvalidContractValue("scoped decisions require a scope_name")
        expires_at = _timestamp(values["expires_at"], "expires_at")
        current = now or datetime.now(timezone.utc)
        if expires_at <= current.astimezone(timezone.utc):
            raise InvalidContractValue("decision is expired")
        return cls(
            decision_version=values["decision_version"], decision_id=decision_id, outcome=outcome,
            scope_kind=scope_kind, scope_name=scope_name, reason=_text(values["reason"], "reason"),
            evidence_refs=_string_list(values["evidence_refs"], "evidence_refs"),
            evidence_digest=_digest(values["evidence_digest"], "evidence_digest"),
            signed_by=_text(values["signed_by"], "signed_by"), signature=_text(values["signature"], "signature"),
            expires_at=_text(values["expires_at"], "expires_at"),
        )

    @property
    def digest(self) -> str:
        return sha256(canonical_bytes(self.to_mapping())).hexdigest()

    def to_mapping(self) -> dict[str, Any]:
        return {"decision_version": self.decision_version, "decision_id": self.decision_id, "outcome": self.outcome, "scope_kind": self.scope_kind, "scope_name": self.scope_name, "reason": self.reason, "evidence_refs": list(self.evidence_refs), "evidence_digest": self.evidence_digest, "signed_by": self.signed_by, "signature": self.signature, "expires_at": self.expires_at}


@dataclass(frozen=True)
class ResolvedScopeV1:
    scope_version: str
    enabled_source_profiles: tuple[str, ...]
    disabled_source_profiles: tuple[tuple[str, str], ...]
    enabled_migration_sources: tuple[str, ...]
    disabled_migration_sources: tuple[tuple[str, str], ...]
    feature_flags: tuple[str, ...]
    egress_destinations: tuple[str, ...]
    disabled_external_model_routes: tuple[tuple[str, str], ...]
    disabled_export_destinations: tuple[tuple[str, str], ...]
    capability_manifest_digest: str
    source_manifest_digest: str
    mandatory_release_constraints: tuple[str, ...]

    FIELDS: ClassVar[set[str]] = {"scope_version", "enabled_source_profiles", "disabled_source_profiles", "enabled_migration_sources", "disabled_migration_sources", "feature_flags", "egress_destinations", "disabled_external_model_routes", "disabled_export_destinations", "capability_manifest_digest", "source_manifest_digest", "mandatory_release_constraints"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ResolvedScopeV1":
        values = _strict(data, cls.FIELDS)
        if values["scope_version"] != RESOLVED_SCOPE_VERSION:
            raise UnsupportedContractVersion("unsupported scope_version")
        def disabled(field: str) -> tuple[tuple[str, str], ...]:
            value = values[field]
            if not isinstance(value, list):
                raise InvalidContractValue(f"{field} must be an array")
            pairs: list[tuple[str, str]] = []
            for item in value:
                if not isinstance(item, Mapping) or set(item) != {"name", "reason"}:
                    raise InvalidContractValue(f"{field} entries require name and reason")
                pairs.append((_text(item["name"], f"{field}.name"), _text(item["reason"], f"{field}.reason")))
            result = tuple(pairs)
            if len(set(result)) != len(result) or tuple(sorted(result)) != result:
                raise InvalidContractValue(f"{field} must be sorted and unique")
            return result
        scope = cls(values["scope_version"], _string_list(values["enabled_source_profiles"], "enabled_source_profiles"), disabled("disabled_source_profiles"), _string_list(values["enabled_migration_sources"], "enabled_migration_sources"), disabled("disabled_migration_sources"), _string_list(values["feature_flags"], "feature_flags"), _string_list(values["egress_destinations"], "egress_destinations"), disabled("disabled_external_model_routes"), disabled("disabled_export_destinations"), _digest(values["capability_manifest_digest"], "capability_manifest_digest"), _digest(values["source_manifest_digest"], "source_manifest_digest"), _string_list(values["mandatory_release_constraints"], "mandatory_release_constraints"))
        for enabled, disabled_items, label in (
            (scope.enabled_source_profiles, scope.disabled_source_profiles, "source profile"),
            (scope.enabled_migration_sources, scope.disabled_migration_sources, "migration source"),
            (scope.egress_destinations, scope.disabled_export_destinations, "export destination"),
        ):
            overlap = set(enabled) & {name for name, _ in disabled_items}
            if overlap:
                raise InvalidContractValue(f"{label} cannot be both enabled and disabled: {sorted(overlap)}")
        return scope

    def to_mapping(self) -> dict[str, Any]:
        def disabled(values: tuple[tuple[str, str], ...]) -> list[dict[str, str]]:
            return [{"name": name, "reason": reason} for name, reason in values]
        return {"scope_version": self.scope_version, "enabled_source_profiles": list(self.enabled_source_profiles), "disabled_source_profiles": disabled(self.disabled_source_profiles), "enabled_migration_sources": list(self.enabled_migration_sources), "disabled_migration_sources": disabled(self.disabled_migration_sources), "feature_flags": list(self.feature_flags), "egress_destinations": list(self.egress_destinations), "disabled_external_model_routes": disabled(self.disabled_external_model_routes), "disabled_export_destinations": disabled(self.disabled_export_destinations), "capability_manifest_digest": self.capability_manifest_digest, "source_manifest_digest": self.source_manifest_digest, "mandatory_release_constraints": list(self.mandatory_release_constraints)}


@dataclass(frozen=True)
class SecondBrainContractDigestV1:
    contract_version: str
    decision_digests: tuple[tuple[str, str], ...]
    resolved_scope: ResolvedScopeV1
    digest: str

    @classmethod
    def create(cls, decisions: Sequence[DecisionRecordV1], scope: ResolvedScopeV1) -> "SecondBrainContractDigestV1":
        if {decision.decision_id for decision in decisions} != DECISION_IDS or len(decisions) != len(DECISION_IDS):
            raise InvalidContractValue("exactly one resolved decision is required for DB-01 through DB-08")
        bindings = tuple(sorted((decision.decision_id, decision.digest) for decision in decisions))
        body = {"contract_version": CONTRACT_DIGEST_VERSION, "decision_digests": [{"decision_id": decision_id, "digest": digest} for decision_id, digest in bindings], "resolved_scope": scope.to_mapping()}
        return cls(CONTRACT_DIGEST_VERSION, bindings, scope, sha256(canonical_bytes(body)).hexdigest())

    def to_mapping(self) -> dict[str, Any]:
        return {"contract_version": self.contract_version, "decision_digests": [{"decision_id": key, "digest": value} for key, value in self.decision_digests], "resolved_scope": self.resolved_scope.to_mapping(), "digest": self.digest}
def resolve_second_brain_contract(
    decisions: Sequence[DecisionRecordV1],
    scope: ResolvedScopeV1,
    *,
    verify_signature: Callable[[DecisionRecordV1], bool],
) -> SecondBrainContractDigestV1:
    """Verify each decision and bind its allowed scoped denial into ``scope``."""
    by_id = {decision.decision_id: decision for decision in decisions}
    if len(by_id) != len(decisions) or set(by_id) != DECISION_IDS:
        raise InvalidContractValue("exactly one decision is required for DB-01 through DB-08")
    for decision in decisions:
        if not verify_signature(decision):
            raise InvalidContractValue(f"invalid signature for {decision.decision_id}")
    disabled_by_kind = {
        "source_profile": dict(scope.disabled_source_profiles),
        "migration_source": dict(scope.disabled_migration_sources),
        "external_model_route": dict(scope.disabled_external_model_routes),
        "export_destination": dict(scope.disabled_export_destinations),
    }
    for decision_id in SCOPED_DECISIONS:
        decision = by_id[decision_id]
        disabled = disabled_by_kind[decision.scope_kind]
        if decision.outcome == "NO_GO":
            if disabled != {decision.scope_name: decision.reason}:
                raise InvalidContractValue(
                    f"{decision_id} NO_GO must disable exactly its named {decision.scope_kind}"
                )
        elif decision.scope_name in disabled:
            raise InvalidContractValue(f"{decision_id} GO cannot disable its named scope")
    return SecondBrainContractDigestV1.create(decisions, scope)
