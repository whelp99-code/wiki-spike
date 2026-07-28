"""Immutable, fail-closed Stage-0 Second Brain decision contracts."""
from __future__ import annotations

from base64 import b64decode
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import re
from typing import Any, ClassVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical_bytes
from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion

DECISION_RECORD_VERSION = "second-brain-decision-record-v1"
RESOLVED_SCOPE_VERSION = "second-brain-resolved-scope-v1"
EXPECTED_SCOPE_MANIFEST_VERSION = "second-brain-expected-scope-manifest-v1"
CONTRACT_DIGEST_VERSION = "second-brain-contract-digest-v1"
CONTRACT_ENVELOPE_VERSION = "second-brain-contract-envelope-v1"
DECISION_SIGNATURE_VERSION = "second-brain-decision-signature-v1"
CONTRACT_SIGNATURE_VERSION = "second-brain-contract-signature-v1"
DECISION_SIGNING_DOMAIN = b"wiki-spike.second-brain.decision.v1\x00"
CONTRACT_SIGNING_DOMAIN = b"wiki-spike.second-brain.contract.v1\x00"
DECISION_IDS = frozenset({f"DB-{number:02d}" for number in range(1, 9)})
FATAL_DECISIONS = frozenset({"DB-01", "DB-04", "DB-05", "DB-07"})
SCOPED_DECISIONS = frozenset({"DB-02", "DB-03", "DB-06", "DB-08"})
_SCOPE_KIND_BY_DECISION = {"DB-02": "source_profile", "DB-03": "migration_source", "DB-06": "external_model_route", "DB-08": "export_destination"}
_REQUIRED_SCOPE_INVENTORY = {
    "DB-02": frozenset({"Codex", "Claude/Memory Bank", "Git", "Markdown"}),
    "DB-03": frozenset({"unified-db", "legacy Mem0/RAG", "me-wiki"}),
}
_FEATURE_BY_GLOBAL_DECISION = {
    "DB-01": "identity-auth",
    "DB-04": "conflict-behavior",
    "DB-05": "benchmark-governance",
    "DB-07": "cutover-retention",
}
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _strict(data: Mapping[str, Any], fields: set[str]) -> dict[str, Any]:
    unknown, missing = set(data) - fields, fields - set(data)
    if unknown: raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    if missing: raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
    return dict(data)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value: raise InvalidContractValue(f"{field} must be a non-empty string")
    return value


def _positive_decimal(value: Any, field: str) -> str:
    value = _text(value, field)
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise InvalidContractValue(f"{field} must be a canonical positive decimal string")
    return value


def _digest(value: Any, field: str) -> str:
    value = _text(value, field)
    if not _DIGEST_RE.fullmatch(value): raise InvalidContractValue(f"{field} must be a lowercase SHA-256 digest")
    return value


def _names(value: Any, field: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list): raise InvalidContractValue(f"{field} must be an array")
    names = tuple(_text(item, field) for item in value)
    if (nonempty and not names) or tuple(sorted(names)) != names or len(set(names)) != len(names): raise InvalidContractValue(f"{field} must be {'non-empty, ' if nonempty else ''}sorted and unique")
    return names


def _timestamp(value: Any, field: str) -> datetime:
    try: parsed = datetime.fromisoformat(_text(value, field).replace("Z", "+00:00"))
    except ValueError as exc: raise InvalidContractValue(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None: raise InvalidContractValue(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)
def _canonical_utc_timestamp(value: Any, field: str) -> datetime:
    """Parse only the canonical UTC wire representation used by Stage-1 state."""
    value = _text(value, field)
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
        raise InvalidContractValue(f"{field} must be a canonical UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise InvalidContractValue(f"{field} must be a canonical UTC timestamp") from exc


def _signature_bytes(value: Any, field: str) -> bytes:
    try: result = b64decode(_text(value, field), validate=True)
    except ValueError as exc: raise InvalidContractValue(f"{field} must be base64") from exc
    if len(result) != 64: raise InvalidContractValue(f"{field} must be an Ed25519 signature")
    return result


def detached_signing_bytes(domain: bytes, payload: Mapping[str, Any]) -> bytes:
    return domain + canonical_bytes(payload)


@dataclass(frozen=True)
class Ed25519SignatureEnvelopeV1:
    signature_version: str; role: str; key_id: str; public_key_b64: str; signature_b64: str
    FIELDS: ClassVar[set[str]] = {"signature_version", "role", "key_id", "public_key_b64", "signature_b64"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, version: str) -> "Ed25519SignatureEnvelopeV1":
        values = _strict(data, cls.FIELDS)
        if values["signature_version"] != version: raise UnsupportedContractVersion("unsupported signature_version")
        role = _text(values["role"], "role")
        if role not in {"owner", "approver"}: raise InvalidContractValue("signature role must be owner or approver")
        try:
            raw = b64decode(_text(values["public_key_b64"], "public_key_b64"), validate=True); Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc: raise InvalidContractValue("public_key_b64 must contain an Ed25519 public key") from exc
        _signature_bytes(values["signature_b64"], "signature_b64")
        return cls(values["signature_version"], role, _text(values["key_id"], "key_id"), values["public_key_b64"], values["signature_b64"])
    def to_mapping(self) -> dict[str, str]:
        return {"signature_version": self.signature_version, "role": self.role, "key_id": self.key_id, "public_key_b64": self.public_key_b64, "signature_b64": self.signature_b64}
    def verify(self, domain: bytes, payload: Mapping[str, Any]) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(b64decode(self.public_key_b64, validate=True)).verify(_signature_bytes(self.signature_b64, "signature_b64"), detached_signing_bytes(domain, payload)); return True
        except (InvalidSignature, ValueError, InvalidContractValue): return False


def _signature_set(value: Any, *, version: str) -> tuple[Ed25519SignatureEnvelopeV1, ...]:
    if not isinstance(value, list): raise InvalidContractValue("signatures must be an array")
    signatures = tuple(Ed25519SignatureEnvelopeV1.from_mapping(item, version=version) for item in value if isinstance(item, Mapping))
    if len(signatures) != 2 or len(signatures) != len(value): raise InvalidContractValue("signatures require exactly owner and approver envelopes")
    if tuple(item.role for item in signatures) != ("approver", "owner"): raise InvalidContractValue("signatures must be canonically ordered as approver then owner")
    if signatures[0].key_id == signatures[1].key_id or signatures[0].public_key_b64 == signatures[1].public_key_b64: raise InvalidContractValue("owner and approver must have distinct key identities and public keys")
    return signatures


@dataclass(frozen=True)
class TrustedAuthorityBindingsV1:
    """One out-of-band owner/approver authority pair."""
    approver_key_id: str; approver_public_key_b64: str; owner_key_id: str; owner_public_key_b64: str
    def matches(self, signature: Ed25519SignatureEnvelopeV1) -> bool:
        return ((signature.role == "approver" and (signature.key_id, signature.public_key_b64) == (self.approver_key_id, self.approver_public_key_b64)) or (signature.role == "owner" and (signature.key_id, signature.public_key_b64) == (self.owner_key_id, self.owner_public_key_b64)))


@dataclass(frozen=True)
class TrustedDecisionKeyBindingsV1:
    """Out-of-band authority indexed by each exact decision identity and aggregate policy."""
    decision_bindings: Mapping[tuple[str, str, str | None], TrustedAuthorityBindingsV1]
    aggregate_bindings: TrustedAuthorityBindingsV1

    def __post_init__(self) -> None:
        bindings = dict(self.decision_bindings)
        for decision_id, scope_kind, scope_name in bindings:
            expected_kind = _SCOPE_KIND_BY_DECISION.get(decision_id, "global")
            if decision_id not in DECISION_IDS or scope_kind != expected_kind or ((scope_kind == "global") != (scope_name is None)):
                raise InvalidContractValue("trusted decision binding has an invalid decision scope identity")
        object.__setattr__(self, "decision_bindings", bindings)

    def matches_decision(self, decision: "DecisionRecordV1", signature: Ed25519SignatureEnvelopeV1) -> bool:
        return (binding := self.decision_bindings.get((decision.decision_id, decision.scope_kind, decision.scope_name))) is not None and binding.matches(signature)

    def matches_aggregate(self, signature: Ed25519SignatureEnvelopeV1) -> bool:
        return self.aggregate_bindings.matches(signature)

@dataclass(frozen=True)
class DecisionRecordV1:
    decision_version: str; decision_id: str; outcome: str; scope_kind: str; scope_name: str | None; record_revision: str; decided_at: str; supersedes: tuple[str, str, str | None, str, str] | None; post_interview_reconciliation: tuple[str, str]; reason: str; evidence_refs: tuple[str, ...]; evidence_digest: str; expires_at: str; signatures: tuple[Ed25519SignatureEnvelopeV1, ...]
    FIELDS: ClassVar[set[str]] = {"decision_version", "decision_id", "outcome", "scope_kind", "scope_name", "record_revision", "decided_at", "supersedes", "post_interview_reconciliation", "reason", "evidence_refs", "evidence_digest", "expires_at", "signatures"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, now: datetime | None = None) -> "DecisionRecordV1":
        v = _strict(data, cls.FIELDS)
        if v["decision_version"] != DECISION_RECORD_VERSION: raise UnsupportedContractVersion("unsupported decision_version")
        decision_id, outcome = _text(v["decision_id"], "decision_id"), _text(v["outcome"], "outcome")
        if decision_id not in DECISION_IDS or outcome not in {"GO", "NO_GO"}: raise InvalidContractValue("unsupported decision_id or outcome")
        kind = _SCOPE_KIND_BY_DECISION.get(decision_id, "global")
        if _text(v["scope_kind"], "scope_kind") != kind: raise InvalidContractValue("scope_kind does not match decision_id")
        name = v["scope_name"]
        if (kind == "global" and name is not None) or (kind != "global" and (not isinstance(name, str) or not name)): raise InvalidContractValue("global decisions require null scope_name; scoped decisions require a scope_name")
        revision = _positive_decimal(v["record_revision"], "record_revision")
        revision_number = int(revision)
        decided_at = _text(v["decided_at"], "decided_at"); _timestamp(decided_at, "decided_at")
        reconciliation = v["post_interview_reconciliation"]
        if not isinstance(reconciliation, Mapping): raise InvalidContractValue("post_interview_reconciliation must be an object")
        reconciliation = _strict(reconciliation, {"original_question", "reconciliation"})
        post_interview_reconciliation = (_text(reconciliation["original_question"], "post_interview_reconciliation.original_question"), _text(reconciliation["reconciliation"], "post_interview_reconciliation.reconciliation"))
        supersedes_raw = v["supersedes"]
        if revision_number == 1:
            if supersedes_raw is not None: raise InvalidContractValue("initial record_revision must not supersede another record")
            supersedes = None
        else:
            if not isinstance(supersedes_raw, Mapping): raise InvalidContractValue("superseding record requires supersedes linkage")
            prior = _strict(supersedes_raw, {"decision_id", "scope_kind", "scope_name", "record_revision", "decision_digest"})
            prior_revision = _positive_decimal(prior["record_revision"], "supersedes.record_revision")
            if prior["decision_id"] != decision_id or prior["scope_kind"] != kind or prior["scope_name"] != name or int(prior_revision) != revision_number - 1:
                raise InvalidContractValue("supersedes must link the immediately prior record for the same decision scope")
            supersedes = (decision_id, kind, name, prior_revision, _digest(prior["decision_digest"], "supersedes.decision_digest"))
        if now is not None and _timestamp(v["expires_at"], "expires_at") <= now.astimezone(timezone.utc): raise InvalidContractValue("decision is expired")
        return cls(v["decision_version"], decision_id, outcome, kind, name, revision, decided_at, supersedes, post_interview_reconciliation, _text(v["reason"], "reason"), _names(v["evidence_refs"], "evidence_refs", nonempty=True), _digest(v["evidence_digest"], "evidence_digest"), _text(v["expires_at"], "expires_at"), _signature_set(v["signatures"], version=DECISION_SIGNATURE_VERSION))
    def signing_payload(self) -> dict[str, Any]:
        result = self.to_mapping(); del result["signatures"]; return result
    @property
    def digest(self) -> str: return sha256(canonical_bytes(self.to_mapping())).hexdigest()
    def to_mapping(self) -> dict[str, Any]:
        supersedes = None if self.supersedes is None else {"decision_id": self.supersedes[0], "scope_kind": self.supersedes[1], "scope_name": self.supersedes[2], "record_revision": self.supersedes[3], "decision_digest": self.supersedes[4]}
        return {"decision_version": self.decision_version, "decision_id": self.decision_id, "outcome": self.outcome, "scope_kind": self.scope_kind, "scope_name": self.scope_name, "record_revision": self.record_revision, "decided_at": self.decided_at, "supersedes": supersedes, "post_interview_reconciliation": {"original_question": self.post_interview_reconciliation[0], "reconciliation": self.post_interview_reconciliation[1]}, "reason": self.reason, "evidence_refs": list(self.evidence_refs), "evidence_digest": self.evidence_digest, "expires_at": self.expires_at, "signatures": [x.to_mapping() for x in self.signatures]}


@dataclass(frozen=True)
class ExpectedScopeManifestV1:
    expected_scopes: tuple[tuple[str, str, str], ...]
    FIELDS: ClassVar[set[str]] = {"manifest_version", "expected_scopes"}

    @classmethod
    def from_tuples(cls, scopes: Sequence[tuple[str, str, str]]) -> "ExpectedScopeManifestV1":
        items = tuple(scopes)
        if tuple(sorted(items)) != items or len(set(items)) != len(items) or any(d not in SCOPED_DECISIONS or _SCOPE_KIND_BY_DECISION[d] != k or not isinstance(n, str) or not n for d, k, n in items): raise InvalidContractValue("expected scope manifest contains invalid or noncanonical scopes")
        for decision_id, required_names in _REQUIRED_SCOPE_INVENTORY.items():
            actual_names = {name for decision, _, name in items if decision == decision_id}
            if actual_names != required_names: raise InvalidContractValue(f"{decision_id} required inventory must be exact")
        if not all(any(decision == decision_id for decision, _, _ in items) for decision_id in ("DB-06", "DB-08")):
            raise InvalidContractValue("DB-06 and DB-08 require explicit configured signed scopes")
        return cls(items)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ExpectedScopeManifestV1":
        values = _strict(data, cls.FIELDS)
        if values["manifest_version"] != EXPECTED_SCOPE_MANIFEST_VERSION: raise UnsupportedContractVersion("unsupported manifest_version")
        entries = values["expected_scopes"]
        if not isinstance(entries, list): raise InvalidContractValue("expected_scopes must be an array")
        scopes: list[tuple[str, str, str]] = []
        for entry in entries:
            if not isinstance(entry, Mapping): raise InvalidContractValue("expected_scopes entries must be objects")
            item = _strict(entry, {"decision_id", "scope_kind", "scope_name"})
            scopes.append((_text(item["decision_id"], "decision_id"), _text(item["scope_kind"], "scope_kind"), _text(item["scope_name"], "scope_name")))
        return cls.from_tuples(scopes)

    def to_mapping(self) -> dict[str, Any]:
        return {"manifest_version": EXPECTED_SCOPE_MANIFEST_VERSION, "expected_scopes": [{"decision_id": d, "scope_kind": k, "scope_name": n} for d, k, n in self.expected_scopes]}
    @property
    def digest(self) -> str: return sha256(canonical_bytes(self.to_mapping())).hexdigest()


@dataclass(frozen=True)
class ResolvedScopeV1:
    scope_version: str; enabled_source_profiles: tuple[str, ...]; disabled_source_profiles: tuple[tuple[str, str], ...]; enabled_migration_sources: tuple[str, ...]; disabled_migration_sources: tuple[tuple[str, str], ...]; feature_flags: tuple[str, ...]; egress_destinations: tuple[str, ...]; enabled_external_model_routes: tuple[str, ...]; disabled_external_model_routes: tuple[tuple[str, str], ...]; disabled_export_destinations: tuple[tuple[str, str], ...]; capability_manifest_digest: str; source_manifest_digest: str; mandatory_release_constraints: tuple[str, ...]
    FIELDS: ClassVar[set[str]] = {"scope_version", "enabled_source_profiles", "disabled_source_profiles", "enabled_migration_sources", "disabled_migration_sources", "feature_flags", "egress_destinations", "enabled_external_model_routes", "disabled_external_model_routes", "disabled_export_destinations", "capability_manifest_digest", "source_manifest_digest", "mandatory_release_constraints"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ResolvedScopeV1":
        v = _strict(data, cls.FIELDS)
        if v["scope_version"] != RESOLVED_SCOPE_VERSION: raise UnsupportedContractVersion("unsupported scope_version")
        def disabled(field: str) -> tuple[tuple[str, str], ...]:
            value = v[field]
            if not isinstance(value, Mapping): raise InvalidContractValue(f"{field} must be an object mapping names to reasons")
            pairs = tuple(sorted((_text(name, f"{field}.name"), _text(reason, f"{field}.reason")) for name, reason in value.items()))
            if len(pairs) != len(value): raise InvalidContractValue(f"{field} must have unique names")
            return pairs
        scope = cls(v["scope_version"], _names(v["enabled_source_profiles"], "enabled_source_profiles"), disabled("disabled_source_profiles"), _names(v["enabled_migration_sources"], "enabled_migration_sources"), disabled("disabled_migration_sources"), _names(v["feature_flags"], "feature_flags"), _names(v["egress_destinations"], "egress_destinations"), _names(v["enabled_external_model_routes"], "enabled_external_model_routes"), disabled("disabled_external_model_routes"), disabled("disabled_export_destinations"), _digest(v["capability_manifest_digest"], "capability_manifest_digest"), _digest(v["source_manifest_digest"], "source_manifest_digest"), _names(v["mandatory_release_constraints"], "mandatory_release_constraints", nonempty=True))
        if not set(scope.feature_flags) <= set(_FEATURE_BY_GLOBAL_DECISION.values()): raise InvalidContractValue("feature_flags contains an unknown feature")
        for enabled, off, label in ((scope.enabled_source_profiles, scope.disabled_source_profiles, "source profile"), (scope.enabled_migration_sources, scope.disabled_migration_sources, "migration source"), (scope.enabled_external_model_routes, scope.disabled_external_model_routes, "external model route"), (scope.egress_destinations, scope.disabled_export_destinations, "export destination")):
            if set(enabled) & dict(off).keys(): raise InvalidContractValue(f"{label} cannot be both enabled and disabled")
        return scope
    def to_mapping(self) -> dict[str, Any]:
        return {"scope_version": self.scope_version, "enabled_source_profiles": list(self.enabled_source_profiles), "disabled_source_profiles": dict(self.disabled_source_profiles), "enabled_migration_sources": list(self.enabled_migration_sources), "disabled_migration_sources": dict(self.disabled_migration_sources), "feature_flags": list(self.feature_flags), "egress_destinations": list(self.egress_destinations), "enabled_external_model_routes": list(self.enabled_external_model_routes), "disabled_external_model_routes": dict(self.disabled_external_model_routes), "disabled_export_destinations": dict(self.disabled_export_destinations), "capability_manifest_digest": self.capability_manifest_digest, "source_manifest_digest": self.source_manifest_digest, "mandatory_release_constraints": list(self.mandatory_release_constraints)}


@dataclass(frozen=True)
class SecondBrainContractDigestV1:
    contract_version: str; decision_digests: tuple[tuple[str, str, str, str], ...]; resolved_scope: ResolvedScopeV1; expected_scope_manifest: ExpectedScopeManifestV1; digest: str
    FIELDS: ClassVar[set[str]] = {"contract_version", "decision_digests", "resolved_scope", "expected_scope_manifest"}

    @classmethod
    def create(cls, decisions: Sequence[DecisionRecordV1], scope: ResolvedScopeV1, manifest: ExpectedScopeManifestV1) -> "SecondBrainContractDigestV1":
        bindings = tuple(sorted((x.decision_id, x.scope_kind, x.scope_name or "", x.digest) for x in decisions))
        body = {"contract_version": CONTRACT_DIGEST_VERSION, "decision_digests": [{"decision_id": d, "scope_kind": k, "scope_name": n, "digest": h} for d,k,n,h in bindings], "resolved_scope": scope.to_mapping(), "expected_scope_manifest": manifest.to_mapping()}
        return cls(CONTRACT_DIGEST_VERSION, bindings, scope, manifest, sha256(canonical_bytes(body)).hexdigest())

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, digest: str) -> "SecondBrainContractDigestV1":
        values = _strict(data, cls.FIELDS)
        if values["contract_version"] != CONTRACT_DIGEST_VERSION: raise UnsupportedContractVersion("unsupported contract_version")
        entries = values["decision_digests"]
        if not isinstance(entries, list): raise InvalidContractValue("decision_digests must be an array")
        bindings: list[tuple[str, str, str, str]] = []
        for entry in entries:
            if not isinstance(entry, Mapping): raise InvalidContractValue("decision_digests entries must be objects")
            item = _strict(entry, {"decision_id", "scope_kind", "scope_name", "digest"})
            decision_id, scope_kind = _text(item["decision_id"], "decision_id"), _text(item["scope_kind"], "scope_kind")
            scope_name = item["scope_name"]
            if not isinstance(scope_name, str): raise InvalidContractValue("scope_name must be a string")
            expected_kind = _SCOPE_KIND_BY_DECISION.get(decision_id, "global")
            if decision_id not in DECISION_IDS or scope_kind != expected_kind or (scope_kind == "global" and scope_name) or (scope_kind != "global" and not scope_name):
                raise InvalidContractValue("decision digest has an invalid decision scope identity")
            bindings.append((decision_id, scope_kind, scope_name, _digest(item["digest"], "digest")))
        if not isinstance(values["resolved_scope"], Mapping) or not isinstance(values["expected_scope_manifest"], Mapping):
            raise InvalidContractValue("contract body scopes must be objects")
        parsed = cls(CONTRACT_DIGEST_VERSION, tuple(bindings), ResolvedScopeV1.from_mapping(values["resolved_scope"]), ExpectedScopeManifestV1.from_mapping(values["expected_scope_manifest"]), _digest(digest, "contract_digest"))
        if tuple(sorted(parsed.decision_digests)) != parsed.decision_digests or len(set(parsed.decision_digests)) != len(parsed.decision_digests):
            raise InvalidContractValue("decision_digests must be sorted and unique")
        if sha256(canonical_bytes(parsed.body())).hexdigest() != parsed.digest:
            raise InvalidContractValue("contract_digest does not match contract_body")
        return parsed

    def body(self) -> dict[str, Any]:
        return {"contract_version": self.contract_version, "decision_digests": [{"decision_id": d, "scope_kind": k, "scope_name": n, "digest": h} for d,k,n,h in self.decision_digests], "resolved_scope": self.resolved_scope.to_mapping(), "expected_scope_manifest": self.expected_scope_manifest.to_mapping()}


@dataclass(frozen=True)
class ContractResolutionV1:
    outcome: str; contract: SecondBrainContractDigestV1 | None; blocked_decisions: tuple[DecisionRecordV1, ...]


@dataclass(frozen=True)
class SignedSecondBrainContractEnvelopeV1:
    contract: SecondBrainContractDigestV1; signatures: tuple[Ed25519SignatureEnvelopeV1, ...]
    FIELDS: ClassVar[set[str]] = {"contract_envelope_version", "contract_version", "contract_body", "contract_digest", "signatures"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SignedSecondBrainContractEnvelopeV1":
        values = _strict(data, cls.FIELDS)
        if values["contract_envelope_version"] != CONTRACT_ENVELOPE_VERSION: raise UnsupportedContractVersion("unsupported contract_envelope_version")
        if values["contract_version"] != CONTRACT_DIGEST_VERSION: raise UnsupportedContractVersion("unsupported contract_version")
        if not isinstance(values["contract_body"], Mapping): raise InvalidContractValue("contract_body must be an object")
        contract = SecondBrainContractDigestV1.from_mapping(values["contract_body"], digest=values["contract_digest"])
        if contract.contract_version != values["contract_version"]: raise InvalidContractValue("contract_version does not match contract_body")
        return cls(contract, _signature_set(values["signatures"], version=CONTRACT_SIGNATURE_VERSION))

    def signing_payload(self) -> dict[str, Any]: return {"contract_version": self.contract.contract_version, "contract_body": self.contract.body(), "contract_digest": self.contract.digest}
    def to_mapping(self) -> dict[str, Any]: return {"contract_envelope_version": CONTRACT_ENVELOPE_VERSION, **self.signing_payload(), "signatures": [x.to_mapping() for x in self.signatures]}
    def verify(self, trusted_keys: TrustedDecisionKeyBindingsV1) -> bool:
        return sha256(canonical_bytes(self.contract.body())).hexdigest() == self.contract.digest and all(trusted_keys.matches_aggregate(x) and x.signature_version == CONTRACT_SIGNATURE_VERSION and x.verify(CONTRACT_SIGNING_DOMAIN, self.signing_payload()) for x in self.signatures) and tuple(x.role for x in self.signatures) == ("approver", "owner")


def resolve_second_brain_contract(decisions: Sequence[DecisionRecordV1], scope: ResolvedScopeV1, expected_scopes: ExpectedScopeManifestV1, aggregate: SignedSecondBrainContractEnvelopeV1 | None = None, *, trusted_keys: TrustedDecisionKeyBindingsV1 | None = None, now: datetime | None = None) -> ContractResolutionV1:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    decisions = tuple(DecisionRecordV1.from_mapping(decision.to_mapping(), now=current) for decision in decisions)
    scope = ResolvedScopeV1.from_mapping(scope.to_mapping())
    expected_scopes = ExpectedScopeManifestV1.from_mapping(expected_scopes.to_mapping())
    if aggregate is not None: aggregate = SignedSecondBrainContractEnvelopeV1.from_mapping(aggregate.to_mapping())
    scoped = {(x.decision_id, x.scope_kind, x.scope_name) for x in decisions if x.scope_kind != "global"}
    global_ids = [x.decision_id for x in decisions if x.scope_kind == "global"]
    if set(global_ids) != FATAL_DECISIONS or len(global_ids) != len(set(global_ids)) or scoped != set(expected_scopes.expected_scopes) or len(scoped) != len([x for x in decisions if x.scope_kind != "global"]): raise InvalidContractValue("decision evidence does not exactly match the expected-scope manifest")
    if trusted_keys is None: raise InvalidContractValue("trusted owner/approver key bindings are required")
    for x in decisions:
        if _timestamp(x.expires_at, "expires_at") <= current: raise InvalidContractValue(f"decision is expired: {x.decision_id}")
        if len(x.signatures) != 2 or tuple(s.role for s in x.signatures) != ("approver", "owner"):
            raise InvalidContractValue(f"decision requires approver and owner signatures: {x.decision_id}")
        if x.signatures[0].key_id == x.signatures[1].key_id or x.signatures[0].public_key_b64 == x.signatures[1].public_key_b64:
            raise InvalidContractValue(f"decision signatures must use distinct identities: {x.decision_id}")
        if not all(trusted_keys.matches_decision(x, s) and s.verify(DECISION_SIGNING_DOMAIN, x.signing_payload()) for s in x.signatures): raise InvalidContractValue(f"untrusted or invalid signature for {x.decision_id}")
    blocked = tuple(x for x in decisions if x.scope_kind == "global" and x.outcome == "NO_GO")
    if blocked: return ContractResolutionV1("BLOCKED", None, blocked)
    expected_features = tuple(sorted(_FEATURE_BY_GLOBAL_DECISION[x.decision_id] for x in decisions if x.scope_kind == "global" and x.outcome == "GO"))
    if scope.feature_flags != expected_features: raise InvalidContractValue("feature_flags must exactly derive from valid global GO decisions")
    enabled = {"source_profile": set(scope.enabled_source_profiles), "migration_source": set(scope.enabled_migration_sources), "external_model_route": set(scope.enabled_external_model_routes), "export_destination": set(scope.egress_destinations)}
    disabled = {"source_profile": dict(scope.disabled_source_profiles), "migration_source": dict(scope.disabled_migration_sources), "external_model_route": dict(scope.disabled_external_model_routes), "export_destination": dict(scope.disabled_export_destinations)}
    for kind in enabled:
        go = {x.scope_name for x in decisions if x.scope_kind == kind and x.outcome == "GO"}; no_go = {x.scope_name for x in decisions if x.scope_kind == kind and x.outcome == "NO_GO"}
        if enabled[kind] != go or set(disabled[kind]) != no_go: raise InvalidContractValue(f"{kind} enabled and disabled scopes must exactly match GO and NO_GO decisions")
    contract = SecondBrainContractDigestV1.create(decisions, scope, expected_scopes)
    if aggregate is None or aggregate.contract != contract or not aggregate.verify(trusted_keys): raise InvalidContractValue("usable RESOLVED requires a valid aggregate envelope")
    return ContractResolutionV1("RESOLVED", contract, ())
