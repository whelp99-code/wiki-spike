"""Closed, immutable Stage-3 ledger and atomic recall authority contracts."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any, Callable, ClassVar, Protocol, runtime_checkable

from .second_brain_security_contracts import SecurityContextAuthority, require_security_context_authority

from .errors import InvalidContractValue, UnknownContractField

LEDGER_COMMAND_V2 = "second-brain-ledger-command-v2"
LEDGER_RECEIPT_V2 = "second-brain-ledger-receipt-v2"
RECALL_SNAPSHOT_REQUEST_V2 = "second-brain-recall-snapshot-request-v2"
RECALL_SERVE_SNAPSHOT_V2 = "second-brain-recall-serve-snapshot-v2"
RECALL_CONTINUATION_V2 = "second-brain-recall-continuation-v2"
RECALL_CITATION_V2 = "second-brain-recall-citation-v2"
COMMAND_KINDS = frozenset({"CREATE_CANDIDATE", "REVIEW_APPROVE", "REVIEW_REJECT", "CORRECT", "SUPERSEDE", "REVOKE", "FORGET", "DECLARE_CONTRADICTION"})
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_POSITIVE = re.compile(r"^[1-9][0-9]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REF = re.compile(r"^[a-z][a-z0-9_-]{0,63}:[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_CURSOR = re.compile(r"^[A-Za-z0-9_-]{16,512}$")

_MAX_CONTINUATION_TTL_SECONDS = 300
_MAX_CLOCK_SKEW_SECONDS = 30
_REQUIRED_PROVENANCE_COMPONENTS = ("authorization", "global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent")


@runtime_checkable
class RecallTrustVerifierV2(Protocol):
    """Trusted crypto adapter, retained inside a minted authority only."""
    def verify_signed_bytes(self, *, signer_ref: str, algorithm: str, key_id: str, signature: str, payload: bytes) -> bool: ...

_RECALL_TRUST_MINT = object()

class RecallTrustAuthorityV2:
    """Nominal Core authority; public wires cannot manufacture this boundary."""
    __slots__ = ("__verifier", "__clock", "__provenance")
    def __init__(self, mint: object, verifier: RecallTrustVerifierV2, clock: Callable[[], str], provenance: Mapping[str, "AuthorityProvenanceV2"]) -> None:
        if mint is not _RECALL_TRUST_MINT:
            raise InvalidContractValue("RecallTrustAuthorityV2 must be minted")
        self.__verifier, self.__clock, self.__provenance = verifier, clock, dict(provenance)
    def _now(self) -> str: return _utc(self.__clock(), "trusted clock")
    def _verify(self, *, signer_ref: str, algorithm: str, key_id: str, signature: str, body: Mapping[str, Any], domain: str = "signed-v2") -> bool:
        if algorithm != "Ed25519" or not re.fullmatch(r"[A-Za-z0-9_-]+", signature): return False
        return bool(self.__verifier.verify_signed_bytes(signer_ref=signer_ref, algorithm=algorithm, key_id=key_id, signature=signature, payload=canonical_ledger_bytes(domain, body)))
    def _provenance(self, ref: str, digest: str) -> "AuthorityProvenanceV2":
        provenance = self.__provenance.get(ref)
        if provenance is None or provenance.provenance_digest != digest:
            raise InvalidContractValue("authority provenance is missing or does not resolve by ref/digest")
        return provenance

def mint_recall_trust_authority_v2(security_authority: SecurityContextAuthority, verifier: RecallTrustVerifierV2, clock: Callable[[], str], provenance: Mapping[str, "AuthorityProvenanceV2"]) -> RecallTrustAuthorityV2:
    require_security_context_authority(security_authority)
    if not isinstance(verifier, RecallTrustVerifierV2) or not callable(clock):
        raise InvalidContractValue("mint requires trusted verifier and clock")
    parsed = {ref: value if isinstance(value, AuthorityProvenanceV2) else AuthorityProvenanceV2.from_mapping(value) for ref, value in provenance.items()}
    if any(ref != value.provenance_ref for ref, value in parsed.items()):
        raise InvalidContractValue("provenance registry keys must be exact refs")
    return RecallTrustAuthorityV2(_RECALL_TRUST_MINT, verifier, clock, parsed)

@dataclass(frozen=True, slots=True)
class VerifiedAuthorityProvenanceV2:
    provenance: "AuthorityProvenanceV2"


@dataclass(frozen=True, slots=True)
class VerifiedRecallContinuationV2:
    continuation: "RecallContinuationV2"

def canonical_ledger_bytes(domain: str, body: Mapping[str, Any]) -> bytes:
    if not isinstance(domain, str) or not domain:
        raise InvalidContractValue("digest domain must be non-empty")
    try:
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise InvalidContractValue("digest body must be canonical JSON") from exc
    return b"second-brain-ledger/" + domain.encode("ascii") + b"\0" + encoded

def canonical_ledger_digest(domain: str, body: Mapping[str, Any]) -> str:
    return sha256(canonical_ledger_bytes(domain, body)).hexdigest()


def _strict(data: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(data, Mapping) or any(not isinstance(k, str) for k in data):
        raise InvalidContractValue("contract must be an object with string keys")
    unknown, missing = set(data) - fields, fields - set(data)
    if unknown:
        raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
    return dict(data)


def _ref(value: Any, field: str, kind: str | None = None) -> str:
    if not isinstance(value, str) or _REF.fullmatch(value) is None or (kind and not value.startswith(kind + ":")):
        raise InvalidContractValue(f"{field} must be an opaque keyed reference")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a lowercase SHA-256 digest")
    return value


def _decimal(value: Any, field: str, positive: bool = False) -> str:
    if not isinstance(value, str) or ( _POSITIVE if positive else _DECIMAL).fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a canonical decimal")
    return value


def _instant(value: Any, field: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be canonical UTC")
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise InvalidContractValue(f"{field} must be a real UTC timestamp") from exc
    text = instant.strftime("%Y-%m-%dT%H:%M:%S")
    if instant.microsecond:
        text += "." + f"{instant.microsecond:06d}".rstrip("0")
    return text + "Z", instant


def _utc(value: Any, field: str) -> str:
    return _instant(value, field)[0]


def _bound(value: Any, field: str, domain: str, body: Mapping[str, Any]) -> str:
    value = _digest(value, field)
    if value != canonical_ledger_digest(domain, body):
        raise InvalidContractValue(f"{field} does not bind its canonical body")
    return value


def _typed_tuple(value: Any, cls: type, field: str) -> tuple[Any, ...]:
    if not isinstance(value, (tuple, list)):
        raise InvalidContractValue(f"{field} must be an array or tuple")
    copied = tuple(cls.from_mapping(x) if isinstance(x, Mapping) else x for x in value)
    if not all(isinstance(x, cls) for x in copied):
        raise InvalidContractValue(f"{field} contains an invalid value")
    return copied
@dataclass(frozen=True)
class AuthorityProvenanceV2:
    """Complete, signed authority input; verification is always performed by Runtime."""
    provenance_version: str; provenance_ref: str; provenance_digest: str; signer_ref: str; signer_algorithm: str; key_id: str; signature: str; component_labels: tuple[str, ...]; component_states: tuple["GateStateV2", ...]; transaction_cut: str; issued_at: str; expires_at: str; workspace_ref: str; capability_ref: str; authority_epoch: str; subject_ref: str; action: str; query_digest: str | None; scope_digest: str | None; request_digest: str | None; command_payload_digest: str | None
    FIELDS: ClassVar[set[str]] = {"provenance_version", "provenance_ref", "provenance_digest", "signer_ref", "signer_algorithm", "key_id", "signature", "component_labels", "component_states", "transaction_cut", "issued_at", "expires_at", "workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "query_digest", "scope_digest", "request_digest", "command_payload_digest"}
    def __post_init__(self) -> None:
        object.__setattr__(self, "component_states", _typed_tuple(self.component_states, GateStateV2, "component_states"))
        if not isinstance(self.component_labels, (tuple, list)) or tuple(self.component_labels) != _REQUIRED_PROVENANCE_COMPONENTS or len(self.component_states) != len(_REQUIRED_PROVENANCE_COMPONENTS):
            raise InvalidContractValue("provenance requires the complete named component set")
        object.__setattr__(self, "component_labels", tuple(self.component_labels))
        if self.provenance_version != "second-brain-authority-provenance-v2": raise InvalidContractValue("unsupported provenance_version")
        _ref(self.provenance_ref, "provenance_ref", "provenance"); _ref(self.signer_ref, "signer_ref", "signer"); _ref(self.key_id, "key_id", "key")
        if self.signer_algorithm != "Ed25519": raise InvalidContractValue("signer_algorithm is fixed to Ed25519")
        if not isinstance(self.signature, str) or not self.signature or len(self.signature) > 4096 or any(c.isspace() for c in self.signature): raise InvalidContractValue("signature must be store-issued evidence")
        _decimal(self.transaction_cut, "transaction_cut", True); _ref(self.workspace_ref, "workspace_ref", "workspace"); _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True); _ref(self.subject_ref, "subject_ref")
        if not isinstance(self.action, str) or not self.action: raise InvalidContractValue("provenance action required")
        for value, field in ((self.query_digest, "query_digest"), (self.scope_digest, "scope_digest"), (self.request_digest, "request_digest"), (self.command_payload_digest, "command_payload_digest")):
            if value is not None: _digest(value, field)
        issued, issued_i = _instant(self.issued_at, "issued_at"); expires, expires_i = _instant(self.expires_at, "expires_at")
        object.__setattr__(self, "issued_at", issued); object.__setattr__(self, "expires_at", expires)
        if expires_i <= issued_i or not self.component_states or len({(x.epoch, x.digest) for x in self.component_states}) != len(self.component_states): raise InvalidContractValue("invalid provenance lifetime or components")
        _bound(self.provenance_digest, "provenance_digest", "authority-provenance-v2", self.signing_body())
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AuthorityProvenanceV2": return cls(**_strict(data, cls.FIELDS))
    def signing_body(self) -> dict[str, Any]:
        return {k: ([x.to_mapping() for x in self.component_states] if k == "component_states" else list(self.component_labels) if k == "component_labels" else getattr(self, k)) for k in self.FIELDS - {"provenance_digest", "signature"}}
    def to_mapping(self) -> dict[str, Any]:
        return {**{k: getattr(self, k) for k in self.FIELDS if k not in {"component_states", "component_labels"}}, "component_labels": list(self.component_labels), "component_states": [x.to_mapping() for x in self.component_states]}
    def validate_at(self, now: str) -> None:
        now_i = _instant(now, "now")[1]
        if not (_instant(self.issued_at, "issued_at")[1] <= now_i < _instant(self.expires_at, "expires_at")[1]): raise InvalidContractValue("authority provenance is not currently valid")

@dataclass(frozen=True)
class CitationEvidenceV2:
    evidence_version: str; locator_ref: str; locator_digest: str; immutable_source_ref: str; revision_ref: str; evidence_digest: str
    FIELDS: ClassVar[set[str]] = {"evidence_version", "locator_ref", "locator_digest", "immutable_source_ref", "revision_ref", "evidence_digest"}
    def __post_init__(self) -> None:
        if self.evidence_version != "second-brain-citation-evidence-v2": raise InvalidContractValue("unsupported evidence_version")
        _ref(self.locator_ref, "locator_ref", "locator"); _digest(self.locator_digest, "locator_digest"); _ref(self.immutable_source_ref, "source_ref"); _ref(self.revision_ref, "revision_ref", "revision")
        _bound(self.evidence_digest, "evidence_digest", "citation-evidence-v2", {k: getattr(self, k) for k in self.FIELDS - {"evidence_digest"}})
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CitationEvidenceV2": return cls(**_strict(data, cls.FIELDS))
    def to_mapping(self) -> dict[str, Any]: return {k: getattr(self, k) for k in self.FIELDS}


@dataclass(frozen=True)
class BitemporalIntervalV2:
    valid_from: str; valid_to: str | None; recorded_from: str; recorded_to: str | None
    def __post_init__(self) -> None:
        vf, vf_i = _instant(self.valid_from, "valid_from"); rf, rf_i = _instant(self.recorded_from, "recorded_from")
        object.__setattr__(self, "valid_from", vf); object.__setattr__(self, "recorded_from", rf)
        if self.valid_to is not None:
            vt, vt_i = _instant(self.valid_to, "valid_to"); object.__setattr__(self, "valid_to", vt)
            if vt_i <= vf_i: raise InvalidContractValue("valid interval must be half-open")
        if self.recorded_to is not None:
            rt, rt_i = _instant(self.recorded_to, "recorded_to"); object.__setattr__(self, "recorded_to", rt)
            if rt_i <= rf_i: raise InvalidContractValue("recorded interval must be half-open")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "BitemporalIntervalV2":
        v = _strict(data, {"valid_from", "valid_to", "recorded_from", "recorded_to"}); return cls(**v)
    def to_mapping(self) -> dict[str, Any]: return {"valid_from": self.valid_from, "valid_to": self.valid_to, "recorded_from": self.recorded_from, "recorded_to": self.recorded_to}
    def contains(self, valid_at: str, recorded_at: str) -> bool:
        _, va = _instant(valid_at, "valid_at"); _, ra = _instant(recorded_at, "recorded_at")
        _, vf = _instant(self.valid_from, "valid_from"); _, rf = _instant(self.recorded_from, "recorded_from")
        vt = _instant(self.valid_to, "valid_to")[1] if self.valid_to else None; rt = _instant(self.recorded_to, "recorded_to")[1] if self.recorded_to else None
        return vf <= va and (vt is None or va < vt) and rf <= ra and (rt is None or ra < rt)


@dataclass(frozen=True)
class LedgerEdgeV2:
    edge_kind: str; from_candidate_ref: str; to_candidate_ref: str; workspace_ref: str; interval: BitemporalIntervalV2
    def __post_init__(self) -> None:
        if self.edge_kind not in {"SUPPORT", "CONTRADICTION"}: raise InvalidContractValue("edge_kind is closed")
        _ref(self.from_candidate_ref, "from_candidate_ref", "candidate"); _ref(self.to_candidate_ref, "to_candidate_ref", "candidate"); _ref(self.workspace_ref, "workspace_ref", "workspace")
        if isinstance(self.interval, Mapping): object.__setattr__(self, "interval", BitemporalIntervalV2.from_mapping(self.interval))
        if self.from_candidate_ref == self.to_candidate_ref or not isinstance(self.interval, BitemporalIntervalV2): raise InvalidContractValue("invalid ledger edge")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "LedgerEdgeV2": return cls(**_strict(data, {"edge_kind", "from_candidate_ref", "to_candidate_ref", "workspace_ref", "interval"}))
    def to_mapping(self) -> dict[str, Any]: return {"edge_kind": self.edge_kind, "from_candidate_ref": self.from_candidate_ref, "to_candidate_ref": self.to_candidate_ref, "workspace_ref": self.workspace_ref, "interval": self.interval.to_mapping()}
SupportEdgeV2 = LedgerEdgeV2
ContradictionEdgeV2 = LedgerEdgeV2


@dataclass(frozen=True)
class CommandPayloadV2:
    candidate_ref: str; prior_state: str; resulting_state: str; content_digest: str | None; support_edges: tuple[LedgerEdgeV2, ...]; contradiction_edges: tuple[LedgerEdgeV2, ...]
    FIELDS: ClassVar[set[str]] = {"candidate_ref", "prior_state", "resulting_state", "content_digest", "support_edges", "contradiction_edges"}
    def __post_init__(self) -> None:
        object.__setattr__(self, "support_edges", _typed_tuple(self.support_edges, LedgerEdgeV2, "support_edges")); object.__setattr__(self, "contradiction_edges", _typed_tuple(self.contradiction_edges, LedgerEdgeV2, "contradiction_edges"))
        _ref(self.candidate_ref, "candidate_ref", "candidate")
        if self.prior_state not in {"ABSENT", "PENDING", "APPROVED", "REJECTED", "REVOKED", "FORGOTTEN"} or self.resulting_state not in {"PENDING", "APPROVED", "REJECTED", "REVOKED", "FORGOTTEN"}: raise InvalidContractValue("command states are closed")
        if self.content_digest is not None: _digest(self.content_digest, "content_digest")
        if any(e.edge_kind != "SUPPORT" for e in self.support_edges) or any(e.edge_kind != "CONTRADICTION" for e in self.contradiction_edges): raise InvalidContractValue("edge collection kind mismatch")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CommandPayloadV2":
        v = _strict(data, cls.FIELDS)
        if not isinstance(v["support_edges"], list) or not isinstance(v["contradiction_edges"], list): raise InvalidContractValue("edge collections must be arrays")
        return cls(**v)
    def to_mapping(self) -> dict[str, Any]: return {"candidate_ref": self.candidate_ref, "prior_state": self.prior_state, "resulting_state": self.resulting_state, "content_digest": self.content_digest, "support_edges": [x.to_mapping() for x in self.support_edges], "contradiction_edges": [x.to_mapping() for x in self.contradiction_edges]}


@dataclass(frozen=True)
class LedgerCommandV2:
    command_version: str; command_ref: str; workspace_ref: str; capability_ref: str; authority_epoch: str; subject_ref: str; action: str; scope_digest: str; kind: str; target_candidate_ref: str | None; expected_active_revision_ref: str | None; related_candidate_refs: tuple[str, ...]; interval: BitemporalIntervalV2; payload: CommandPayloadV2; command_payload_digest: str; authority_provenance_ref: str; authority_provenance_digest: str; command_digest: str
    FIELDS: ClassVar[set[str]] = {"command_version", "command_ref", "workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "scope_digest", "kind", "target_candidate_ref", "expected_active_revision_ref", "related_candidate_refs", "interval", "payload", "command_payload_digest", "authority_provenance_ref", "authority_provenance_digest", "command_digest"}
    def __post_init__(self) -> None:
        if self.command_version != LEDGER_COMMAND_V2 or self.kind not in COMMAND_KINDS: raise InvalidContractValue("closed command version or kind")
        _ref(self.command_ref, "command_ref", "command"); _ref(self.workspace_ref, "workspace_ref", "workspace"); _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True); _ref(self.subject_ref, "subject_ref"); _digest(self.scope_digest, "scope_digest")
        if not isinstance(self.action, str) or not self.action: raise InvalidContractValue("command action required")
        if not isinstance(self.related_candidate_refs, (tuple, list)): raise InvalidContractValue("related_candidate_refs must be an array")
        object.__setattr__(self, "related_candidate_refs", tuple(self.related_candidate_refs))
        if isinstance(self.interval, Mapping): object.__setattr__(self, "interval", BitemporalIntervalV2.from_mapping(self.interval))
        if isinstance(self.payload, Mapping): object.__setattr__(self, "payload", CommandPayloadV2.from_mapping(self.payload))
        if not isinstance(self.interval, BitemporalIntervalV2) or not isinstance(self.payload, CommandPayloadV2): raise InvalidContractValue("typed command values required")
        if len(set(self.related_candidate_refs)) != len(self.related_candidate_refs): raise InvalidContractValue("candidate references must be unique")
        for value in self.related_candidate_refs: _ref(value, "related_candidate_refs", "candidate")
        if self.target_candidate_ref is not None: _ref(self.target_candidate_ref, "target_candidate_ref", "candidate")
        if self.kind == "CREATE_CANDIDATE":
            if self.expected_active_revision_ref is not None: raise InvalidContractValue("create commands cannot assert an active revision")
        else:
            _ref(self.expected_active_revision_ref, "expected_active_revision_ref", "revision")
        _ref(self.authority_provenance_ref, "authority_provenance_ref", "provenance"); _digest(self.authority_provenance_digest, "authority_provenance_digest")
        _bound(self.command_payload_digest, "command_payload_digest", "command-payload-v2", self.payload.to_mapping())
        matrix = {"CREATE_CANDIDATE": (None, 0, "ABSENT", "PENDING", True, 0, 0), "REVIEW_APPROVE": ("target", 0, "PENDING", "APPROVED", False, 0, 0), "REVIEW_REJECT": ("target", 0, "PENDING", "REJECTED", False, 0, 0), "CORRECT": ("target", 1, "APPROVED", "APPROVED", True, 1, 0), "SUPERSEDE": ("target", 1, "APPROVED", "APPROVED", True, 1, 0), "REVOKE": ("target", 0, "APPROVED", "REVOKED", False, 0, 0), "FORGET": ("target", 0, "APPROVED", "FORGOTTEN", False, 0, 0), "DECLARE_CONTRADICTION": ("target", 1, "APPROVED", "APPROVED", False, 0, 1)}[self.kind]
        target, count, prior, result, content, supports, contradictions = matrix
        if (target is None) != (self.target_candidate_ref is None) or len(self.related_candidate_refs) != count or (self.payload.prior_state, self.payload.resulting_state) != (prior, result) or (self.payload.content_digest is not None) != content or (len(self.payload.support_edges), len(self.payload.contradiction_edges)) != (supports, contradictions): raise InvalidContractValue("command kind invariant matrix failed")
        if self.kind != "CREATE_CANDIDATE" and self.payload.candidate_ref != self.target_candidate_ref: raise InvalidContractValue("payload must bind target")
        if self.kind == "CREATE_CANDIDATE" and self.payload.candidate_ref in self.related_candidate_refs: raise InvalidContractValue("candidate collision")
        if self.kind in {"CORRECT", "SUPERSEDE"}:
            edge = self.payload.support_edges[0]
            expected = (self.related_candidate_refs[0], self.target_candidate_ref) if self.kind == "CORRECT" else (self.target_candidate_ref, self.related_candidate_refs[0])
            if (edge.from_candidate_ref, edge.to_candidate_ref) != expected: raise InvalidContractValue(f"{self.kind} support edge direction is invalid")
        if self.kind == "DECLARE_CONTRADICTION":
            edge = self.payload.contradiction_edges[0]
            if (edge.from_candidate_ref, edge.to_candidate_ref) != (self.target_candidate_ref, self.related_candidate_refs[0]): raise InvalidContractValue("contradiction edge direction is invalid")
        if any(e.workspace_ref != self.workspace_ref for e in self.payload.support_edges + self.payload.contradiction_edges): raise InvalidContractValue("edge workspace differs from command")
        _bound(self.command_digest, "command_digest", "command-v2", {k: v for k, v in self.to_mapping().items() if k != "command_digest"})
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "LedgerCommandV2": return cls(**_strict(data, cls.FIELDS))
    def to_mapping(self) -> dict[str, Any]: return {"command_version": self.command_version, "command_ref": self.command_ref, "workspace_ref": self.workspace_ref, "capability_ref": self.capability_ref, "authority_epoch": self.authority_epoch, "subject_ref": self.subject_ref, "action": self.action, "scope_digest": self.scope_digest, "kind": self.kind, "target_candidate_ref": self.target_candidate_ref, "expected_active_revision_ref": self.expected_active_revision_ref, "related_candidate_refs": list(self.related_candidate_refs), "interval": self.interval.to_mapping(), "payload": self.payload.to_mapping(), "command_payload_digest": self.command_payload_digest, "authority_provenance_ref": self.authority_provenance_ref, "authority_provenance_digest": self.authority_provenance_digest, "command_digest": self.command_digest}


@dataclass(frozen=True)
class LedgerReceiptV2:
    receipt_version: str; command_ref: str; workspace_ref: str; transaction_cut: str; ledger_epoch: str; receipt_digest: str
    FIELDS: ClassVar[set[str]] = {"receipt_version", "command_ref", "workspace_ref", "transaction_cut", "ledger_epoch", "receipt_digest"}
    def __post_init__(self) -> None:
        if self.receipt_version != LEDGER_RECEIPT_V2: raise InvalidContractValue("unsupported receipt_version")
        _ref(self.command_ref, "command_ref", "command"); _ref(self.workspace_ref, "workspace_ref", "workspace"); _decimal(self.transaction_cut, "transaction_cut", True); _decimal(self.ledger_epoch, "ledger_epoch", True)
        _bound(self.receipt_digest, "receipt_digest", "receipt-v2", {"receipt_version": self.receipt_version, "command_ref": self.command_ref, "workspace_ref": self.workspace_ref, "transaction_cut": self.transaction_cut, "ledger_epoch": self.ledger_epoch})
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "LedgerReceiptV2": return cls(**_strict(data, cls.FIELDS))


_AUTHORITY_FIELDS = ("generation_ref", "generation_digest", "checkpoint_ref", "checkpoint_digest", "freshness_digest", "authority_checkpoint_digest")
_AUTHORITY_COMMITMENT_FIELDS = (
    "workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "query_digest", "scope_digest",
    "valid_at", "recorded_at", "transaction_cut", "authority_provenance_ref", "authority_provenance_digest", *_AUTHORITY_FIELDS,
    "authorization", "global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent", "projection_digest", "contract_digest",
)
def _authority_values(obj: Any) -> None:
    _ref(obj.generation_ref, "generation_ref", "generation"); _digest(obj.generation_digest, "generation_digest"); _ref(obj.checkpoint_ref, "checkpoint_ref", "checkpoint"); _digest(obj.checkpoint_digest, "checkpoint_digest"); _digest(obj.freshness_digest, "freshness_digest"); _digest(obj.authority_checkpoint_digest, "authority_checkpoint_digest")

def _authority_commitment_body(obj: Any) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for field in _AUTHORITY_COMMITMENT_FIELDS:
        value = getattr(obj, field)
        body[field] = value.to_mapping() if isinstance(value, (RecallAuthorityV2, GateStateV2)) else value
    return body

def _authority_commitment(obj: Any) -> str:
    return canonical_ledger_digest("recall-authority-v2", _authority_commitment_body(obj))

@dataclass(frozen=True)
class RecallContinuationV2:
    continuation_version: str; continuation_ref: str; workspace_ref: str; capability_ref: str; authority_epoch: str; subject_ref: str; action: str; query_digest: str; scope_digest: str; valid_at: str; recorded_at: str; transaction_cut: str; authority_provenance_ref: str; authority_provenance_digest: str; signer_ref: str; signer_algorithm: str; key_id: str; signature: str; generation_ref: str; generation_digest: str; checkpoint_ref: str; checkpoint_digest: str; freshness_digest: str; authority_checkpoint_digest: str; authority_commitment_digest: str; base_snapshot_digest: str; cursor_handle_ref: str; cursor_state_digest: str; issued_at: str; expires_at: str; continuation_digest: str
    FIELDS: ClassVar[set[str]] = {"continuation_version", "continuation_ref", "workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "query_digest", "scope_digest", "valid_at", "recorded_at", "transaction_cut", "authority_provenance_ref", "authority_provenance_digest", "signer_ref", "signer_algorithm", "key_id", "signature", *_AUTHORITY_FIELDS, "authority_commitment_digest", "base_snapshot_digest", "cursor_handle_ref", "cursor_state_digest", "issued_at", "expires_at", "continuation_digest"}
    def __post_init__(self) -> None:
        if self.continuation_version != RECALL_CONTINUATION_V2: raise InvalidContractValue("unsupported continuation_version")
        _ref(self.continuation_ref, "continuation_ref", "continuation"); _ref(self.cursor_handle_ref, "cursor_handle_ref", "cursor"); _ref(self.workspace_ref, "workspace_ref", "workspace"); _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True); _ref(self.subject_ref, "subject_ref")
        if not isinstance(self.action, str) or not self.action or len(self.action) > 128: raise InvalidContractValue("continuation action required")
        _digest(self.query_digest, "query_digest"); _digest(self.scope_digest, "scope_digest"); va, _ = _instant(self.valid_at, "valid_at"); ra, _ = _instant(self.recorded_at, "recorded_at"); object.__setattr__(self, "valid_at", va); object.__setattr__(self, "recorded_at", ra); _decimal(self.transaction_cut, "transaction_cut", True); _ref(self.authority_provenance_ref, "authority_provenance_ref", "provenance"); _digest(self.authority_provenance_digest, "authority_provenance_digest"); _ref(self.signer_ref, "signer_ref", "signer"); _ref(self.key_id, "key_id", "key")
        if self.signer_algorithm != "Ed25519" or not isinstance(self.signature, str) or not self.signature or len(self.signature) > 4096 or any(c.isspace() for c in self.signature): raise InvalidContractValue("continuation signature metadata is invalid")
        _authority_values(self); _digest(self.authority_commitment_digest, "authority_commitment_digest"); _digest(self.base_snapshot_digest, "base_snapshot_digest"); _digest(self.cursor_state_digest, "cursor_state_digest")
        issued, issued_i = _instant(self.issued_at, "issued_at"); expires, expires_i = _instant(self.expires_at, "expires_at"); object.__setattr__(self, "issued_at", issued); object.__setattr__(self, "expires_at", expires)
        if expires_i <= issued_i or (expires_i - issued_i).total_seconds() > _MAX_CONTINUATION_TTL_SECONDS: raise InvalidContractValue("continuation lifetime is invalid")
        _bound(self.continuation_digest, "continuation_digest", "continuation-v2", self.signing_body())
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallContinuationV2": return cls(**_strict(data, cls.FIELDS))
    def signing_body(self) -> dict[str, Any]: return {k: getattr(self, k) for k in self.FIELDS - {"continuation_digest", "signature"}}
    def to_mapping(self) -> dict[str, Any]: return {k: getattr(self, k) for k in self.FIELDS}
    def validate_at(self, authority: RecallTrustAuthorityV2) -> None:
        if not isinstance(authority, RecallTrustAuthorityV2):
            raise InvalidContractValue("a minted RecallTrustAuthorityV2 is required")
        _verify_continuation(authority, self, authority._now())

@dataclass(frozen=True)
class RecallSnapshotRequestV2:
    request_version: str; workspace_ref: str; capability_ref: str; authority_epoch: str; subject_ref: str; action: str; query_digest: str; valid_at: str; recorded_at: str; scope_digest: str; transaction_cut: str; authority_provenance_ref: str; authority_provenance_digest: str; continuation: RecallContinuationV2 | None; request_digest: str
    FIELDS: ClassVar[set[str]] = {"request_version", "workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "query_digest", "valid_at", "recorded_at", "scope_digest", "transaction_cut", "authority_provenance_ref", "authority_provenance_digest", "continuation", "request_digest"}
    def __post_init__(self) -> None:
        if isinstance(self.continuation, Mapping): object.__setattr__(self, "continuation", RecallContinuationV2.from_mapping(self.continuation))
        if self.request_version != RECALL_SNAPSHOT_REQUEST_V2 or (self.continuation is not None and not isinstance(self.continuation, RecallContinuationV2)): raise InvalidContractValue("invalid request")
        _ref(self.workspace_ref, "workspace_ref", "workspace"); _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True); _ref(self.subject_ref, "subject_ref")
        if not isinstance(self.action, str) or not self.action or len(self.action) > 128: raise InvalidContractValue("request action required")
        _digest(self.query_digest, "query_digest"); _digest(self.scope_digest, "scope_digest"); _decimal(self.transaction_cut, "transaction_cut", True); _ref(self.authority_provenance_ref, "authority_provenance_ref", "provenance"); _digest(self.authority_provenance_digest, "authority_provenance_digest")
        va, _ = _instant(self.valid_at, "valid_at"); ra, _ = _instant(self.recorded_at, "recorded_at"); object.__setattr__(self, "valid_at", va); object.__setattr__(self, "recorded_at", ra)
        if self.continuation and tuple(getattr(self.continuation, x) for x in ("workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "query_digest", "scope_digest", "valid_at", "recorded_at", "transaction_cut")) != (self.workspace_ref, self.capability_ref, self.authority_epoch, self.subject_ref, self.action, self.query_digest, self.scope_digest, self.valid_at, self.recorded_at, self.transaction_cut):
            raise InvalidContractValue("continuation is not request-bound")
        _bound(self.request_digest, "request_digest", "request-v2", {k: v for k, v in self.to_mapping().items() if k != "request_digest"})
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallSnapshotRequestV2": return cls(**_strict(data, cls.FIELDS))
    def to_mapping(self) -> dict[str, Any]: return {k: (None if self.continuation is None else self.continuation.to_mapping()) if k == "continuation" else getattr(self, k) for k in self.FIELDS}


@dataclass(frozen=True)
class RecallAuthorityV2:
    decision: str; capability_ref: str; authority_epoch: str; query_digest: str; workspace_ref: str; scope_digest: str
    def __post_init__(self) -> None:
        if self.decision not in {"ALLOW", "DENY", "ABSTAIN"}: raise InvalidContractValue("authorization decision is closed")
        _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True); _digest(self.query_digest, "query_digest"); _ref(self.workspace_ref, "workspace_ref", "workspace"); _digest(self.scope_digest, "scope_digest")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallAuthorityV2": return cls(**_strict(data, {"decision", "capability_ref", "authority_epoch", "query_digest", "workspace_ref", "scope_digest"}))
    def to_mapping(self) -> dict[str, Any]: return {"decision": self.decision, "capability_ref": self.capability_ref, "authority_epoch": self.authority_epoch, "query_digest": self.query_digest, "workspace_ref": self.workspace_ref, "scope_digest": self.scope_digest}

@dataclass(frozen=True)
class GateStateV2:
    state: str; epoch: str; digest: str
    def __post_init__(self) -> None:
        if self.state not in {"PASS", "DENY", "ABSTAIN"}: raise InvalidContractValue("gate state is closed")
        _decimal(self.epoch, "epoch", True); _digest(self.digest, "digest")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "GateStateV2": return cls(**_strict(data, {"state", "epoch", "digest"}))
    def to_mapping(self) -> dict[str, Any]: return {"state": self.state, "epoch": self.epoch, "digest": self.digest}

@dataclass(frozen=True)
class RecallCitationV2:
    citation_version: str; candidate_ref: str; evidence: CitationEvidenceV2; citation_digest: str
    def __post_init__(self) -> None:
        if self.citation_version != RECALL_CITATION_V2: raise InvalidContractValue("unsupported citation_version")
        _ref(self.candidate_ref, "candidate_ref", "candidate")
        if isinstance(self.evidence, Mapping): object.__setattr__(self, "evidence", CitationEvidenceV2.from_mapping(self.evidence))
        if not isinstance(self.evidence, CitationEvidenceV2): raise InvalidContractValue("citation needs immutable locator evidence")
        _bound(self.citation_digest, "citation_digest", "citation-v2", {"citation_version": self.citation_version, "candidate_ref": self.candidate_ref, "evidence": self.evidence.to_mapping()})
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallCitationV2": return cls(**_strict(data, {"citation_version", "candidate_ref", "evidence", "citation_digest"}))
    def to_mapping(self) -> dict[str, Any]: return {"citation_version": self.citation_version, "candidate_ref": self.candidate_ref, "evidence": self.evidence.to_mapping(), "citation_digest": self.citation_digest}

@dataclass(frozen=True)
class CandidateOutcomeV2:
    candidate_ref: str; revision_ref: str; state: str; content_digest: str; support_refs: tuple[str, ...]
    def __post_init__(self) -> None:
        if not isinstance(self.support_refs, (tuple, list)): raise InvalidContractValue("support_refs must be array")
        object.__setattr__(self, "support_refs", tuple(self.support_refs)); _ref(self.candidate_ref, "candidate_ref", "candidate"); _ref(self.revision_ref, "revision_ref", "revision"); _digest(self.content_digest, "content_digest")
        if self.state not in {"PENDING", "APPROVED", "REJECTED", "REVOKED", "FORGOTTEN"} or len(set(self.support_refs)) != len(self.support_refs): raise InvalidContractValue("invalid candidate outcome")
        for value in self.support_refs: _ref(value, "support_refs", "candidate")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CandidateOutcomeV2": return cls(**_strict(data, {"candidate_ref", "revision_ref", "state", "content_digest", "support_refs"}))
    def to_mapping(self) -> dict[str, Any]: return {"candidate_ref": self.candidate_ref, "revision_ref": self.revision_ref, "state": self.state, "content_digest": self.content_digest, "support_refs": list(self.support_refs)}

@dataclass(frozen=True)
class ConflictOutcomeV2:
    decision_version: str; left_candidate_ref: str; right_candidate_ref: str; state: str; winning_candidate_ref: str | None; expected_decision_revision_ref: str | None; authority_provenance_ref: str | None; authority_provenance_digest: str | None; winning_revision_citation: CitationEvidenceV2 | None; decision_digest: str
    FIELDS: ClassVar[set[str]] = {"decision_version", "left_candidate_ref", "right_candidate_ref", "state", "winning_candidate_ref", "expected_decision_revision_ref", "authority_provenance_ref", "authority_provenance_digest", "winning_revision_citation", "decision_digest"}
    def __post_init__(self) -> None:
        if self.decision_version != "second-brain-conflict-decision-v2": raise InvalidContractValue("unsupported decision_version")
        _ref(self.left_candidate_ref, "left_candidate_ref", "candidate"); _ref(self.right_candidate_ref, "right_candidate_ref", "candidate")
        if self.left_candidate_ref >= self.right_candidate_ref or self.state not in {"OPEN", "RESOLVED"}: raise InvalidContractValue("conflicts require canonical side ordering")
        if self.state == "OPEN":
            if any(x is not None for x in (self.winning_candidate_ref, self.expected_decision_revision_ref, self.authority_provenance_ref, self.authority_provenance_digest, self.winning_revision_citation)): raise InvalidContractValue("open conflict cannot carry a decision")
        else:
            _ref(self.winning_candidate_ref, "winning_candidate_ref", "candidate")
            if self.winning_candidate_ref not in {self.left_candidate_ref, self.right_candidate_ref}: raise InvalidContractValue("resolved winner must be a conflict side")
            _ref(self.expected_decision_revision_ref, "expected_decision_revision_ref", "revision"); _ref(self.authority_provenance_ref, "authority_provenance_ref", "provenance"); _digest(self.authority_provenance_digest, "authority_provenance_digest")
            if isinstance(self.winning_revision_citation, Mapping): object.__setattr__(self, "winning_revision_citation", CitationEvidenceV2.from_mapping(self.winning_revision_citation))
            if not isinstance(self.winning_revision_citation, CitationEvidenceV2) or self.winning_revision_citation.revision_ref != self.expected_decision_revision_ref: raise InvalidContractValue("resolved conflict needs expected winning revision citation")
        _bound(self.decision_digest, "decision_digest", "conflict-decision-v2", {k: (self.winning_revision_citation.to_mapping() if k == "winning_revision_citation" and self.winning_revision_citation else getattr(self, k)) for k in self.FIELDS - {"decision_digest"}})
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ConflictOutcomeV2": return cls(**_strict(data, cls.FIELDS))
    def to_mapping(self) -> dict[str, Any]: return {k: (None if self.winning_revision_citation is None else self.winning_revision_citation.to_mapping()) if k == "winning_revision_citation" else getattr(self, k) for k in self.FIELDS}

ConflictDecisionV2 = ConflictOutcomeV2

@dataclass(frozen=True)
class RecallServeSnapshotV2:
    snapshot_version: str; snapshot_attestation_version: str; snapshot_signer_ref: str; snapshot_signer_algorithm: str; snapshot_key_id: str; snapshot_signature: str; provenance_component_labels: tuple[str, ...]; provenance_component_states: tuple["GateStateV2", ...]; has_more: bool; pagination_commitment_digest: str; selected_candidates_digest: str; selected_citations_digest: str; selected_conflicts_digest: str; workspace_ref: str; capability_ref: str; authority_epoch: str; subject_ref: str; action: str; query_digest: str; transaction_cut: str; valid_at: str; recorded_at: str; scope_digest: str; authority_provenance_ref: str; authority_provenance_digest: str; generation_ref: str; generation_digest: str; checkpoint_ref: str; checkpoint_digest: str; freshness_digest: str; authority_checkpoint_digest: str; authorization: RecallAuthorityV2; global_floor: GateStateV2; binding: GateStateV2; recovery: GateStateV2; route: GateStateV2; cohort: GateStateV2; deletion: GateStateV2; consent: GateStateV2; projection_digest: str; contract_digest: str; authority_commitment_digest: str; base_snapshot_digest: str | None; cursor_state_digest: str | None; incoming_cursor_digest: str | None; incoming_continuation_ref: str | None; candidates: tuple[CandidateOutcomeV2, ...]; conflicts: tuple[ConflictOutcomeV2, ...]; citations: tuple[RecallCitationV2, ...]; continuation: RecallContinuationV2 | None; snapshot_digest: str
    FIELDS: ClassVar[set[str]] = {"snapshot_version", "snapshot_attestation_version", "snapshot_signer_ref", "snapshot_signer_algorithm", "snapshot_key_id", "snapshot_signature", "provenance_component_labels", "provenance_component_states", "has_more", "pagination_commitment_digest", "selected_candidates_digest", "selected_citations_digest", "selected_conflicts_digest", "workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "query_digest", "transaction_cut", "valid_at", "recorded_at", "scope_digest", "authority_provenance_ref", "authority_provenance_digest", *_AUTHORITY_FIELDS, "authorization", "global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent", "projection_digest", "contract_digest", "authority_commitment_digest", "base_snapshot_digest", "cursor_state_digest", "incoming_cursor_digest", "incoming_continuation_ref", "candidates", "conflicts", "citations", "continuation", "snapshot_digest"}
    def __post_init__(self) -> None:
        if self.snapshot_version != RECALL_SERVE_SNAPSHOT_V2 or self.snapshot_attestation_version != "second-brain-recall-snapshot-attestation-v2": raise InvalidContractValue("unsupported snapshot version or attestation version")
        _ref(self.snapshot_signer_ref, "snapshot_signer_ref", "signer"); _ref(self.snapshot_key_id, "snapshot_key_id", "key")
        if self.snapshot_signer_algorithm != "Ed25519" or not isinstance(self.snapshot_signature, str) or not self.snapshot_signature or len(self.snapshot_signature) > 4096 or any(c.isspace() for c in self.snapshot_signature): raise InvalidContractValue("snapshot attestation must be Ed25519 signed evidence")
        if not isinstance(self.has_more, bool): raise InvalidContractValue("has_more must be boolean")
        object.__setattr__(self, "provenance_component_states", _typed_tuple(self.provenance_component_states, GateStateV2, "provenance_component_states"))
        if not isinstance(self.provenance_component_labels, (tuple, list)) or tuple(self.provenance_component_labels) != _REQUIRED_PROVENANCE_COMPONENTS or len(self.provenance_component_states) != len(_REQUIRED_PROVENANCE_COMPONENTS): raise InvalidContractValue("snapshot requires complete named provenance component states")
        object.__setattr__(self, "provenance_component_labels", tuple(self.provenance_component_labels))
        _digest(self.pagination_commitment_digest, "pagination_commitment_digest"); _digest(self.selected_candidates_digest, "selected_candidates_digest"); _digest(self.selected_citations_digest, "selected_citations_digest"); _digest(self.selected_conflicts_digest, "selected_conflicts_digest")
        object.__setattr__(self, "candidates", _typed_tuple(self.candidates, CandidateOutcomeV2, "candidates")); object.__setattr__(self, "conflicts", _typed_tuple(self.conflicts, ConflictOutcomeV2, "conflicts")); object.__setattr__(self, "citations", _typed_tuple(self.citations, RecallCitationV2, "citations"))
        if isinstance(self.authorization, Mapping): object.__setattr__(self, "authorization", RecallAuthorityV2.from_mapping(self.authorization))
        for name in ("global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent"):
            if isinstance(getattr(self, name), Mapping): object.__setattr__(self, name, GateStateV2.from_mapping(getattr(self, name)))
        if isinstance(self.continuation, Mapping): object.__setattr__(self, "continuation", RecallContinuationV2.from_mapping(self.continuation))
        _ref(self.workspace_ref, "workspace_ref", "workspace"); _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True); _ref(self.subject_ref, "subject_ref")
        if not isinstance(self.action, str) or not self.action or len(self.action) > 128: raise InvalidContractValue("snapshot action required")
        _digest(self.query_digest, "query_digest"); _decimal(self.transaction_cut, "transaction_cut", True); _digest(self.scope_digest, "scope_digest"); _ref(self.authority_provenance_ref, "authority_provenance_ref", "provenance"); _digest(self.authority_provenance_digest, "authority_provenance_digest"); _authority_values(self); _digest(self.projection_digest, "projection_digest"); _digest(self.contract_digest, "contract_digest"); _digest(self.authority_commitment_digest, "authority_commitment_digest")
        if self.base_snapshot_digest is not None:
            _digest(self.base_snapshot_digest, "base_snapshot_digest")
            _digest(self.cursor_state_digest, "cursor_state_digest")
        elif self.cursor_state_digest is not None:
            raise InvalidContractValue("cursor_state_digest requires a base snapshot")
        if self.incoming_cursor_digest is not None: _digest(self.incoming_cursor_digest, "incoming_cursor_digest")
        if self.incoming_continuation_ref is not None: _ref(self.incoming_continuation_ref, "incoming_continuation_ref", "continuation")
        if (self.base_snapshot_digest is None, self.incoming_cursor_digest is None, self.incoming_continuation_ref is None).count(True) not in {0, 3}: raise InvalidContractValue("incoming continuation chain fields must be all present or absent")
        va, _ = _instant(self.valid_at, "valid_at"); ra, recorded = _instant(self.recorded_at, "recorded_at"); object.__setattr__(self, "valid_at", va); object.__setattr__(self, "recorded_at", ra)
        gates = (self.global_floor, self.binding, self.recovery, self.route, self.cohort, self.deletion, self.consent)
        if not isinstance(self.authorization, RecallAuthorityV2) or not all(isinstance(x, GateStateV2) and x.epoch == self.authority_epoch for x in gates): raise InvalidContractValue("typed, authority-epoch-bound gate states required")
        if tuple(getattr(self.authorization, x) for x in ("capability_ref", "authority_epoch", "query_digest", "workspace_ref", "scope_digest")) != (self.capability_ref, self.authority_epoch, self.query_digest, self.workspace_ref, self.scope_digest): raise InvalidContractValue("authorization is not snapshot-bound")
        if self.authority_commitment_digest != _authority_commitment(self): raise InvalidContractValue("authority commitment does not bind snapshot authority")
        blocked = any(g.state != "PASS" for g in gates)
        if (blocked or self.authorization.decision != "ALLOW") and (self.candidates or self.conflicts or self.citations or self.continuation): raise InvalidContractValue("non-allow authority cannot disclose results")
        if blocked and self.authorization.decision != ("DENY" if any(g.state == "DENY" for g in gates) else "ABSTAIN"): raise InvalidContractValue("gate decision precedence is invalid")
        displayed = {x.candidate_ref for x in self.candidates}
        if len(displayed) != len(self.candidates) or tuple(x.candidate_ref for x in self.candidates) != tuple(sorted(displayed)) or any(x.state != "APPROVED" for x in self.candidates):
            raise InvalidContractValue("only unique canonically ordered approved candidates may be displayed")
        revisions = {x.candidate_ref: x.revision_ref for x in self.candidates}
        if any(x.left_candidate_ref not in displayed or x.right_candidate_ref not in displayed for x in self.conflicts) or any(x.candidate_ref not in displayed or x.evidence.revision_ref != revisions[x.candidate_ref] for x in self.citations):
            raise InvalidContractValue("outcomes must bind displayed revisions")
        if tuple(x.candidate_ref for x in self.citations) != tuple(sorted(x.candidate_ref for x in self.citations)) or {x.candidate_ref for x in self.citations} != displayed:
            raise InvalidContractValue("exactly one canonically ordered citation is required per displayed candidate")
        if tuple((x.left_candidate_ref, x.right_candidate_ref) for x in self.conflicts) != tuple(sorted((x.left_candidate_ref, x.right_candidate_ref) for x in self.conflicts)) or len({(x.left_candidate_ref, x.right_candidate_ref) for x in self.conflicts}) != len(self.conflicts):
            raise InvalidContractValue("conflicts must be unique and canonically ordered")
        if any(any(ref not in displayed for ref in candidate.support_refs) for candidate in self.candidates):
            raise InvalidContractValue("support references must be restricted to displayed candidates")
        if any(conflict.state == "RESOLVED" and (conflict.winning_candidate_ref not in revisions or conflict.winning_revision_citation is None or revisions[conflict.winning_candidate_ref] != conflict.winning_revision_citation.revision_ref) for conflict in self.conflicts):
            raise InvalidContractValue("conflict winner must identify a side and cite that displayed revision")
        if self.selected_candidates_digest != canonical_ledger_digest("snapshot-selected-candidates-v2", {"candidates": [x.to_mapping() for x in self.candidates]}) or self.selected_citations_digest != canonical_ledger_digest("snapshot-selected-citations-v2", {"citations": [x.to_mapping() for x in self.citations]}) or self.selected_conflicts_digest != canonical_ledger_digest("snapshot-selected-conflicts-v2", {"conflicts": [x.to_mapping() for x in self.conflicts]}): raise InvalidContractValue("selected result commitments do not bind exact canonical selections")
        pagination = {"has_more": self.has_more, "cursor_state_digest": None if self.continuation is None else self.continuation.cursor_state_digest, "terminal": self.continuation is None}
        if self.has_more != (self.continuation is not None) or self.pagination_commitment_digest != canonical_ledger_digest("snapshot-pagination-v2", pagination): raise InvalidContractValue("pagination commitment does not bind outgoing continuation presence")
        snapshot_body = {k: v for k, v in self.to_mapping().items() if k not in {"snapshot_digest", "continuation", "snapshot_signature"}}
        _bound(self.snapshot_digest, "snapshot_digest", "snapshot-v2", snapshot_body)
        if self.continuation:
            fields = ("workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "query_digest", "scope_digest", "valid_at", "recorded_at", "transaction_cut", "authority_provenance_ref", "authority_provenance_digest", *_AUTHORITY_FIELDS, "authority_commitment_digest")
            if any(getattr(self.continuation, x) != getattr(self, x) for x in fields) or self.continuation.base_snapshot_digest != self.snapshot_digest or _instant(self.continuation.expires_at, "expires_at")[1] <= recorded: raise InvalidContractValue("continuation is not fresh snapshot authority")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallServeSnapshotV2": return cls(**_strict(data, cls.FIELDS))
    def to_mapping(self) -> dict[str, Any]:
        result = {k: getattr(self, k) for k in self.FIELDS}; result.update({"provenance_component_labels": list(self.provenance_component_labels), "provenance_component_states": [x.to_mapping() for x in self.provenance_component_states], "authorization": self.authorization.to_mapping(), "candidates": [x.to_mapping() for x in self.candidates], "conflicts": [x.to_mapping() for x in self.conflicts], "citations": [x.to_mapping() for x in self.citations], "continuation": None if self.continuation is None else self.continuation.to_mapping()}); result.update({n: getattr(self, n).to_mapping() for n in ("global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent")}); return result


def _request_provenance_binding(request: RecallSnapshotRequestV2) -> str:
    # This intentionally excludes provenance identity and request_digest, avoiding a digest cycle.
    body = {
        key: (
            request.continuation.to_mapping()
            if key == "continuation" and request.continuation is not None
            else getattr(request, key)
        )
        for key in RecallSnapshotRequestV2.FIELDS
        - {"authority_provenance_ref", "authority_provenance_digest", "request_digest"}
    }
    return canonical_ledger_digest("request-provenance-binding-v2", body)

def _verify_provenance(authority: RecallTrustAuthorityV2, request: RecallSnapshotRequestV2, now: str) -> None:
    provenance = authority._provenance(request.authority_provenance_ref, request.authority_provenance_digest)
    provenance.validate_at(now)
    if provenance.signer_algorithm != "Ed25519" or provenance.request_digest != _request_provenance_binding(request) or any(getattr(provenance, name) != getattr(request, name) for name in ("workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "query_digest", "scope_digest", "transaction_cut")):
        raise InvalidContractValue("authority provenance is not request-bound")
    if not authority._verify(signer_ref=provenance.signer_ref, algorithm=provenance.signer_algorithm, key_id=provenance.key_id, signature=provenance.signature, body=provenance.signing_body()):
        raise InvalidContractValue("authority provenance signature verification failed")

def _verify_continuation(authority: RecallTrustAuthorityV2, continuation: RecallContinuationV2, now: str) -> None:
    if not (_instant(continuation.issued_at, "issued_at")[1] <= _instant(now, "trusted_now")[1] < _instant(continuation.expires_at, "expires_at")[1]):
        raise InvalidContractValue("expired continuation cannot acquire a snapshot")
    if not authority._verify(signer_ref=continuation.signer_ref, algorithm=continuation.signer_algorithm, key_id=continuation.key_id, signature=continuation.signature, body=continuation.signing_body()):
        raise InvalidContractValue("continuation signature verification failed")

def _snapshot_attestation_body(result: RecallServeSnapshotV2) -> dict[str, Any]:
    """Non-cyclic, domain-separated trusted result envelope; excludes only its signature."""
    return {k: v for k, v in result.to_mapping().items() if k not in {"snapshot_signature", "continuation"}}

def _verify_snapshot_attestation(authority: RecallTrustAuthorityV2, result: RecallServeSnapshotV2, provenance: AuthorityProvenanceV2) -> None:
    if tuple(result.provenance_component_labels) != provenance.component_labels or tuple((x.epoch, x.digest, x.state) for x in result.provenance_component_states) != tuple((x.epoch, x.digest, x.state) for x in provenance.component_states):
        raise InvalidContractValue("snapshot provenance component states do not exactly match signed authority provenance")
    gates = (result.global_floor, result.binding, result.recovery, result.route, result.cohort, result.deletion, result.consent)
    named = dict(zip(result.provenance_component_labels, result.provenance_component_states, strict=True))
    if any(named[name] != gate for name, gate in zip(_REQUIRED_PROVENANCE_COMPONENTS[1:], gates, strict=True)):
        raise InvalidContractValue("snapshot provenance component states do not exactly match authorization gates")
    authorization = named["authorization"]
    expected = "PASS" if result.authorization.decision == "ALLOW" else ("DENY" if result.authorization.decision == "DENY" else "ABSTAIN")
    if authorization.state != expected or authorization.epoch != result.authority_epoch:
        raise InvalidContractValue("snapshot provenance authorization component does not match authorization decision")
    for conflict in result.conflicts:
        if conflict.state != "RESOLVED":
            continue
        decision_provenance = authority._provenance(conflict.authority_provenance_ref, conflict.authority_provenance_digest)
        decision_provenance.validate_at(authority._now())
        conflict_payload_digest = canonical_ledger_digest(
            "resolve-conflict-payload-v2",
            {
                "left_candidate_ref": conflict.left_candidate_ref,
                "right_candidate_ref": conflict.right_candidate_ref,
                "winning_candidate_ref": conflict.winning_candidate_ref,
                "expected_decision_revision_ref": conflict.expected_decision_revision_ref,
                "winning_revision_evidence_digest": conflict.winning_revision_citation.evidence_digest,
            },
        )
        if (
            decision_provenance.action != "RESOLVE_CONFLICT"
            or decision_provenance.workspace_ref != result.workspace_ref
            or decision_provenance.capability_ref != result.capability_ref
            or decision_provenance.authority_epoch != result.authority_epoch
            or decision_provenance.subject_ref != result.subject_ref
            or decision_provenance.scope_digest != result.scope_digest
            or decision_provenance.command_payload_digest != conflict_payload_digest
            or any(component.state != "PASS" for component in decision_provenance.component_states)
        ):
            raise InvalidContractValue("resolved conflict decision provenance is not snapshot authority-bound")
        if not authority._verify(signer_ref=decision_provenance.signer_ref, algorithm=decision_provenance.signer_algorithm, key_id=decision_provenance.key_id, signature=decision_provenance.signature, body=decision_provenance.signing_body()):
            raise InvalidContractValue("resolved conflict decision provenance signature verification failed")
    if not authority._verify(signer_ref=result.snapshot_signer_ref, algorithm=result.snapshot_signer_algorithm, key_id=result.snapshot_key_id, signature=result.snapshot_signature, body=_snapshot_attestation_body(result), domain="snapshot-attestation-v2"):
        raise InvalidContractValue("snapshot attestation signature verification failed")

def validate_recall_snapshot_acquisition(request: RecallSnapshotRequestV2, result: RecallServeSnapshotV2, authority: RecallTrustAuthorityV2) -> RecallServeSnapshotV2:
    """Mandatory trusted admission; structural parsing never verifies signatures."""
    if not isinstance(request, RecallSnapshotRequestV2) or not isinstance(result, RecallServeSnapshotV2) or not isinstance(authority, RecallTrustAuthorityV2):
        raise InvalidContractValue("snapshot acquisition requires a minted RecallTrustAuthorityV2")
    now = authority._now()
    _verify_provenance(authority, request, now)
    _verify_snapshot_attestation(authority, result, authority._provenance(result.authority_provenance_ref, result.authority_provenance_digest))
    fields = ("workspace_ref", "capability_ref", "authority_epoch", "subject_ref", "action", "query_digest", "transaction_cut", "valid_at", "recorded_at", "scope_digest", "authority_provenance_ref", "authority_provenance_digest")
    if any(getattr(request, field) != getattr(result, field) for field in fields): raise InvalidContractValue("snapshot result is not request-bound")
    if request.continuation:
        _verify_continuation(authority, request.continuation, now)
        if (
            result.base_snapshot_digest != request.continuation.base_snapshot_digest
            or result.incoming_continuation_ref != request.continuation.continuation_ref
            or result.incoming_cursor_digest
            != canonical_ledger_digest(
                "cursor-v2",
                {
                    "cursor_handle_ref": request.continuation.cursor_handle_ref,
                    "cursor_state_digest": request.continuation.cursor_state_digest,
                    "base_snapshot_digest": request.continuation.base_snapshot_digest,
                },
            )
        ):
            raise InvalidContractValue("continuation chain drift")
    elif any(value is not None for value in (result.base_snapshot_digest, result.incoming_cursor_digest, result.incoming_continuation_ref)):
        raise InvalidContractValue("initial page cannot carry continuation chain fields")
    if result.continuation: _verify_continuation(authority, result.continuation, now)
    return result

def make_recall_continuation_v2(body: Mapping[str, Any]) -> RecallContinuationV2:
    """Build a digest-bound continuation from its complete signing body."""
    values = _strict(body, RecallContinuationV2.FIELDS - {"continuation_digest"})
    values["continuation_digest"] = canonical_ledger_digest("continuation-v2", {k: v for k, v in values.items() if k != "signature"})
    return RecallContinuationV2.from_mapping(values)
def validate_recall_continuation_at(continuation: RecallContinuationV2, authority: RecallTrustAuthorityV2) -> VerifiedRecallContinuationV2:
    """Verify a continuation only through the minted trust boundary."""
    if not isinstance(continuation, RecallContinuationV2) or not isinstance(authority, RecallTrustAuthorityV2):
        raise InvalidContractValue("typed continuation and minted trust authority required")
    _verify_continuation(authority, continuation, authority._now())
    return VerifiedRecallContinuationV2(continuation)

def make_recall_snapshot_v2(body: Mapping[str, Any]) -> RecallServeSnapshotV2:
    """Build a digest-bound snapshot; continuations must already bind its base digest."""
    values = _strict(body, RecallServeSnapshotV2.FIELDS - {"snapshot_digest", "authority_commitment_digest", "pagination_commitment_digest", "selected_candidates_digest", "selected_citations_digest", "selected_conflicts_digest"})
    authority_values = dict(values)
    if isinstance(authority_values["authorization"], Mapping):
        authority_values["authorization"] = RecallAuthorityV2.from_mapping(authority_values["authorization"])
    for name in ("global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent"):
        if isinstance(authority_values[name], Mapping):
            authority_values[name] = GateStateV2.from_mapping(authority_values[name])
    authority_source = type("AuthoritySource", (), authority_values)()
    values["authority_commitment_digest"] = _authority_commitment(authority_source)
    values["selected_candidates_digest"] = canonical_ledger_digest("snapshot-selected-candidates-v2", {"candidates": values["candidates"]})
    values["selected_citations_digest"] = canonical_ledger_digest("snapshot-selected-citations-v2", {"citations": values["citations"]})
    values["selected_conflicts_digest"] = canonical_ledger_digest("snapshot-selected-conflicts-v2", {"conflicts": values["conflicts"]})
    continuation = values["continuation"]
    values["pagination_commitment_digest"] = canonical_ledger_digest("snapshot-pagination-v2", {"has_more": values["has_more"], "cursor_state_digest": None if continuation is None else continuation["cursor_state_digest"], "terminal": continuation is None})
    digest_body = {k: v for k, v in values.items() if k not in {"continuation", "snapshot_signature"}}
    values["snapshot_digest"] = canonical_ledger_digest("snapshot-v2", digest_body)
    return RecallServeSnapshotV2.from_mapping(values)
def validate_ledger_recall_v2_semantics(wire: Mapping[str, Any]) -> Any:
    """Structural/semantic parsing only; it never admits cryptographic authority or snapshots."""
    if not isinstance(wire, Mapping):
        raise InvalidContractValue("wire must be an object")
    version = wire.get("command_version") or wire.get("receipt_version") or wire.get("request_version") or wire.get("snapshot_version") or wire.get("continuation_version") or wire.get("citation_version") or wire.get("evidence_version") or wire.get("decision_version") or wire.get("provenance_version")
    parsers = {
        LEDGER_COMMAND_V2: LedgerCommandV2, LEDGER_RECEIPT_V2: LedgerReceiptV2,
        RECALL_SNAPSHOT_REQUEST_V2: RecallSnapshotRequestV2, RECALL_SERVE_SNAPSHOT_V2: RecallServeSnapshotV2,
        RECALL_CONTINUATION_V2: RecallContinuationV2, RECALL_CITATION_V2: RecallCitationV2,
        "second-brain-citation-evidence-v2": CitationEvidenceV2, "second-brain-conflict-decision-v2": ConflictOutcomeV2,
        "second-brain-authority-provenance-v2": AuthorityProvenanceV2,
    }
    parser = parsers.get(version)
    if parser is None:
        raise InvalidContractValue("unknown ledger recall wire version")
    return parser.from_mapping(wire)
