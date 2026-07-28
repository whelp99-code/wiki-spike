"""Closed, immutable Stage-3 ledger and atomic recall authority contracts."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any, ClassVar

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


def canonical_ledger_digest(domain: str, body: Mapping[str, Any]) -> str:
    if not isinstance(domain, str) or not domain:
        raise InvalidContractValue("digest domain must be non-empty")
    try:
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise InvalidContractValue("digest body must be canonical JSON") from exc
    return sha256(b"second-brain-ledger/" + domain.encode("ascii") + b"\0" + encoded).hexdigest()


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
    command_version: str; command_ref: str; workspace_ref: str; capability_ref: str; authority_epoch: str; kind: str; target_candidate_ref: str | None; related_candidate_refs: tuple[str, ...]; interval: BitemporalIntervalV2; payload: CommandPayloadV2; command_digest: str
    FIELDS: ClassVar[set[str]] = {"command_version", "command_ref", "workspace_ref", "capability_ref", "authority_epoch", "kind", "target_candidate_ref", "related_candidate_refs", "interval", "payload", "command_digest"}
    def __post_init__(self) -> None:
        if self.command_version != LEDGER_COMMAND_V2 or self.kind not in COMMAND_KINDS: raise InvalidContractValue("closed command version or kind")
        _ref(self.command_ref, "command_ref", "command"); _ref(self.workspace_ref, "workspace_ref", "workspace"); _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True)
        if not isinstance(self.related_candidate_refs, (tuple, list)): raise InvalidContractValue("related_candidate_refs must be an array")
        object.__setattr__(self, "related_candidate_refs", tuple(self.related_candidate_refs))
        if isinstance(self.interval, Mapping): object.__setattr__(self, "interval", BitemporalIntervalV2.from_mapping(self.interval))
        if isinstance(self.payload, Mapping): object.__setattr__(self, "payload", CommandPayloadV2.from_mapping(self.payload))
        if not isinstance(self.interval, BitemporalIntervalV2) or not isinstance(self.payload, CommandPayloadV2): raise InvalidContractValue("typed command values required")
        if len(set(self.related_candidate_refs)) != len(self.related_candidate_refs): raise InvalidContractValue("candidate references must be unique")
        for value in self.related_candidate_refs: _ref(value, "related_candidate_refs", "candidate")
        if self.target_candidate_ref is not None: _ref(self.target_candidate_ref, "target_candidate_ref", "candidate")
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
    def to_mapping(self) -> dict[str, Any]: return {"command_version": self.command_version, "command_ref": self.command_ref, "workspace_ref": self.workspace_ref, "capability_ref": self.capability_ref, "authority_epoch": self.authority_epoch, "kind": self.kind, "target_candidate_ref": self.target_candidate_ref, "related_candidate_refs": list(self.related_candidate_refs), "interval": self.interval.to_mapping(), "payload": self.payload.to_mapping(), "command_digest": self.command_digest}


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
    "workspace_ref", "capability_ref", "authority_epoch", "query_digest", "scope_digest",
    "transaction_cut", *_AUTHORITY_FIELDS, "authorization", "global_floor", "binding",
    "recovery", "route", "cohort", "deletion", "consent", "projection_digest", "contract_digest",
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
    continuation_version: str; continuation_ref: str; workspace_ref: str; capability_ref: str; authority_epoch: str; query_digest: str; scope_digest: str; transaction_cut: str; generation_ref: str; generation_digest: str; checkpoint_ref: str; checkpoint_digest: str; freshness_digest: str; authority_checkpoint_digest: str; authority_commitment_digest: str; base_snapshot_digest: str; cursor: str; expires_at: str; continuation_digest: str
    FIELDS: ClassVar[set[str]] = {"continuation_version", "continuation_ref", "workspace_ref", "capability_ref", "authority_epoch", "query_digest", "scope_digest", "transaction_cut", *_AUTHORITY_FIELDS, "authority_commitment_digest", "base_snapshot_digest", "cursor", "expires_at", "continuation_digest"}
    def __post_init__(self) -> None:
        if self.continuation_version != RECALL_CONTINUATION_V2 or not isinstance(self.cursor, str) or not self.cursor: raise InvalidContractValue("invalid continuation")
        _ref(self.continuation_ref, "continuation_ref", "continuation"); _ref(self.workspace_ref, "workspace_ref", "workspace"); _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True); _digest(self.query_digest, "query_digest"); _digest(self.scope_digest, "scope_digest"); _decimal(self.transaction_cut, "transaction_cut", True); _authority_values(self); _digest(self.authority_commitment_digest, "authority_commitment_digest"); _digest(self.base_snapshot_digest, "base_snapshot_digest")
        expires, _ = _instant(self.expires_at, "expires_at"); object.__setattr__(self, "expires_at", expires)
        _bound(self.continuation_digest, "continuation_digest", "continuation-v2", {k: getattr(self, k) for k in self.FIELDS - {"continuation_digest"}})
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallContinuationV2": return cls(**_strict(data, cls.FIELDS))
    def to_mapping(self) -> dict[str, Any]: return {k: getattr(self, k) for k in self.FIELDS}


@dataclass(frozen=True)
class RecallSnapshotRequestV2:
    request_version: str; workspace_ref: str; capability_ref: str; authority_epoch: str; query_digest: str; valid_at: str; recorded_at: str; scope_digest: str; continuation: RecallContinuationV2 | None; request_digest: str
    FIELDS: ClassVar[set[str]] = {"request_version", "workspace_ref", "capability_ref", "authority_epoch", "query_digest", "valid_at", "recorded_at", "scope_digest", "continuation", "request_digest"}
    def __post_init__(self) -> None:
        if isinstance(self.continuation, Mapping): object.__setattr__(self, "continuation", RecallContinuationV2.from_mapping(self.continuation))
        if self.request_version != RECALL_SNAPSHOT_REQUEST_V2 or (self.continuation is not None and not isinstance(self.continuation, RecallContinuationV2)): raise InvalidContractValue("invalid request")
        _ref(self.workspace_ref, "workspace_ref", "workspace"); _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True); _digest(self.query_digest, "query_digest"); _digest(self.scope_digest, "scope_digest")
        va, _ = _instant(self.valid_at, "valid_at"); ra, _ = _instant(self.recorded_at, "recorded_at"); object.__setattr__(self, "valid_at", va); object.__setattr__(self, "recorded_at", ra)
        if self.continuation and tuple(getattr(self.continuation, x) for x in ("workspace_ref", "capability_ref", "authority_epoch", "query_digest", "scope_digest")) != (self.workspace_ref, self.capability_ref, self.authority_epoch, self.query_digest, self.scope_digest): raise InvalidContractValue("continuation is not request-bound")
        _bound(self.request_digest, "request_digest", "request-v2", {k: v for k, v in self.to_mapping().items() if k != "request_digest"})
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallSnapshotRequestV2": return cls(**_strict(data, cls.FIELDS))
    def to_mapping(self) -> dict[str, Any]: return {"request_version": self.request_version, "workspace_ref": self.workspace_ref, "capability_ref": self.capability_ref, "authority_epoch": self.authority_epoch, "query_digest": self.query_digest, "valid_at": self.valid_at, "recorded_at": self.recorded_at, "scope_digest": self.scope_digest, "continuation": None if self.continuation is None else self.continuation.to_mapping(), "request_digest": self.request_digest}


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
    citation_version: str; candidate_ref: str; source_ref: str; citation_digest: str
    def __post_init__(self) -> None:
        if self.citation_version != RECALL_CITATION_V2: raise InvalidContractValue("unsupported citation_version")
        _ref(self.candidate_ref, "candidate_ref", "candidate"); _ref(self.source_ref, "source_ref"); _digest(self.citation_digest, "citation_digest")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallCitationV2": return cls(**_strict(data, {"citation_version", "candidate_ref", "source_ref", "citation_digest"}))
    def to_mapping(self) -> dict[str, Any]: return {"citation_version": self.citation_version, "candidate_ref": self.candidate_ref, "source_ref": self.source_ref, "citation_digest": self.citation_digest}

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
    left_candidate_ref: str; right_candidate_ref: str; state: str
    def __post_init__(self) -> None:
        _ref(self.left_candidate_ref, "left_candidate_ref", "candidate"); _ref(self.right_candidate_ref, "right_candidate_ref", "candidate")
        if self.left_candidate_ref == self.right_candidate_ref or self.state not in {"OPEN", "RESOLVED"}: raise InvalidContractValue("invalid conflict")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ConflictOutcomeV2": return cls(**_strict(data, {"left_candidate_ref", "right_candidate_ref", "state"}))
    def to_mapping(self) -> dict[str, Any]: return {"left_candidate_ref": self.left_candidate_ref, "right_candidate_ref": self.right_candidate_ref, "state": self.state}

@dataclass(frozen=True)
class RecallServeSnapshotV2:
    snapshot_version: str; workspace_ref: str; capability_ref: str; authority_epoch: str; query_digest: str; transaction_cut: str; valid_at: str; recorded_at: str; scope_digest: str; generation_ref: str; generation_digest: str; checkpoint_ref: str; checkpoint_digest: str; freshness_digest: str; authority_checkpoint_digest: str; authorization: RecallAuthorityV2; global_floor: GateStateV2; binding: GateStateV2; recovery: GateStateV2; route: GateStateV2; cohort: GateStateV2; deletion: GateStateV2; consent: GateStateV2; projection_digest: str; contract_digest: str; authority_commitment_digest: str; base_snapshot_digest: str | None; incoming_cursor_digest: str | None; incoming_continuation_ref: str | None; candidates: tuple[CandidateOutcomeV2, ...]; conflicts: tuple[ConflictOutcomeV2, ...]; citations: tuple[RecallCitationV2, ...]; continuation: RecallContinuationV2 | None; snapshot_digest: str
    FIELDS: ClassVar[set[str]] = {"snapshot_version", "workspace_ref", "capability_ref", "authority_epoch", "query_digest", "transaction_cut", "valid_at", "recorded_at", "scope_digest", *_AUTHORITY_FIELDS, "authorization", "global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent", "projection_digest", "contract_digest", "authority_commitment_digest", "base_snapshot_digest", "incoming_cursor_digest", "incoming_continuation_ref", "candidates", "conflicts", "citations", "continuation", "snapshot_digest"}
    def __post_init__(self) -> None:
        if self.snapshot_version != RECALL_SERVE_SNAPSHOT_V2: raise InvalidContractValue("unsupported snapshot_version")
        object.__setattr__(self, "candidates", _typed_tuple(self.candidates, CandidateOutcomeV2, "candidates")); object.__setattr__(self, "conflicts", _typed_tuple(self.conflicts, ConflictOutcomeV2, "conflicts")); object.__setattr__(self, "citations", _typed_tuple(self.citations, RecallCitationV2, "citations"))
        if isinstance(self.authorization, Mapping): object.__setattr__(self, "authorization", RecallAuthorityV2.from_mapping(self.authorization))
        for name in ("global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent"):
            if isinstance(getattr(self, name), Mapping): object.__setattr__(self, name, GateStateV2.from_mapping(getattr(self, name)))
        if isinstance(self.continuation, Mapping): object.__setattr__(self, "continuation", RecallContinuationV2.from_mapping(self.continuation))
        _ref(self.workspace_ref, "workspace_ref", "workspace"); _ref(self.capability_ref, "capability_ref", "capability"); _decimal(self.authority_epoch, "authority_epoch", True); _digest(self.query_digest, "query_digest"); _decimal(self.transaction_cut, "transaction_cut", True); _digest(self.scope_digest, "scope_digest"); _authority_values(self); _digest(self.projection_digest, "projection_digest"); _digest(self.contract_digest, "contract_digest"); _digest(self.authority_commitment_digest, "authority_commitment_digest")
        if self.base_snapshot_digest is not None: _digest(self.base_snapshot_digest, "base_snapshot_digest")
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
        if any(x.left_candidate_ref not in displayed or x.right_candidate_ref not in displayed for x in self.conflicts) or any(x.candidate_ref not in displayed for x in self.citations): raise InvalidContractValue("outcomes must bind displayed candidates")
        snapshot_body = {k: v for k, v in self.to_mapping().items() if k not in {"snapshot_digest", "continuation"}}
        _bound(self.snapshot_digest, "snapshot_digest", "snapshot-v2", snapshot_body)
        if self.continuation:
            fields = ("workspace_ref", "capability_ref", "authority_epoch", "query_digest", "scope_digest", "transaction_cut", *_AUTHORITY_FIELDS, "authority_commitment_digest")
            if any(getattr(self.continuation, x) != getattr(self, x) for x in fields) or self.continuation.base_snapshot_digest != self.snapshot_digest or _instant(self.continuation.expires_at, "expires_at")[1] <= recorded: raise InvalidContractValue("continuation is not fresh snapshot authority")
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallServeSnapshotV2": return cls(**_strict(data, cls.FIELDS))
    def to_mapping(self) -> dict[str, Any]:
        result = {k: getattr(self, k) for k in self.FIELDS}; result.update({"authorization": self.authorization.to_mapping(), "candidates": [x.to_mapping() for x in self.candidates], "conflicts": [x.to_mapping() for x in self.conflicts], "citations": [x.to_mapping() for x in self.citations], "continuation": None if self.continuation is None else self.continuation.to_mapping()}); result.update({n: getattr(self, n).to_mapping() for n in ("global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent")}); return result


def validate_recall_snapshot_acquisition(request: RecallSnapshotRequestV2, result: RecallServeSnapshotV2) -> RecallServeSnapshotV2:
    if not isinstance(request, RecallSnapshotRequestV2) or not isinstance(result, RecallServeSnapshotV2): raise InvalidContractValue("snapshot acquisition requires typed request and result")
    fields = ("workspace_ref", "capability_ref", "authority_epoch", "query_digest", "valid_at", "recorded_at", "scope_digest")
    if any(getattr(request, field) != getattr(result, field) for field in fields): raise InvalidContractValue("snapshot result is not request-bound")
    if request.continuation:
        chain = ("base_snapshot_digest", "incoming_continuation_ref")
        if any(getattr(result, f) != getattr(request.continuation, f) for f in chain) or result.incoming_cursor_digest != canonical_ledger_digest("cursor-v2", {"cursor": request.continuation.cursor}):
            raise InvalidContractValue("continuation chain drift")
        authority = ("transaction_cut", *_AUTHORITY_FIELDS, "authority_commitment_digest")
        if any(getattr(request.continuation, f) != getattr(result, f) for f in authority): raise InvalidContractValue("continuation authority drift")
        if _instant(request.continuation.expires_at, "expires_at")[1] <= _instant(result.recorded_at, "recorded_at")[1]: raise InvalidContractValue("expired continuation cannot acquire a snapshot")
    return result
def make_recall_continuation_v2(body: Mapping[str, Any]) -> RecallContinuationV2:
    """Build a digest-bound continuation from its complete public body."""
    values = _strict(body, RecallContinuationV2.FIELDS - {"continuation_digest"})
    values["continuation_digest"] = canonical_ledger_digest("continuation-v2", values)
    return RecallContinuationV2.from_mapping(values)


def make_recall_snapshot_v2(body: Mapping[str, Any]) -> RecallServeSnapshotV2:
    """Build a digest-bound snapshot; continuations must already bind its base digest."""
    values = _strict(body, RecallServeSnapshotV2.FIELDS - {"snapshot_digest", "authority_commitment_digest"})
    authority_values = dict(values)
    if isinstance(authority_values["authorization"], Mapping):
        authority_values["authorization"] = RecallAuthorityV2.from_mapping(authority_values["authorization"])
    for name in ("global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent"):
        if isinstance(authority_values[name], Mapping):
            authority_values[name] = GateStateV2.from_mapping(authority_values[name])
    authority_source = type("AuthoritySource", (), authority_values)()
    values["authority_commitment_digest"] = _authority_commitment(authority_source)
    digest_body = {k: v for k, v in values.items() if k != "continuation"}
    values["snapshot_digest"] = canonical_ledger_digest("snapshot-v2", digest_body)
    return RecallServeSnapshotV2.from_mapping(values)
