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
SOURCE_ITEM_DISPOSITION_VERSION = "second-brain-source-item-disposition-v1"
SOURCE_ITEM_VERSION = "second-brain-source-item-v1"
SOURCE_PAGE_VERSION = "second-brain-source-page-v1"
SOURCE_CHECKPOINT_VERSION = "second-brain-source-checkpoint-v1"
CUTOVER_RUNBOOK_VERSION = "second-brain-cutover-runbook-v1"
PRE_MUTATION_ROLLBACK_RECEIPT_VERSION = "second-brain-pre-mutation-rollback-receipt-v1"
ROUTE_SWITCH_RECEIPT_VERSION = "second-brain-route-switch-receipt-v1"
ROUTE_AUTHORITY_STATE_VERSION = "second-brain-route-authority-state-v1"
ACTIVATION_RECEIPT_V1 = "second-brain-activation-receipt-v1"
CONSENT_TRANSFER_RECEIPT_V1 = "second-brain-consent-transfer-receipt-v1"
DECOMMISSION_CERTIFICATE_REQUEST_V1 = "second-brain-decommission-certificate-request-v1"
DECOMMISSION_CERTIFICATE_V1 = "second-brain-decommission-certificate-v1"
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


def _nullable_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _text(value, field)


def _source_cursor(value: Any, field: str) -> str | None:
    value = _nullable_text(value, field)
    if value is not None and (len(value) > 512 or "\x00" in value):
        raise InvalidContractValue(f"{field} must be a bounded opaque cursor")
    return value


def _native_identifier(value: Any, field: str) -> str:
    value = _text(value, field)
    if len(value) > 512 or "\x00" in value:
        raise InvalidContractValue(f"{field} must be a bounded opaque identifier")
    return value


def route_switch_digest(domain: str, body: Mapping[str, Any]) -> str:
    """Domain-separate immutable route-control DTO digests.

    Stage-0's generic contract digest intentionally has no route-control
    dependencies.  Keeping this tiny helper here avoids an import cycle with
    the Stage-3 ledger while retaining an explicit, canonical digest domain.
    """
    if not isinstance(domain, str) or not domain:
        raise InvalidContractValue("route switch digest domain must be non-empty")
    try:
        return sha256(canonical_bytes({"domain": domain, "body": dict(body)})).hexdigest()
    except (TypeError, ValueError) as exc:
        raise InvalidContractValue("route switch digest body must be canonical") from exc


@dataclass(frozen=True)
class SourceItemDispositionV1:
    """A content-free, retry-safe outcome for one pinned native revision."""

    disposition_version: str; native_id: str; revision: str; disposition: str; reason_code: str; retryable: bool
    FIELDS: ClassVar[set[str]] = {"disposition_version", "native_id", "revision", "disposition", "reason_code", "retryable"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SourceItemDispositionV1":
        v = _strict(data, cls.FIELDS)
        if v["disposition_version"] != SOURCE_ITEM_DISPOSITION_VERSION:
            raise UnsupportedContractVersion("unsupported disposition_version")
        disposition = _text(v["disposition"], "disposition")
        if disposition not in {"ACCEPTED", "DUPLICATE", "TOMBSTONE", "SKIPPED", "QUARANTINED", "TRANSIENT_FAILURE"}:
            raise InvalidContractValue("unsupported source item disposition")
        reason_code = _text(v["reason_code"], "reason_code")
        if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", reason_code) is None:
            raise InvalidContractValue("reason_code must be a bounded non-secret code")
        if not isinstance(v["retryable"], bool) or v["retryable"] != (disposition == "TRANSIENT_FAILURE"):
            raise InvalidContractValue("only transient failures may be retryable")
        return cls(SOURCE_ITEM_DISPOSITION_VERSION, _native_identifier(v["native_id"], "native_id"), _native_identifier(v["revision"], "revision"), disposition, reason_code, v["retryable"])

    def to_mapping(self) -> dict[str, Any]:
        return {"disposition_version": self.disposition_version, "native_id": self.native_id, "revision": self.revision, "disposition": self.disposition, "reason_code": self.reason_code, "retryable": self.retryable}


@dataclass(frozen=True)
class SourceItemV1:
    """One read-only native item. Raw content and credentials never cross this DTO."""

    item_version: str; native_id: str; revision: str; observed_cursor: str | None; observed_watermark: str | None; tombstone: bool; content_digest: str | None; disposition: SourceItemDispositionV1
    FIELDS: ClassVar[set[str]] = {"item_version", "native_id", "revision", "observed_cursor", "observed_watermark", "tombstone", "content_digest", "disposition"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SourceItemV1":
        v = _strict(data, cls.FIELDS)
        if v["item_version"] != SOURCE_ITEM_VERSION:
            raise UnsupportedContractVersion("unsupported item_version")
        if not isinstance(v["tombstone"], bool) or not isinstance(v["disposition"], Mapping):
            raise InvalidContractValue("source item tombstone and disposition are required")
        disposition = SourceItemDispositionV1.from_mapping(v["disposition"])
        native_id, revision = _native_identifier(v["native_id"], "native_id"), _native_identifier(v["revision"], "revision")
        if (disposition.native_id, disposition.revision) != (native_id, revision):
            raise InvalidContractValue("source item disposition must bind its native identity and revision")
        digest = v["content_digest"]
        if v["tombstone"]:
            if disposition.disposition != "TOMBSTONE" or digest is not None:
                raise InvalidContractValue("tombstones require TOMBSTONE disposition and no content digest")
        elif disposition.disposition == "TOMBSTONE" or not isinstance(digest, str):
            raise InvalidContractValue("non-tombstone source items require a non-tombstone disposition and digest")
        if digest is not None:
            digest = _digest(digest, "content_digest")
        return cls(SOURCE_ITEM_VERSION, native_id, revision, _source_cursor(v["observed_cursor"], "observed_cursor"), _source_cursor(v["observed_watermark"], "observed_watermark"), v["tombstone"], digest, disposition)

    def to_mapping(self) -> dict[str, Any]:
        return {"item_version": self.item_version, "native_id": self.native_id, "revision": self.revision, "observed_cursor": self.observed_cursor, "observed_watermark": self.observed_watermark, "tombstone": self.tombstone, "content_digest": self.content_digest, "disposition": self.disposition.to_mapping()}


@dataclass(frozen=True)
class SourcePageV1:
    """A bounded, pinned and explicitly non-authorizing source read page."""

    page_version: str; source_profile: str; source_scope: str; cursor: str | None; watermark: str | None; next_cursor: str | None; next_watermark: str | None; complete_snapshot: bool; items: tuple[SourceItemV1, ...]; live_operation_authorized: bool
    FIELDS: ClassVar[set[str]] = {"page_version", "source_profile", "source_scope", "cursor", "watermark", "next_cursor", "next_watermark", "complete_snapshot", "items", "live_operation_authorized"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SourcePageV1":
        v = _strict(data, cls.FIELDS)
        if v["page_version"] != SOURCE_PAGE_VERSION:
            raise UnsupportedContractVersion("unsupported page_version")
        source_profile = _text(v["source_profile"], "source_profile")
        if source_profile not in {"Codex", "Claude/Memory Bank", "Git", "Markdown"}:
            raise InvalidContractValue("source page must bind one approved source profile")
        if not isinstance(v["complete_snapshot"], bool) or v["live_operation_authorized"] is not False or not isinstance(v["items"], list):
            raise InvalidContractValue("source page must be complete-state typed and never authorize a live operation")
        cursor, watermark = _source_cursor(v["cursor"], "cursor"), _source_cursor(v["watermark"], "watermark")
        next_cursor, next_watermark = _source_cursor(v["next_cursor"], "next_cursor"), _source_cursor(v["next_watermark"], "next_watermark")
        if (cursor is None) != (watermark is None):
            raise InvalidContractValue("current cursor and watermark must be pinned as a pair")
        if (next_cursor is None) != (next_watermark is None):
            raise InvalidContractValue("next cursor and watermark must be pinned as a pair")
        items = tuple(SourceItemV1.from_mapping(item) for item in v["items"] if isinstance(item, Mapping))
        if len(items) != len(v["items"]) or len(items) > 1000:
            raise InvalidContractValue("source page items must be bounded objects")
        identities = tuple((item.native_id, item.revision) for item in items)
        if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
            raise InvalidContractValue("source page items must be sorted and unique by native revision")
        if any((item.observed_cursor, item.observed_watermark) != (next_cursor, next_watermark) for item in items):
            raise InvalidContractValue("each source item must pin the returned cursor and watermark")
        if any(item.tombstone for item in items) and not v["complete_snapshot"]:
            raise InvalidContractValue("tombstones require an explicit complete snapshot")
        return cls(SOURCE_PAGE_VERSION, source_profile, _native_identifier(v["source_scope"], "source_scope"), cursor, watermark, next_cursor, next_watermark, v["complete_snapshot"], items, False)

    def to_mapping(self) -> dict[str, Any]:
        return {"page_version": self.page_version, "source_profile": self.source_profile, "source_scope": self.source_scope, "cursor": self.cursor, "watermark": self.watermark, "next_cursor": self.next_cursor, "next_watermark": self.next_watermark, "complete_snapshot": self.complete_snapshot, "items": [item.to_mapping() for item in self.items], "live_operation_authorized": False}

    @property
    def digest(self) -> str:
        """Canonical page-body binding; raw source content never enters this digest."""
        return sha256(canonical_bytes(self.to_mapping())).hexdigest()


@dataclass(frozen=True)
class SourceCheckpointV1:
    """A compare-and-swap checkpoint; dispositions are durable before advancement."""

    checkpoint_version: str; source_profile: str; source_scope: str; observed_page_digest: str; prior_checkpoint_digest: str | None; cursor: str | None; watermark: str | None; dispositions: tuple[SourceItemDispositionV1, ...]; tombstones: tuple[tuple[str, str], ...]; checkpoint_digest: str; live_operation_authorized: bool
    FIELDS: ClassVar[set[str]] = {"checkpoint_version", "source_profile", "source_scope", "observed_page_digest", "prior_checkpoint_digest", "cursor", "watermark", "dispositions", "tombstones", "checkpoint_digest", "live_operation_authorized"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SourceCheckpointV1":
        v = _strict(data, cls.FIELDS)
        if v["checkpoint_version"] != SOURCE_CHECKPOINT_VERSION or v["live_operation_authorized"] is not False:
            raise InvalidContractValue("source checkpoints are versioned and never authorize live operations")
        source_profile = _text(v["source_profile"], "source_profile")
        if source_profile not in {"Codex", "Claude/Memory Bank", "Git", "Markdown"}:
            raise InvalidContractValue("checkpoint must bind one approved source profile")
        if not isinstance(v["dispositions"], list) or not isinstance(v["tombstones"], list):
            raise InvalidContractValue("checkpoint dispositions and tombstones must be arrays")
        dispositions = tuple(SourceItemDispositionV1.from_mapping(item) for item in v["dispositions"] if isinstance(item, Mapping))
        if len(dispositions) != len(v["dispositions"]):
            raise InvalidContractValue("checkpoint dispositions must be objects")
        identities = tuple((item.native_id, item.revision) for item in dispositions)
        if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
            raise InvalidContractValue("checkpoint dispositions must be sorted and unique")
        tombstones: list[tuple[str, str]] = []
        for entry in v["tombstones"]:
            if not isinstance(entry, Mapping):
                raise InvalidContractValue("checkpoint tombstones must be objects")
            item = _strict(entry, {"native_id", "revision"})
            tombstones.append((_native_identifier(item["native_id"], "tombstone.native_id"), _native_identifier(item["revision"], "tombstone.revision")))
        ordered_tombstones = tuple(tombstones)
        if ordered_tombstones != tuple(sorted(ordered_tombstones)) or len(set(ordered_tombstones)) != len(ordered_tombstones):
            raise InvalidContractValue("checkpoint tombstones must be sorted and unique")
        if ordered_tombstones != tuple((d.native_id, d.revision) for d in dispositions if d.disposition == "TOMBSTONE"):
            raise InvalidContractValue("checkpoint tombstones must exactly match TOMBSTONE dispositions")
        cursor, watermark = _source_cursor(v["cursor"], "cursor"), _source_cursor(v["watermark"], "watermark")
        if (cursor is None) != (watermark is None):
            raise InvalidContractValue("checkpoint cursor and watermark must be pinned as a pair")
        digest = _digest(v["checkpoint_digest"], "checkpoint_digest")
        body = {key: value for key, value in v.items() if key != "checkpoint_digest"}
        if sha256(canonical_bytes(body)).hexdigest() != digest:
            raise InvalidContractValue("checkpoint_digest does not bind the checkpoint body")
        return cls(SOURCE_CHECKPOINT_VERSION, source_profile, _native_identifier(v["source_scope"], "source_scope"), _digest(v["observed_page_digest"], "observed_page_digest"), None if v["prior_checkpoint_digest"] is None else _digest(v["prior_checkpoint_digest"], "prior_checkpoint_digest"), cursor, watermark, dispositions, ordered_tombstones, digest, False)

    def to_mapping(self) -> dict[str, Any]:
        return {"checkpoint_version": self.checkpoint_version, "source_profile": self.source_profile, "source_scope": self.source_scope, "observed_page_digest": self.observed_page_digest, "prior_checkpoint_digest": self.prior_checkpoint_digest, "cursor": self.cursor, "watermark": self.watermark, "dispositions": [item.to_mapping() for item in self.dispositions], "tombstones": [{"native_id": native_id, "revision": revision} for native_id, revision in self.tombstones], "checkpoint_digest": self.checkpoint_digest, "live_operation_authorized": False}


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


_ROUTE_APPROVER_ROLES = ("migration", "product", "quality", "security")
_ROUTE_RECEIPT_OPERATIONS = frozenset({"REHEARSE", "SWITCH_ATOMIC", "VERIFY"})
_ROUTE_VISIBILITY_MAXIMUM = 64


def _route_text(value: Any, field: str, *, maximum: int = 256) -> str:
    value = _text(value, field)
    if len(value) > maximum or "\x00" in value:
        raise InvalidContractValue(f"{field} must be a bounded opaque value")
    return value


def _route_epoch(value: Any, field: str) -> str:
    return _positive_decimal(value, field)


@dataclass(frozen=True, slots=True)
class RouteApprovalDigestV1:
    """One external four-role approval reference; approval payloads stay external."""

    role: str
    approval_digest: str
    FIELDS: ClassVar[set[str]] = {"role", "approval_digest"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RouteApprovalDigestV1":
        values = _strict(data, cls.FIELDS)
        role = _route_text(values["role"], "approval.role", maximum=32).lower()
        if role not in _ROUTE_APPROVER_ROLES:
            raise InvalidContractValue("approval.role is not a required cutover role")
        return cls(role, _digest(values["approval_digest"], "approval.approval_digest"))

    def to_mapping(self) -> dict[str, str]:
        return {"role": self.role, "approval_digest": self.approval_digest}


@dataclass(frozen=True, slots=True)
class CutoverRunbookV1:
    """Closed, hash-bound route runbook; it is evidence, never live authority."""

    runbook_version: str
    cohort_manifest_digest: str
    cutover_decision_digest: str
    route_authority: str
    target: str
    generation_digest: str
    route_version: str
    capability_epoch: str
    visibility: str
    pre_mutation_rollback_target: str
    pre_mutation_rollback_receipt_digest: str
    approval_digests: tuple[RouteApprovalDigestV1, ...]
    postcheck_contract_digest: str
    runbook_digest: str
    FIELDS: ClassVar[set[str]] = {
        "runbook_version", "cohort_manifest_digest", "cutover_decision_digest",
        "route_authority", "target", "generation_digest", "route_version",
        "capability_epoch", "visibility", "pre_mutation_rollback_target",
        "pre_mutation_rollback_receipt_digest", "approval_digests",
        "postcheck_contract_digest", "runbook_digest",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CutoverRunbookV1":
        values = _strict(data, cls.FIELDS)
        if values["runbook_version"] != CUTOVER_RUNBOOK_VERSION:
            raise UnsupportedContractVersion("unsupported cutover runbook version")
        raw_approvals = values["approval_digests"]
        if not isinstance(raw_approvals, list):
            raise InvalidContractValue("approval_digests must be a canonical array")
        approvals = tuple(
            RouteApprovalDigestV1.from_mapping(item)
            for item in raw_approvals
            if isinstance(item, Mapping)
        )
        if len(approvals) != len(raw_approvals):
            raise InvalidContractValue("approval_digests entries must be objects")
        roles = tuple(item.role for item in approvals)
        if roles != _ROUTE_APPROVER_ROLES or len(set(roles)) != len(_ROUTE_APPROVER_ROLES):
            raise InvalidContractValue(
                "approval_digests must be canonically ordered exact migration, product, quality, security"
            )
        body = {
            "runbook_version": CUTOVER_RUNBOOK_VERSION,
            "cohort_manifest_digest": _digest(values["cohort_manifest_digest"], "cohort_manifest_digest"),
            "cutover_decision_digest": _digest(values["cutover_decision_digest"], "cutover_decision_digest"),
            "route_authority": _route_text(values["route_authority"], "route_authority"),
            "target": _route_text(values["target"], "target"),
            "generation_digest": _digest(values["generation_digest"], "generation_digest"),
            "route_version": _route_text(values["route_version"], "route_version", maximum=64),
            "capability_epoch": _route_epoch(values["capability_epoch"], "capability_epoch"),
            "visibility": _route_text(values["visibility"], "visibility", maximum=_ROUTE_VISIBILITY_MAXIMUM),
            "pre_mutation_rollback_target": _route_text(
                values["pre_mutation_rollback_target"], "pre_mutation_rollback_target"
            ),
            "pre_mutation_rollback_receipt_digest": _digest(
                values["pre_mutation_rollback_receipt_digest"],
                "pre_mutation_rollback_receipt_digest",
            ),
            "approval_digests": [item.to_mapping() for item in approvals],
            "postcheck_contract_digest": _digest(
                values["postcheck_contract_digest"], "postcheck_contract_digest"
            ),
        }
        runbook_digest = _digest(values["runbook_digest"], "runbook_digest")
        if runbook_digest != route_switch_digest(CUTOVER_RUNBOOK_VERSION, body):
            raise InvalidContractValue("runbook_digest does not bind the cutover runbook")
        return cls(
            CUTOVER_RUNBOOK_VERSION,
            body["cohort_manifest_digest"], body["cutover_decision_digest"],
            body["route_authority"], body["target"], body["generation_digest"],
            body["route_version"], body["capability_epoch"], body["visibility"],
            body["pre_mutation_rollback_target"],
            body["pre_mutation_rollback_receipt_digest"], approvals,
            body["postcheck_contract_digest"], runbook_digest,
        )

    def body(self) -> dict[str, Any]:
        return {
            "runbook_version": self.runbook_version,
            "cohort_manifest_digest": self.cohort_manifest_digest,
            "cutover_decision_digest": self.cutover_decision_digest,
            "route_authority": self.route_authority,
            "target": self.target,
            "generation_digest": self.generation_digest,
            "route_version": self.route_version,
            "capability_epoch": self.capability_epoch,
            "visibility": self.visibility,
            "pre_mutation_rollback_target": self.pre_mutation_rollback_target,
            "pre_mutation_rollback_receipt_digest": self.pre_mutation_rollback_receipt_digest,
            "approval_digests": [item.to_mapping() for item in self.approval_digests],
            "postcheck_contract_digest": self.postcheck_contract_digest,
        }

    def to_mapping(self) -> dict[str, Any]:
        return self.body() | {"runbook_digest": self.runbook_digest}


@dataclass(frozen=True, slots=True)
class PreMutationRollbackReceiptV1:
    """A closed proof of the sole allowed rollback window before mutation."""

    rollback_receipt_version: str
    cohort_manifest_digest: str
    route_authority: str
    target: str
    generation_digest: str
    route_version: str
    rollback_target: str
    state: str
    live_operation_authorized: bool
    rollback_receipt_digest: str
    FIELDS: ClassVar[set[str]] = {
        "rollback_receipt_version", "cohort_manifest_digest", "route_authority", "target",
        "generation_digest", "route_version", "rollback_target", "state",
        "live_operation_authorized", "rollback_receipt_digest",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "PreMutationRollbackReceiptV1":
        values = _strict(data, cls.FIELDS)
        if values["rollback_receipt_version"] != PRE_MUTATION_ROLLBACK_RECEIPT_VERSION:
            raise UnsupportedContractVersion("unsupported pre-mutation rollback receipt version")
        if values["state"] != "ROUTE_SWITCHED_NO_MUTATION" or values["live_operation_authorized"] is not False:
            raise InvalidContractValue("rollback receipt must prove ROUTE_SWITCHED_NO_MUTATION and remain non-authorizing")
        body = {
            "rollback_receipt_version": PRE_MUTATION_ROLLBACK_RECEIPT_VERSION,
            "cohort_manifest_digest": _digest(values["cohort_manifest_digest"], "cohort_manifest_digest"),
            "route_authority": _route_text(values["route_authority"], "route_authority"),
            "target": _route_text(values["target"], "target"),
            "generation_digest": _digest(values["generation_digest"], "generation_digest"),
            "route_version": _route_text(values["route_version"], "route_version", maximum=64),
            "rollback_target": _route_text(values["rollback_target"], "rollback_target"),
            "state": "ROUTE_SWITCHED_NO_MUTATION",
            "live_operation_authorized": False,
        }
        receipt_digest = _digest(values["rollback_receipt_digest"], "rollback_receipt_digest")
        if receipt_digest != route_switch_digest(PRE_MUTATION_ROLLBACK_RECEIPT_VERSION, body):
            raise InvalidContractValue("rollback_receipt_digest does not bind the rollback receipt")
        return cls(
            PRE_MUTATION_ROLLBACK_RECEIPT_VERSION, body["cohort_manifest_digest"],
            body["route_authority"], body["target"], body["generation_digest"],
            body["route_version"], body["rollback_target"], "ROUTE_SWITCHED_NO_MUTATION",
            False, receipt_digest,
        )

    def body(self) -> dict[str, Any]:
        return {
            "rollback_receipt_version": self.rollback_receipt_version,
            "cohort_manifest_digest": self.cohort_manifest_digest,
            "route_authority": self.route_authority,
            "target": self.target,
            "generation_digest": self.generation_digest,
            "route_version": self.route_version,
            "rollback_target": self.rollback_target,
            "state": self.state,
            "live_operation_authorized": False,
        }

    def to_mapping(self) -> dict[str, Any]:
        return self.body() | {"rollback_receipt_digest": self.rollback_receipt_digest}


@dataclass(frozen=True, slots=True)
class RouteAuthorityStateV1:
    """The full canonical route state; there is no legacy or mixed-cohort form."""

    state_version: str
    route_authority: str
    cohort_manifest_digest: str
    cutover_decision_digest: str
    target: str
    resolved_scope_digest: str
    contract_digest: str
    source_manifest_digest: str
    capability_manifest_digest: str
    benchmark_manifest_digest: str
    generation_digest: str
    checkpoint_digest: str
    route_version: str
    capability_epoch: str
    visibility: str
    pre_mutation_rollback_receipt_digest: str
    state: str
    authority_revision: str
    prior_state_digest: str | None
    state_digest: str
    FIELDS: ClassVar[set[str]] = {
        "state_version", "route_authority", "cohort_manifest_digest", "cutover_decision_digest",
        "target", "resolved_scope_digest", "contract_digest", "source_manifest_digest",
        "capability_manifest_digest", "benchmark_manifest_digest", "generation_digest",
        "checkpoint_digest", "route_version", "capability_epoch", "visibility",
        "pre_mutation_rollback_receipt_digest", "state", "authority_revision",
        "prior_state_digest", "state_digest",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RouteAuthorityStateV1":
        values = _strict(data, cls.FIELDS)
        if values["state_version"] != ROUTE_AUTHORITY_STATE_VERSION:
            raise UnsupportedContractVersion("unsupported route authority state version")
        if values["state"] != "CANONICAL_MUTATED":
            raise InvalidContractValue("route authority state must be CANONICAL_MUTATED")
        prior = values["prior_state_digest"]
        if prior is not None:
            prior = _digest(prior, "prior_state_digest")
        body = {
            "state_version": ROUTE_AUTHORITY_STATE_VERSION,
            "route_authority": _route_text(values["route_authority"], "route_authority"),
            "cohort_manifest_digest": _digest(values["cohort_manifest_digest"], "cohort_manifest_digest"),
            "cutover_decision_digest": _digest(values["cutover_decision_digest"], "cutover_decision_digest"),
            "target": _route_text(values["target"], "target"),
            "resolved_scope_digest": _digest(values["resolved_scope_digest"], "resolved_scope_digest"),
            "contract_digest": _digest(values["contract_digest"], "contract_digest"),
            "source_manifest_digest": _digest(values["source_manifest_digest"], "source_manifest_digest"),
            "capability_manifest_digest": _digest(values["capability_manifest_digest"], "capability_manifest_digest"),
            "benchmark_manifest_digest": _digest(values["benchmark_manifest_digest"], "benchmark_manifest_digest"),
            "generation_digest": _digest(values["generation_digest"], "generation_digest"),
            "checkpoint_digest": _digest(values["checkpoint_digest"], "checkpoint_digest"),
            "route_version": _route_text(values["route_version"], "route_version", maximum=64),
            "capability_epoch": _route_epoch(values["capability_epoch"], "capability_epoch"),
            "visibility": _route_text(values["visibility"], "visibility", maximum=_ROUTE_VISIBILITY_MAXIMUM),
            "pre_mutation_rollback_receipt_digest": _digest(values["pre_mutation_rollback_receipt_digest"], "pre_mutation_rollback_receipt_digest"),
            "state": "CANONICAL_MUTATED",
            "authority_revision": _route_epoch(values["authority_revision"], "authority_revision"),
            "prior_state_digest": prior,
        }
        state_digest = _digest(values["state_digest"], "state_digest")
        if state_digest != route_switch_digest(ROUTE_AUTHORITY_STATE_VERSION, body):
            raise InvalidContractValue("state_digest does not bind the canonical route state")
        return cls(
            ROUTE_AUTHORITY_STATE_VERSION, body["route_authority"], body["cohort_manifest_digest"],
            body["cutover_decision_digest"], body["target"], body["resolved_scope_digest"],
            body["contract_digest"], body["source_manifest_digest"],
            body["capability_manifest_digest"], body["benchmark_manifest_digest"],
            body["generation_digest"], body["checkpoint_digest"], body["route_version"],
            body["capability_epoch"], body["visibility"],
            body["pre_mutation_rollback_receipt_digest"], "CANONICAL_MUTATED",
            body["authority_revision"], prior, state_digest,
        )

    def body(self) -> dict[str, Any]:
        return {
            "state_version": self.state_version,
            "route_authority": self.route_authority,
            "cohort_manifest_digest": self.cohort_manifest_digest,
            "cutover_decision_digest": self.cutover_decision_digest,
            "target": self.target,
            "resolved_scope_digest": self.resolved_scope_digest,
            "contract_digest": self.contract_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "capability_manifest_digest": self.capability_manifest_digest,
            "benchmark_manifest_digest": self.benchmark_manifest_digest,
            "generation_digest": self.generation_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "route_version": self.route_version,
            "capability_epoch": self.capability_epoch,
            "visibility": self.visibility,
            "pre_mutation_rollback_receipt_digest": self.pre_mutation_rollback_receipt_digest,
            "state": self.state,
            "authority_revision": self.authority_revision,
            "prior_state_digest": self.prior_state_digest,
        }

    def to_mapping(self) -> dict[str, Any]:
        return self.body() | {"state_digest": self.state_digest}


@dataclass(frozen=True, slots=True)
class RouteSwitchReceiptV1:
    """Hash-only switch, rehearsal, or postcheck receipt; never an authorization."""

    receipt_version: str
    operation: str
    state: str
    route_authority: str
    cohort_manifest_digest: str
    cutover_decision_digest: str
    target: str
    resolved_scope_digest: str
    contract_digest: str
    source_manifest_digest: str
    capability_manifest_digest: str
    benchmark_manifest_digest: str
    generation_digest: str
    checkpoint_digest: str
    route_version: str
    capability_epoch: str
    visibility: str
    pre_mutation_rollback_receipt_digest: str
    route_state_digest: str
    authority_revision: str
    live_operation_authorized: bool
    receipt_digest: str
    FIELDS: ClassVar[set[str]] = {
        "receipt_version", "operation", "state", "route_authority", "cohort_manifest_digest",
        "cutover_decision_digest", "target", "resolved_scope_digest", "contract_digest",
        "source_manifest_digest", "capability_manifest_digest", "benchmark_manifest_digest",
        "generation_digest", "checkpoint_digest", "route_version", "capability_epoch",
        "visibility", "pre_mutation_rollback_receipt_digest", "route_state_digest",
        "authority_revision", "live_operation_authorized", "receipt_digest",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RouteSwitchReceiptV1":
        values = _strict(data, cls.FIELDS)
        if values["receipt_version"] != ROUTE_SWITCH_RECEIPT_VERSION:
            raise UnsupportedContractVersion("unsupported route switch receipt version")
        operation = _route_text(values["operation"], "operation", maximum=32)
        if operation not in _ROUTE_RECEIPT_OPERATIONS:
            raise InvalidContractValue("unsupported route receipt operation")
        expected_state = "ROUTE_SWITCHED_NO_MUTATION" if operation == "REHEARSE" else "CANONICAL_MUTATED"
        if values["state"] != expected_state or values["live_operation_authorized"] is not False:
            raise InvalidContractValue("route receipt state or authorization marker is invalid")
        body = {
            "receipt_version": ROUTE_SWITCH_RECEIPT_VERSION,
            "operation": operation,
            "state": expected_state,
            "route_authority": _route_text(values["route_authority"], "route_authority"),
            "cohort_manifest_digest": _digest(values["cohort_manifest_digest"], "cohort_manifest_digest"),
            "cutover_decision_digest": _digest(values["cutover_decision_digest"], "cutover_decision_digest"),
            "target": _route_text(values["target"], "target"),
            "resolved_scope_digest": _digest(values["resolved_scope_digest"], "resolved_scope_digest"),
            "contract_digest": _digest(values["contract_digest"], "contract_digest"),
            "source_manifest_digest": _digest(values["source_manifest_digest"], "source_manifest_digest"),
            "capability_manifest_digest": _digest(values["capability_manifest_digest"], "capability_manifest_digest"),
            "benchmark_manifest_digest": _digest(values["benchmark_manifest_digest"], "benchmark_manifest_digest"),
            "generation_digest": _digest(values["generation_digest"], "generation_digest"),
            "checkpoint_digest": _digest(values["checkpoint_digest"], "checkpoint_digest"),
            "route_version": _route_text(values["route_version"], "route_version", maximum=64),
            "capability_epoch": _route_epoch(values["capability_epoch"], "capability_epoch"),
            "visibility": _route_text(values["visibility"], "visibility", maximum=_ROUTE_VISIBILITY_MAXIMUM),
            "pre_mutation_rollback_receipt_digest": _digest(values["pre_mutation_rollback_receipt_digest"], "pre_mutation_rollback_receipt_digest"),
            "route_state_digest": _digest(values["route_state_digest"], "route_state_digest"),
            "authority_revision": _route_epoch(values["authority_revision"], "authority_revision"),
            "live_operation_authorized": False,
        }
        receipt_digest = _digest(values["receipt_digest"], "receipt_digest")
        if receipt_digest != route_switch_digest(ROUTE_SWITCH_RECEIPT_VERSION, body):
            raise InvalidContractValue("receipt_digest does not bind the route receipt")
        return cls(
            ROUTE_SWITCH_RECEIPT_VERSION, operation, expected_state,
            body["route_authority"], body["cohort_manifest_digest"],
            body["cutover_decision_digest"], body["target"], body["resolved_scope_digest"],
            body["contract_digest"], body["source_manifest_digest"],
            body["capability_manifest_digest"], body["benchmark_manifest_digest"],
            body["generation_digest"], body["checkpoint_digest"], body["route_version"],
            body["capability_epoch"], body["visibility"],
            body["pre_mutation_rollback_receipt_digest"], body["route_state_digest"],
            body["authority_revision"], False, receipt_digest,
        )

    @classmethod
    def create(cls, **values: Any) -> "RouteSwitchReceiptV1":
        body = dict(values)
        body["receipt_version"] = ROUTE_SWITCH_RECEIPT_VERSION
        body["live_operation_authorized"] = False
        body["receipt_digest"] = route_switch_digest(
            ROUTE_SWITCH_RECEIPT_VERSION,
            {key: value for key, value in body.items() if key != "receipt_digest"},
        )
        return cls.from_mapping(body)

    def body(self) -> dict[str, Any]:
        return {
            "receipt_version": self.receipt_version,
            "operation": self.operation,
            "state": self.state,
            "route_authority": self.route_authority,
            "cohort_manifest_digest": self.cohort_manifest_digest,
            "cutover_decision_digest": self.cutover_decision_digest,
            "target": self.target,
            "resolved_scope_digest": self.resolved_scope_digest,
            "contract_digest": self.contract_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "capability_manifest_digest": self.capability_manifest_digest,
            "benchmark_manifest_digest": self.benchmark_manifest_digest,
            "generation_digest": self.generation_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "route_version": self.route_version,
            "capability_epoch": self.capability_epoch,
            "visibility": self.visibility,
            "pre_mutation_rollback_receipt_digest": self.pre_mutation_rollback_receipt_digest,
            "route_state_digest": self.route_state_digest,
            "authority_revision": self.authority_revision,
            "live_operation_authorized": False,
        }

    def to_mapping(self) -> dict[str, Any]:
        return self.body() | {"receipt_digest": self.receipt_digest}


# CODE-06 deliberately keeps signatures structurally closed here.  Verification
# is a deployment concern: the public CLI must never learn a key, registry, or
# trusted clock from argv or a serialized artifact.
def _decommission_signature(value: Any, field: str) -> str:
    value = _route_text(value, field, maximum=4096)
    if any(character.isspace() for character in value):
        raise InvalidContractValue(f"{field} must be compact signature evidence")
    try:
        encoded = b64decode(value, validate=True)
    except Exception as exc:
        raise InvalidContractValue(f"{field} must be base64 Ed25519 evidence") from exc
    if len(encoded) != 64:
        raise InvalidContractValue(f"{field} must be a 64-byte Ed25519 signature")
    return value


def _decommission_approvals(value: Any, field: str) -> tuple[RouteApprovalDigestV1, ...]:
    if not isinstance(value, list):
        raise InvalidContractValue(f"{field} must be a canonical array")
    approvals = tuple(RouteApprovalDigestV1.from_mapping(item) for item in value if isinstance(item, Mapping))
    if len(approvals) != len(value) or tuple(item.role for item in approvals) != _ROUTE_APPROVER_ROLES:
        raise InvalidContractValue(
            f"{field} must be exact canonically ordered migration, product, quality, security"
        )
    return approvals


@dataclass(frozen=True, slots=True)
class ActivationReceiptV1:
    """Signed, non-live activation evidence; cryptographic trust is injected."""

    activation_receipt_version: str; workspace_ref: str; source_ref: str; route_authority: str
    route_state_digest: str; route_receipt_digest: str; cutover_decision_digest: str
    cohort_manifest_digest: str; activated_at: str; approval_digests: tuple[RouteApprovalDigestV1, ...]
    state: str; live_operation_authorized: bool; signer_ref: str; signer_algorithm: str
    key_id: str; activation_digest: str; signature: str
    FIELDS: ClassVar[set[str]] = {
        "activation_receipt_version", "workspace_ref", "source_ref", "route_authority",
        "route_state_digest", "route_receipt_digest", "cutover_decision_digest",
        "cohort_manifest_digest", "activated_at", "approval_digests", "state",
        "live_operation_authorized", "signer_ref", "signer_algorithm", "key_id",
        "activation_digest", "signature",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ActivationReceiptV1":
        values = _strict(data, cls.FIELDS)
        if values["activation_receipt_version"] != ACTIVATION_RECEIPT_V1:
            raise UnsupportedContractVersion("unsupported activation receipt version")
        approvals = _decommission_approvals(values["approval_digests"], "approval_digests")
        activated_at = values["activated_at"]
        _canonical_utc_timestamp(activated_at, "activated_at")
        if values["state"] != "CANONICAL_MUTATED" or values["live_operation_authorized"] is not False:
            raise InvalidContractValue("activation must be CANONICAL_MUTATED non-live evidence")
        if values["signer_algorithm"] != "Ed25519":
            raise InvalidContractValue("activation signer_algorithm must be Ed25519")
        body = {
            "activation_receipt_version": ACTIVATION_RECEIPT_V1,
            "workspace_ref": _route_text(values["workspace_ref"], "workspace_ref"),
            "source_ref": _route_text(values["source_ref"], "source_ref"),
            "route_authority": _route_text(values["route_authority"], "route_authority"),
            "route_state_digest": _digest(values["route_state_digest"], "route_state_digest"),
            "route_receipt_digest": _digest(values["route_receipt_digest"], "route_receipt_digest"),
            "cutover_decision_digest": _digest(values["cutover_decision_digest"], "cutover_decision_digest"),
            "cohort_manifest_digest": _digest(values["cohort_manifest_digest"], "cohort_manifest_digest"),
            "activated_at": activated_at,
            "approval_digests": [item.to_mapping() for item in approvals],
            "state": "CANONICAL_MUTATED", "live_operation_authorized": False,
            "signer_ref": _route_text(values["signer_ref"], "signer_ref"),
            "signer_algorithm": "Ed25519", "key_id": _route_text(values["key_id"], "key_id"),
        }
        digest = _digest(values["activation_digest"], "activation_digest")
        if digest != sha256(canonical_bytes(body)).hexdigest():
            raise InvalidContractValue("activation_digest does not bind activation evidence")
        return cls(ACTIVATION_RECEIPT_V1, body["workspace_ref"], body["source_ref"], body["route_authority"],
                   body["route_state_digest"], body["route_receipt_digest"], body["cutover_decision_digest"],
                   body["cohort_manifest_digest"], activated_at, approvals, "CANONICAL_MUTATED", False,
                   body["signer_ref"], "Ed25519", body["key_id"], digest,
                   _decommission_signature(values["signature"], "signature"))

    def body(self) -> dict[str, Any]:
        return {key: value for key, value in self.to_mapping().items() if key not in {"activation_digest", "signature"}}

    def to_mapping(self) -> dict[str, Any]:
        return {"activation_receipt_version": self.activation_receipt_version, "workspace_ref": self.workspace_ref,
                "source_ref": self.source_ref, "route_authority": self.route_authority,
                "route_state_digest": self.route_state_digest, "route_receipt_digest": self.route_receipt_digest,
                "cutover_decision_digest": self.cutover_decision_digest, "cohort_manifest_digest": self.cohort_manifest_digest,
                "activated_at": self.activated_at, "approval_digests": [item.to_mapping() for item in self.approval_digests],
                "state": self.state, "live_operation_authorized": False, "signer_ref": self.signer_ref,
                "signer_algorithm": self.signer_algorithm, "key_id": self.key_id,
                "activation_digest": self.activation_digest, "signature": self.signature}


@dataclass(frozen=True, slots=True)
class ConsentTransferReceiptV1:
    """Signed transfer evidence.  Expiry and signature are verified by the port."""

    consent_transfer_receipt_version: str; workspace_ref: str; source_ref: str; activation_digest: str
    cutover_decision_digest: str; conservation_receipt_sha256: str; allowlist_digest: str
    consent_ref: str; retention_revision: str; transfer_state: str; issued_at: str; expires_at: str
    live_operation_authorized: bool; signer_ref: str; signer_algorithm: str; key_id: str
    receipt_digest: str; signature: str
    FIELDS: ClassVar[set[str]] = {
        "consent_transfer_receipt_version", "workspace_ref", "source_ref", "activation_digest",
        "cutover_decision_digest", "conservation_receipt_sha256", "allowlist_digest", "consent_ref",
        "retention_revision", "transfer_state", "issued_at", "expires_at", "live_operation_authorized",
        "signer_ref", "signer_algorithm", "key_id", "receipt_digest", "signature",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ConsentTransferReceiptV1":
        values = _strict(data, cls.FIELDS)
        if values["consent_transfer_receipt_version"] != CONSENT_TRANSFER_RECEIPT_V1:
            raise UnsupportedContractVersion("unsupported consent transfer receipt version")
        issued_at, expires_at = values["issued_at"], values["expires_at"]
        if _canonical_utc_timestamp(issued_at, "issued_at") >= _canonical_utc_timestamp(expires_at, "expires_at"):
            raise InvalidContractValue("consent transfer expiry must be after issue time")
        if values["transfer_state"] != "TRANSFERRED" or values["live_operation_authorized"] is not False or values["signer_algorithm"] != "Ed25519":
            raise InvalidContractValue("consent transfer must be TRANSFERRED non-live Ed25519 evidence")
        body = {
            "consent_transfer_receipt_version": CONSENT_TRANSFER_RECEIPT_V1,
            "workspace_ref": _route_text(values["workspace_ref"], "workspace_ref"), "source_ref": _route_text(values["source_ref"], "source_ref"),
            "activation_digest": _digest(values["activation_digest"], "activation_digest"), "cutover_decision_digest": _digest(values["cutover_decision_digest"], "cutover_decision_digest"),
            "conservation_receipt_sha256": _digest(values["conservation_receipt_sha256"], "conservation_receipt_sha256"), "allowlist_digest": _digest(values["allowlist_digest"], "allowlist_digest"),
            "consent_ref": _route_text(values["consent_ref"], "consent_ref"), "retention_revision": _route_epoch(values["retention_revision"], "retention_revision"),
            "transfer_state": "TRANSFERRED", "issued_at": issued_at, "expires_at": expires_at, "live_operation_authorized": False,
            "signer_ref": _route_text(values["signer_ref"], "signer_ref"), "signer_algorithm": "Ed25519", "key_id": _route_text(values["key_id"], "key_id"),
        }
        digest = _digest(values["receipt_digest"], "receipt_digest")
        if digest != sha256(canonical_bytes(body)).hexdigest(): raise InvalidContractValue("receipt_digest does not bind consent transfer evidence")
        return cls(CONSENT_TRANSFER_RECEIPT_V1, body["workspace_ref"], body["source_ref"], body["activation_digest"], body["cutover_decision_digest"], body["conservation_receipt_sha256"], body["allowlist_digest"], body["consent_ref"], body["retention_revision"], "TRANSFERRED", issued_at, expires_at, False, body["signer_ref"], "Ed25519", body["key_id"], digest, _decommission_signature(values["signature"], "signature"))

    def body(self) -> dict[str, Any]: return {key: value for key, value in self.to_mapping().items() if key not in {"receipt_digest", "signature"}}
    def to_mapping(self) -> dict[str, Any]:
        return {"consent_transfer_receipt_version": self.consent_transfer_receipt_version, "workspace_ref": self.workspace_ref, "source_ref": self.source_ref, "activation_digest": self.activation_digest, "cutover_decision_digest": self.cutover_decision_digest, "conservation_receipt_sha256": self.conservation_receipt_sha256, "allowlist_digest": self.allowlist_digest, "consent_ref": self.consent_ref, "retention_revision": self.retention_revision, "transfer_state": self.transfer_state, "issued_at": self.issued_at, "expires_at": self.expires_at, "live_operation_authorized": False, "signer_ref": self.signer_ref, "signer_algorithm": self.signer_algorithm, "key_id": self.key_id, "receipt_digest": self.receipt_digest, "signature": self.signature}


@dataclass(frozen=True, slots=True)
class DecommissionCertificateRequestV1:
    """Hash-only final rollback-close request; it carries no live-delete grant."""

    decommission_certificate_request_version: str; workspace_ref: str; source_ref: str; activation_digest: str; retention_end: str; cutover_decision_digest: str; conservation_receipt_sha256: str; backup_manifest_digest: str; isolated_restore_target_digest: str; deterministic_recall_digest: str; allowlist_digest: str; consent_transfer_receipt_digest: str; approval_digests: tuple[RouteApprovalDigestV1, ...]; requested_state: str; destructive_action_authorized: bool; request_digest: str
    FIELDS: ClassVar[set[str]] = {"decommission_certificate_request_version", "workspace_ref", "source_ref", "activation_digest", "retention_end", "cutover_decision_digest", "conservation_receipt_sha256", "backup_manifest_digest", "isolated_restore_target_digest", "deterministic_recall_digest", "allowlist_digest", "consent_transfer_receipt_digest", "approval_digests", "requested_state", "destructive_action_authorized", "request_digest"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "DecommissionCertificateRequestV1":
        values = _strict(data, cls.FIELDS)
        if values["decommission_certificate_request_version"] != DECOMMISSION_CERTIFICATE_REQUEST_V1 or values["requested_state"] != "ROLLBACK_CLOSED" or values["destructive_action_authorized"] is not False:
            raise InvalidContractValue("decommission request is closed rollback evidence only")
        retention_end = values["retention_end"]; _canonical_utc_timestamp(retention_end, "retention_end")
        approvals = _decommission_approvals(values["approval_digests"], "approval_digests")
        body = {"decommission_certificate_request_version": DECOMMISSION_CERTIFICATE_REQUEST_V1, "workspace_ref": _route_text(values["workspace_ref"], "workspace_ref"), "source_ref": _route_text(values["source_ref"], "source_ref"), "activation_digest": _digest(values["activation_digest"], "activation_digest"), "retention_end": retention_end, "cutover_decision_digest": _digest(values["cutover_decision_digest"], "cutover_decision_digest"), "conservation_receipt_sha256": _digest(values["conservation_receipt_sha256"], "conservation_receipt_sha256"), "backup_manifest_digest": _digest(values["backup_manifest_digest"], "backup_manifest_digest"), "isolated_restore_target_digest": _digest(values["isolated_restore_target_digest"], "isolated_restore_target_digest"), "deterministic_recall_digest": _digest(values["deterministic_recall_digest"], "deterministic_recall_digest"), "allowlist_digest": _digest(values["allowlist_digest"], "allowlist_digest"), "consent_transfer_receipt_digest": _digest(values["consent_transfer_receipt_digest"], "consent_transfer_receipt_digest"), "approval_digests": [item.to_mapping() for item in approvals], "requested_state": "ROLLBACK_CLOSED", "destructive_action_authorized": False}
        digest = _digest(values["request_digest"], "request_digest")
        if digest != sha256(canonical_bytes(body)).hexdigest(): raise InvalidContractValue("request_digest does not bind decommission request")
        return cls(DECOMMISSION_CERTIFICATE_REQUEST_V1, body["workspace_ref"], body["source_ref"], body["activation_digest"], retention_end, body["cutover_decision_digest"], body["conservation_receipt_sha256"], body["backup_manifest_digest"], body["isolated_restore_target_digest"], body["deterministic_recall_digest"], body["allowlist_digest"], body["consent_transfer_receipt_digest"], approvals, "ROLLBACK_CLOSED", False, digest)

    def body(self) -> dict[str, Any]: return {key: value for key, value in self.to_mapping().items() if key != "request_digest"}
    def to_mapping(self) -> dict[str, Any]:
        return {"decommission_certificate_request_version": self.decommission_certificate_request_version, "workspace_ref": self.workspace_ref, "source_ref": self.source_ref, "activation_digest": self.activation_digest, "retention_end": self.retention_end, "cutover_decision_digest": self.cutover_decision_digest, "conservation_receipt_sha256": self.conservation_receipt_sha256, "backup_manifest_digest": self.backup_manifest_digest, "isolated_restore_target_digest": self.isolated_restore_target_digest, "deterministic_recall_digest": self.deterministic_recall_digest, "allowlist_digest": self.allowlist_digest, "consent_transfer_receipt_digest": self.consent_transfer_receipt_digest, "approval_digests": [item.to_mapping() for item in self.approval_digests], "requested_state": self.requested_state, "destructive_action_authorized": False, "request_digest": self.request_digest}


@dataclass(frozen=True, slots=True)
class DecommissionCertificateV1:
    """Signed evidence that rollback closure was verified; never a delete action."""
    decommission_certificate_version: str; request: DecommissionCertificateRequestV1; request_digest: str; verified_at: str; retention_seconds: str; state: str; destructive_action_authorized: bool; signer_ref: str; signer_algorithm: str; key_id: str; certificate_digest: str; signature: str
    FIELDS: ClassVar[set[str]] = {"decommission_certificate_version", "request", "request_digest", "verified_at", "retention_seconds", "state", "destructive_action_authorized", "signer_ref", "signer_algorithm", "key_id", "certificate_digest", "signature"}
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "DecommissionCertificateV1":
        values = _strict(data, cls.FIELDS)
        if values["decommission_certificate_version"] != DECOMMISSION_CERTIFICATE_V1 or not isinstance(values["request"], Mapping): raise InvalidContractValue("unsupported or malformed decommission certificate")
        request = DecommissionCertificateRequestV1.from_mapping(values["request"])
        verified_at = values["verified_at"]; _canonical_utc_timestamp(verified_at, "verified_at")
        if values["request_digest"] != request.request_digest or values["retention_seconds"] != "7776000" or values["state"] != "ROLLBACK_CLOSED" or values["destructive_action_authorized"] is not False or values["signer_algorithm"] != "Ed25519": raise InvalidContractValue("decommission certificate fields are not closed")
        body = {"decommission_certificate_version": DECOMMISSION_CERTIFICATE_V1, "request": request.to_mapping(), "request_digest": request.request_digest, "verified_at": verified_at, "retention_seconds": "7776000", "state": "ROLLBACK_CLOSED", "destructive_action_authorized": False, "signer_ref": _route_text(values["signer_ref"], "signer_ref"), "signer_algorithm": "Ed25519", "key_id": _route_text(values["key_id"], "key_id")}
        digest = _digest(values["certificate_digest"], "certificate_digest")
        if digest != sha256(canonical_bytes(body)).hexdigest(): raise InvalidContractValue("certificate_digest does not bind certificate")
        return cls(DECOMMISSION_CERTIFICATE_V1, request, request.request_digest, verified_at, "7776000", "ROLLBACK_CLOSED", False, body["signer_ref"], "Ed25519", body["key_id"], digest, _decommission_signature(values["signature"], "signature"))
    def body(self) -> dict[str, Any]: return {key: value for key, value in self.to_mapping().items() if key not in {"certificate_digest", "signature"}}
    def to_mapping(self) -> dict[str, Any]: return {"decommission_certificate_version": self.decommission_certificate_version, "request": self.request.to_mapping(), "request_digest": self.request_digest, "verified_at": self.verified_at, "retention_seconds": self.retention_seconds, "state": self.state, "destructive_action_authorized": False, "signer_ref": self.signer_ref, "signer_algorithm": self.signer_algorithm, "key_id": self.key_id, "certificate_digest": self.certificate_digest, "signature": self.signature}
