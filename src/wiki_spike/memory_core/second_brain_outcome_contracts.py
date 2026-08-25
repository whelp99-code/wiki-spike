"""Sole public SecondBrainOutcomeV1 envelope and closed legacy adapters."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Final, assert_never

from .contracts import CoreResult, canonical_bytes
from .errors import InvalidContractValue, UnknownContractField

OUTCOME_VERSION: Final = "second-brain-outcome/v1"
RECEIPT_VERSION: Final = "second-brain-receipt/v1"
REF_MAX: Final = 128
TEXT_MAX: Final = 65536
TUPLE_MAX: Final = 100
V2_CODES: Final = frozenset({"OK", "COMMITTED", "ABSTAINED", "NOT_SERVED"})
SUCCESS_CODES: Final = frozenset({"OK", "CREATED", "COMMITTED", "PENDING_REVIEW", "NO_MATCH", "ABSTAINED", "DEGRADED_EXACT", "DELETION_IN_PROGRESS", "RESTORED_QUARANTINED"})
_OMIT_NONE: Final = frozenset({"generation_ref", "checkpoint_ref"})


class OutcomeCodeV1(StrEnum):
    OK = "OK"; CREATED = "CREATED"; COMMITTED = "COMMITTED"; PENDING_REVIEW = "PENDING_REVIEW"; NO_MATCH = "NO_MATCH"
    ABSTAINED = "ABSTAINED"; DEGRADED_EXACT = "DEGRADED_EXACT"; DELETION_IN_PROGRESS = "DELETION_IN_PROGRESS"
    RESTORED_QUARANTINED = "RESTORED_QUARANTINED"; INVALID_INPUT = "INVALID_INPUT"; UNKNOWN_FIELD = "UNKNOWN_FIELD"
    FORMAT_UNSUPPORTED = "FORMAT_UNSUPPORTED"; OCR_REQUIRED = "OCR_REQUIRED"; LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    AUTH_REQUIRED = "AUTH_REQUIRED"; CAPABILITY_DENIED = "CAPABILITY_DENIED"; CAPABILITY_REPLAYED = "CAPABILITY_REPLAYED"
    SCOPE_DISABLED = "SCOPE_DISABLED"; CONSENT_DISABLED = "CONSENT_DISABLED"; GOVERNANCE_BLOCKED = "GOVERNANCE_BLOCKED"
    STALE_REVISION = "STALE_REVISION"; NOT_SERVED = "NOT_SERVED"; QUARANTINED = "QUARANTINED"; INTEGRITY_FAILED = "INTEGRITY_FAILED"
    CITATION_CORRUPT = "CITATION_CORRUPT"; KEY_UNAVAILABLE = "KEY_UNAVAILABLE"; WORKSPACE_EXISTS = "WORKSPACE_EXISTS"
    WORKSPACE_MODE_MISMATCH = "WORKSPACE_MODE_MISMATCH"; SOURCE_MUTATED = "SOURCE_MUTATED"; SOURCE_INCOMPLETE = "SOURCE_INCOMPLETE"
    SOURCE_COLLISION = "SOURCE_COLLISION"; BACKUP_INCOMPATIBLE = "BACKUP_INCOMPATIBLE"; DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    SYNC_TIMEOUT = "SYNC_TIMEOUT"; CUSTODY_PENDING = "CUSTODY_PENDING"; INTERNAL_ERROR = "INTERNAL_ERROR"


class WriteEffectV1(StrEnum):
    NONE = "NONE"; SECURITY_ONLY = "SECURITY_ONLY"; STAGED_NON_SERVING = "STAGED_NON_SERVING"; DOMAIN_COMMITTED = "DOMAIN_COMMITTED"


class OperationStateV1(StrEnum):
    ABSENT = "ABSENT"; PROVISIONING = "PROVISIONING"; READY_NON_SERVING = "READY_NON_SERVING"; SERVING_READY = "SERVING_READY"
    RESTORED_QUARANTINED = "RESTORED_QUARANTINED"; SERVE_WITHHELD = "SERVE_WITHHELD"; QUARANTINED = "QUARANTINED"
    PENDING_REVIEW = "PENDING_REVIEW"; APPROVED = "APPROVED"; REJECTED = "REJECTED"; SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"; FORGOTTEN = "FORGOTTEN"; PREPARED = "PREPARED"; SIGNED = "SIGNED"; ACTIVE = "ACTIVE"
    DISCOVERED = "DISCOVERED"; IMPORTING = "IMPORTING"; RECONCILING = "RECONCILING"; QUARANTINED_ITEM = "QUARANTINED_ITEM"
    REQUESTED = "REQUESTED"; API_VETO_ACTIVE = "API_VETO_ACTIVE"; TOMBSTONE_ACTIVE = "TOMBSTONE_ACTIVE"
    CHECKPOINT_COMMITTED = "CHECKPOINT_COMMITTED"; REVOCATION_KEYS_DESTROYED = "REVOCATION_KEYS_DESTROYED"
    CRYPTO_SHRED_COMPLETE = "CRYPTO_SHRED_COMPLETE"; PURGE_PENDING = "PURGE_PENDING"; COMPLETE = "COMPLETE"
    STAGING = "STAGING"; VERIFIED = "VERIFIED"; COPIED = "COPIED"; ADMITTED = "ADMITTED"


class ActionNameV2(StrEnum):
    backup = "backup"; citation = "citation"; command = "command"; correct = "correct"; doctor = "doctor"
    forget = "forget"; inbox = "inbox"; recall = "recall"; remember = "remember"; restore = "restore"
    restore_admit = "restore_admit"; review = "review"; revoke = "revoke"; source_add = "source_add"
    source_disable = "source_disable"; source_list = "source_list"; source_scan = "source_scan"
    source_status = "source_status"; source_sync = "source_sync"; status = "status"; transition = "transition"


class WorkspaceModeV1(StrEnum):
    LOCAL = "LOCAL"; CERTIFIED = "CERTIFIED"


class DataKindV1(StrEnum):
    init = "init"; inbox = "inbox"; recall = "recall"; citation = "citation"; source = "source"; status = "status"; backup = "backup"


_CLI: Final = {OutcomeCodeV1[name]: code for code, names in (
    (0, SUCCESS_CODES),
    (2, frozenset({"INVALID_INPUT", "UNKNOWN_FIELD", "FORMAT_UNSUPPORTED", "OCR_REQUIRED", "LIMIT_EXCEEDED"})),
    (3, frozenset({"AUTH_REQUIRED", "CAPABILITY_DENIED", "CAPABILITY_REPLAYED", "SCOPE_DISABLED", "CONSENT_DISABLED", "GOVERNANCE_BLOCKED"})),
    (4, frozenset({"STALE_REVISION", "NOT_SERVED", "QUARANTINED", "INTEGRITY_FAILED", "CITATION_CORRUPT", "WORKSPACE_EXISTS", "WORKSPACE_MODE_MISMATCH", "SOURCE_MUTATED", "SOURCE_INCOMPLETE", "SOURCE_COLLISION", "BACKUP_INCOMPATIBLE"})),
    (5, frozenset({"KEY_UNAVAILABLE", "DEPENDENCY_UNAVAILABLE", "SYNC_TIMEOUT", "CUSTODY_PENDING"})),
    (70, frozenset({"INTERNAL_ERROR"})),
) for name in names}


def outcome_errors() -> tuple[type[UnknownContractField], type[InvalidContractValue]]:
    return (UnknownContractField, InvalidContractValue)


def cli_exit(code: OutcomeCodeV1) -> int: return _CLI[code]


def _strict(data: Mapping[str, object], required: frozenset[str], optional: frozenset[str] = frozenset()) -> dict[str, object]:
    unknown, missing = set(data) - required - optional, required - optional - set(data)
    if unknown: raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    if missing: raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
    return dict(data)


def _text(value: object, field: str, *, bound: int = REF_MAX) -> str:
    if isinstance(value, str) and value and "\x00" not in value and len(value.encode("utf-8")) <= bound:
        return value
    raise InvalidContractValue(f"{field} must be a bounded non-empty string")


def _enum[E: StrEnum](value: object, field: str, enum: type[E]) -> E:
    if isinstance(value, str):
        try: return enum(value)
        except ValueError: pass
    raise InvalidContractValue(f"{field} is not a closed {enum.__name__} value")


def _bool(value: object, field: str) -> bool:
    if isinstance(value, bool): return value
    raise InvalidContractValue(f"{field} must be a boolean")


def _instant(value: object, field: str) -> str:
    text = _text(value, field, bound=20)
    if len(text) == 20 and text[10] == "T" and text.endswith("Z"): return text
    raise InvalidContractValue(f"{field} must be a canonical UTC timestamp")


def _decimal(value: object, field: str) -> str:
    text = _text(value, field, bound=32)
    if text == "0" or (text.isdecimal() and not text.startswith("0")): return text
    raise InvalidContractValue(f"{field} must be a canonical decimal")


def _opt_text(value: object, field: str) -> str | None:
    return None if value is None else _text(value, field)


def _seq(value: object, field: str) -> tuple[object, ...]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and len(value) <= TUPLE_MAX:
        return tuple(value)
    raise InvalidContractValue(f"{field} must be a bounded array")


def _map(data: object, field: str) -> Mapping[str, object]:
    if isinstance(data, Mapping): return data
    raise InvalidContractValue(f"{field} must be an object")


def _dump(value: object) -> object:
    if value is None or isinstance(value, (bool, str)): return value
    if isinstance(value, StrEnum): return value.value
    if isinstance(value, tuple): return [_dump(item) for item in value]
    slots = getattr(type(value), "__slots__", None)
    if not isinstance(slots, tuple): raise InvalidContractValue("unsupported wire value")
    payload: dict[str, object] = {}
    kind = getattr(type(value), "kind", None)
    if isinstance(kind, str): payload["kind"] = kind
    for name in slots:
        item = getattr(value, name)
        if item is None and name in _OMIT_NONE and type(value).__name__ == "ReceiptV1": continue
        payload[name] = _dump(item)
    return payload


def _build[T](cls: type[T], data: object, field: str, parsers: tuple[tuple[str, Callable[[object], object]], ...], *, tagged: bool = False, optional: frozenset[str] = frozenset()) -> T:
    required = frozenset(name for name, _parser in parsers)
    values = _strict(_map(data, field), required | ({"kind"} if tagged else frozenset()), optional)
    return cls(*(_parser(values.get(name) if name in optional else values[name]) for name, _parser in parsers))


@dataclass(frozen=True, slots=True)
class ActionV2:
    name: ActionNameV2; requires_capability: bool


@dataclass(frozen=True, slots=True)
class InboxItemV1:
    candidate_ref: str; revision_ref: str; source_label: str; created_at: str; preview: str


@dataclass(frozen=True, slots=True)
class RecallItemV1:
    revision_ref: str; text: str; score: str; citations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceItemV1:
    source_ref: str; profile: str; enabled: bool; source_state: OperationStateV1
    checkpoint_ref: str | None; lag_seconds: str; error_code: str | None; capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StatusCountV1:
    name: str; value: str


@dataclass(frozen=True, slots=True)
class InitDataV1:
    workspace_ref: str; owner_ref: str; mode: WorkspaceModeV1; workspace_state: OperationStateV1
    next_actions: tuple[ActionV2, ...]; kind: ClassVar[str] = "init"


@dataclass(frozen=True, slots=True)
class InboxDataV1:
    items: tuple[InboxItemV1, ...]; continuation: str | None; kind: ClassVar[str] = "inbox"


@dataclass(frozen=True, slots=True)
class RecallDataV1:
    answer: str; results: tuple[RecallItemV1, ...]; continuation: str | None; degraded: bool
    kind: ClassVar[str] = "recall"


@dataclass(frozen=True, slots=True)
class CitationDataV1:
    citation_ref: str; source_label: str; locator: str; observed_at: str; excerpt: str
    kind: ClassVar[str] = "citation"


@dataclass(frozen=True, slots=True)
class SourceDataV1:
    sources: tuple[SourceItemV1, ...]; kind: ClassVar[str] = "source"


@dataclass(frozen=True, slots=True)
class StatusDataV1:
    workspace_ref: str; mode: WorkspaceModeV1; technical_state: OperationStateV1
    governance_state: OperationStateV1; operational_state: OperationStateV1
    counts: tuple[StatusCountV1, ...]; ready: bool; kind: ClassVar[str] = "status"


@dataclass(frozen=True, slots=True)
class BackupDataV1:
    backup_ref: str; backup_state: OperationStateV1; cut_ref: str; fingerprint: str
    restore_state: OperationStateV1; kind: ClassVar[str] = "backup"


type OutcomeDataV1 = InitDataV1 | InboxDataV1 | RecallDataV1 | CitationDataV1 | SourceDataV1 | StatusDataV1 | BackupDataV1


def _action(data: object) -> ActionV2:
    return _build(ActionV2, data, "action", (("name", lambda v: _enum(v, "name", ActionNameV2)), ("requires_capability", lambda v: _bool(v, "requires_capability"))))


def _inbox_item(data: object) -> InboxItemV1:
    return _build(InboxItemV1, data, "inbox item", (("candidate_ref", lambda v: _text(v, "candidate_ref")), ("revision_ref", lambda v: _text(v, "revision_ref")), ("source_label", lambda v: _text(v, "source_label", bound=TEXT_MAX)), ("created_at", lambda v: _instant(v, "created_at")), ("preview", lambda v: _text(v, "preview", bound=TEXT_MAX))))


def _recall_item(data: object) -> RecallItemV1:
    return _build(RecallItemV1, data, "recall item", (("revision_ref", lambda v: _text(v, "revision_ref")), ("text", lambda v: _text(v, "text", bound=TEXT_MAX)), ("score", lambda v: _decimal(v, "score")), ("citations", lambda v: tuple(_text(item, "citations") for item in _seq(v, "citations")))))


def _source_item(data: object) -> SourceItemV1:
    return _build(SourceItemV1, data, "source item", (("source_ref", lambda v: _text(v, "source_ref")), ("profile", lambda v: _text(v, "profile")), ("enabled", lambda v: _bool(v, "enabled")), ("source_state", lambda v: _enum(v, "source_state", OperationStateV1)), ("checkpoint_ref", lambda v: _opt_text(v, "checkpoint_ref")), ("lag_seconds", lambda v: _decimal(v, "lag_seconds")), ("error_code", lambda v: None if v is None else _enum(v, "error_code", OutcomeCodeV1).value), ("capabilities", lambda v: tuple(_text(item, "capabilities") for item in _seq(v, "capabilities")))))


def _count(data: object) -> StatusCountV1:
    return _build(StatusCountV1, data, "count", (("name", lambda v: _text(v, "name")), ("value", lambda v: _decimal(v, "value"))))


def _parse_data(raw: object) -> OutcomeDataV1:
    data = _map(raw, "data")
    kind = _enum(data.get("kind"), "kind", DataKindV1)
    match kind:
        case DataKindV1.init:
            return _build(InitDataV1, data, "init", (("workspace_ref", lambda v: _text(v, "workspace_ref")), ("owner_ref", lambda v: _text(v, "owner_ref")), ("mode", lambda v: _enum(v, "mode", WorkspaceModeV1)), ("workspace_state", lambda v: _enum(v, "workspace_state", OperationStateV1)), ("next_actions", lambda v: tuple(_action(item) for item in _seq(v, "next_actions")))), tagged=True)
        case DataKindV1.inbox:
            return _build(InboxDataV1, data, "inbox", (("items", lambda v: tuple(_inbox_item(item) for item in _seq(v, "items"))), ("continuation", lambda v: _opt_text(v, "continuation"))), tagged=True)
        case DataKindV1.recall:
            return _build(RecallDataV1, data, "recall", (("answer", lambda v: _text(v, "answer", bound=TEXT_MAX)), ("results", lambda v: tuple(_recall_item(item) for item in _seq(v, "results"))), ("continuation", lambda v: _opt_text(v, "continuation")), ("degraded", lambda v: _bool(v, "degraded"))), tagged=True)
        case DataKindV1.citation:
            return _build(CitationDataV1, data, "citation", (("citation_ref", lambda v: _text(v, "citation_ref")), ("source_label", lambda v: _text(v, "source_label", bound=TEXT_MAX)), ("locator", lambda v: _text(v, "locator", bound=TEXT_MAX)), ("observed_at", lambda v: _instant(v, "observed_at")), ("excerpt", lambda v: _text(v, "excerpt", bound=TEXT_MAX))), tagged=True)
        case DataKindV1.source:
            return _build(SourceDataV1, data, "source", (("sources", lambda v: tuple(_source_item(item) for item in _seq(v, "sources"))),), tagged=True)
        case DataKindV1.status:
            return _build(StatusDataV1, data, "status", (("workspace_ref", lambda v: _text(v, "workspace_ref")), ("mode", lambda v: _enum(v, "mode", WorkspaceModeV1)), ("technical_state", lambda v: _enum(v, "technical_state", OperationStateV1)), ("governance_state", lambda v: _enum(v, "governance_state", OperationStateV1)), ("operational_state", lambda v: _enum(v, "operational_state", OperationStateV1)), ("counts", lambda v: tuple(_count(item) for item in _seq(v, "counts"))), ("ready", lambda v: _bool(v, "ready"))), tagged=True)
        case DataKindV1.backup:
            return _build(BackupDataV1, data, "backup", (("backup_ref", lambda v: _text(v, "backup_ref")), ("backup_state", lambda v: _enum(v, "backup_state", OperationStateV1)), ("cut_ref", lambda v: _text(v, "cut_ref")), ("fingerprint", lambda v: _text(v, "fingerprint")), ("restore_state", lambda v: _enum(v, "restore_state", OperationStateV1))), tagged=True)
        case unreachable:
            assert_never(unreachable)


@dataclass(frozen=True, slots=True)
class ReceiptV1:
    version: str; receipt_ref: str; operation_ref: str; request_digest: str
    authority_digest: str; state: OperationStateV1; write_effect: WriteEffectV1
    committed_at: str; idempotency_ref: str
    generation_ref: str | None = None; checkpoint_ref: str | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> ReceiptV1:
        parsed = _build(cls, data, "receipt", (("version", lambda v: _text(v, "version")), ("receipt_ref", lambda v: _text(v, "receipt_ref")), ("operation_ref", lambda v: _text(v, "operation_ref")), ("request_digest", lambda v: _text(v, "request_digest")), ("authority_digest", lambda v: _text(v, "authority_digest")), ("state", lambda v: _enum(v, "state", OperationStateV1)), ("write_effect", lambda v: _enum(v, "write_effect", WriteEffectV1)), ("committed_at", lambda v: _instant(v, "committed_at")), ("idempotency_ref", lambda v: _text(v, "idempotency_ref")), ("generation_ref", lambda v: _opt_text(v, "generation_ref")), ("checkpoint_ref", lambda v: _opt_text(v, "checkpoint_ref"))), optional=_OMIT_NONE)
        if parsed.version != RECEIPT_VERSION: raise InvalidContractValue("unsupported receipt version")
        return parsed


@dataclass(frozen=True, slots=True)
class CapabilityUseV3:
    capability_ref: str; authority_epoch: str; workspace_ref: str; scope_digest: str
    action: ActionNameV2; nonce: str; authorized_actions: tuple[ActionNameV2, ...]
    subject_ref: str; device_ref: str; request_digest: str; expires_at: str


@dataclass(frozen=True, slots=True)
class LegacyAdaptBindings:
    operation_ref: str; state: OperationStateV1


@dataclass(frozen=True, slots=True)
class SecondBrainOutcomeV1:
    version: str; ok: bool; code: OutcomeCodeV1; operation_ref: str
    state: OperationStateV1; retryable: bool; write_effect: WriteEffectV1
    receipt: ReceiptV1 | None; data: OutcomeDataV1 | None

    def __post_init__(self) -> None:
        if self.version != OUTCOME_VERSION or self.ok != (self.code.value in SUCCESS_CODES):
            raise InvalidContractValue("outcome version or ok flag is invalid")
        if (self.write_effect is WriteEffectV1.NONE) == (self.receipt is not None):
            raise InvalidContractValue("receipt is required exactly when a write effect is claimed")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> SecondBrainOutcomeV1:
        values = _strict(data, frozenset({"version", "ok", "code", "operation_ref", "state", "retryable", "write_effect", "receipt", "data"}))
        receipt_raw = values["receipt"]
        if receipt_raw is not None and not isinstance(receipt_raw, Mapping):
            raise InvalidContractValue("receipt must be an object or null")
        return cls(_text(values["version"], "version"), _bool(values["ok"], "ok"), _enum(values["code"], "code", OutcomeCodeV1), _text(values["operation_ref"], "operation_ref"), _enum(values["state"], "state", OperationStateV1), _bool(values["retryable"], "retryable"), _enum(values["write_effect"], "write_effect", WriteEffectV1), None if receipt_raw is None else ReceiptV1.from_mapping(receipt_raw), None if values["data"] is None else _parse_data(values["data"]))

    def to_mapping(self) -> dict[str, object]:
        dumped = _dump(self)
        if not isinstance(dumped, dict): raise InvalidContractValue("outcome wire form must be an object")
        return dumped

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


def _internal(bindings: LegacyAdaptBindings) -> SecondBrainOutcomeV1:
    return SecondBrainOutcomeV1(OUTCOME_VERSION, False, OutcomeCodeV1.INTERNAL_ERROR, _text(bindings.operation_ref, "operation_ref"), bindings.state, False, WriteEffectV1.NONE, None, None)


def adapt_v2_result(code: str, receipt: Mapping[str, str], bindings: LegacyAdaptBindings) -> SecondBrainOutcomeV1:
    """Adapt a closed V2Result code/receipt pair into the public envelope."""
    if code not in V2_CODES: return _internal(bindings)
    if code == "COMMITTED":
        return _internal(bindings) if not receipt else SecondBrainOutcomeV1(OUTCOME_VERSION, True, OutcomeCodeV1.COMMITTED, bindings.operation_ref, bindings.state, False, WriteEffectV1.DOMAIN_COMMITTED, ReceiptV1.from_mapping(receipt), None)
    return SecondBrainOutcomeV1(OUTCOME_VERSION, code in SUCCESS_CODES, OutcomeCodeV1(code), bindings.operation_ref, bindings.state, False, WriteEffectV1.NONE, None, None)


def adapt_core_result(result: CoreResult, bindings: LegacyAdaptBindings) -> SecondBrainOutcomeV1:
    """Adapt a CoreResult into the public envelope or fail closed."""
    if result.error_code is not None and result.status in V2_CODES: return _internal(bindings)
    if result.error_code is not None:
        try: error = OutcomeCodeV1(result.error_code)
        except ValueError: return _internal(bindings)
        if error.value in SUCCESS_CODES: return _internal(bindings)
        return SecondBrainOutcomeV1(OUTCOME_VERSION, False, error, bindings.operation_ref, bindings.state, False, WriteEffectV1.NONE, None, None)
    if result.status not in V2_CODES or result.status == "COMMITTED": return _internal(bindings)
    body = _parse_data(result.result) if result.result else None
    return SecondBrainOutcomeV1(OUTCOME_VERSION, True, OutcomeCodeV1(result.status), bindings.operation_ref, bindings.state, False, WriteEffectV1.NONE, None, body)
