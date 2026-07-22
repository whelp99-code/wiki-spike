"""Versioned, deterministic Phase 4 Runtime contracts (P4-01).

The contracts are intentionally metadata-only. Stage payloads are persisted behind
content-bound ``StageResultRef`` objects; responses never inline model output,
source text, credentials, or mutable storage handles.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
import re
import unicodedata
from typing import Any, ClassVar, Mapping, Sequence

from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes as _core_canonical_bytes
from wiki_spike.memory_runtime.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)

RUNTIME_REQUEST_VERSION = "phase4-runtime-request-v1"
RUNTIME_RESPONSE_VERSION = "phase4-runtime-response-v1"
RUNTIME_STATUS_VERSION = "phase4-runtime-status-v1"
STAGE_RESULT_REF_VERSION = "phase4-stage-result-ref-v1"
CANCELLATION_SIGNAL_VERSION = "phase4-cancellation-signal-v1"

_OPERATION_DOMAIN = b"wiki.runtime.operation.v1\x00"
_STAGE_RESULT_DOMAIN = b"wiki.runtime.stage-result.v1\x00"
_CANCELLATION_DOMAIN = b"wiki.runtime.cancellation.v1\x00"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CANONICAL_INTEGER = re.compile(r"^(?:0|[1-9][0-9]*)$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Canonicalize through the frozen Core primitive and translate its errors.

    Phase 4 may consume ``memory_core.contracts`` but must not import Core's
    implementation-owned error module.  Externally visible validation failures
    therefore remain Runtime-owned even when the frozen canonicalizer rejects a
    value.
    """
    try:
        return _core_canonical_bytes(value)
    except ValueError as exc:
        raise InvalidContractValue(str(exc)) from exc


class OperationState(str, Enum):
    RECEIVED = "received"
    PLANNED = "planned"
    RETRIEVED = "retrieved"
    GENERATED = "generated"
    VERIFIED = "verified"
    PROPOSED = "proposed"
    COMPLETED = "completed"
    REJECTED = "rejected"
    ABSTAINED = "abstained"
    DEGRADED = "degraded"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATES = frozenset(
    {
        OperationState.COMPLETED,
        OperationState.REJECTED,
        OperationState.ABSTAINED,
        OperationState.DEGRADED,
        OperationState.FAILED,
        OperationState.CANCELLED,
    }
)
STAGE_STATES = (
    OperationState.PLANNED,
    OperationState.RETRIEVED,
    OperationState.GENERATED,
    OperationState.VERIFIED,
    OperationState.PROPOSED,
)


class StageDisposition(str, Enum):
    CONTINUE = "continue"
    COMPLETE = "complete"
    REJECT = "reject"
    ABSTAIN = "abstain"
    DEGRADE = "degrade"


class RuntimeResponseStatus(str, Enum):
    COMPLETED = "completed"
    REJECTED = "rejected"
    ABSTAINED = "abstained"
    DEGRADED = "degraded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRY_LATER = "retry_later"


def parse_utc_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        raise InvalidContractValue(f"{field} must be canonical UTC RFC3339 seconds (YYYY-MM-DDTHH:MM:SSZ)")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise InvalidContractValue(f"{field} is not a valid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise InvalidContractValue(f"{field} is not canonical")
    return parsed


def format_utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise InvalidContractValue("timestamp must be timezone-aware")
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_integer(value: object, field: str) -> str:
    if not isinstance(value, str) or not _CANONICAL_INTEGER.fullmatch(value):
        raise InvalidContractValue(f"{field} must be a canonical non-negative integer string")
    return value


def _strict_mapping(
    data: Mapping[str, object],
    allowed: set[str],
    required: set[str],
    *,
    label: str,
) -> dict[str, object]:
    if not isinstance(data, Mapping):
        raise InvalidContractValue(f"{label} must be an object")
    unknown = set(data) - allowed
    missing = required - set(data)
    if unknown:
        raise UnknownContractField(f"unknown {label} fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing {label} fields: {sorted(missing)}")
    return dict(data)


def _nonempty(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise InvalidContractValue(f"{field} must be a non-empty string")
    normalized = unicodedata.normalize("NFC", value)
    if not normalized:
        raise InvalidContractValue(f"{field} must be a non-empty string")
    return normalized


def _optional_nonempty(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _nonempty(value, field)


def _hex64(value: object, field: str) -> str:
    text = _nonempty(value, field)
    if not _HEX64.fullmatch(text):
        raise InvalidContractValue(f"{field} must be a lowercase SHA-256 hex string")
    return text


def _safe_code(value: object, field: str) -> str:
    text = _nonempty(value, field)
    if not _SAFE_CODE.fullmatch(text):
        raise InvalidContractValue(
            f"{field} must be a lowercase code using [a-z0-9_.-] and start with a letter"
        )
    return text


def _canonical_object(value: object, field: str) -> dict[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise InvalidContractValue(f"{field} must be an object")
    normalized = json.loads(canonical_bytes({"value": value}).decode("utf-8"))["value"]
    if not isinstance(normalized, dict):
        raise InvalidContractValue(f"{field} must be an object")
    return normalized


def _string_sequence(
    value: object,
    field: str,
    *,
    allow_empty: bool = True,
    sorted_unique: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise InvalidContractValue(f"{field} must be an array of strings")
    raw = tuple(value)
    if not allow_empty and not raw:
        raise InvalidContractValue(f"{field} must not be empty")
    result = tuple(_nonempty(item, field) for item in raw)
    if sorted_unique and tuple(sorted(set(result))) != result:
        raise InvalidContractValue(f"{field} must be sorted and unique")
    return result


def _canonical_object_copy(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    copied = json.loads(canonical_bytes({"value": value}).decode("utf-8"))["value"]
    if not isinstance(copied, dict):
        raise InvalidContractValue("canonical object copy must remain an object")
    return copied


def _hash(domain: bytes, payload: Mapping[str, object]) -> str:
    return sha256(domain + canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class RuntimeRequest:
    runtime_request_version: str
    request_id: str
    operation_id: str
    idempotency_key: str
    workspace_id: str
    actor_id: str
    request_type: str
    received_at: str
    deadline_at: str
    requested_generation_id: str | None
    payload: dict[str, JsonValue]

    FIELDS: ClassVar[set[str]] = {
        "runtime_request_version",
        "request_id",
        "operation_id",
        "idempotency_key",
        "workspace_id",
        "actor_id",
        "request_type",
        "received_at",
        "deadline_at",
        "requested_generation_id",
        "payload",
    }

    @staticmethod
    def operation_identity(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "runtime_request_version": RUNTIME_REQUEST_VERSION,
            "idempotency_key": values["idempotency_key"],
            "workspace_id": values["workspace_id"],
            "actor_id": values["actor_id"],
            "request_type": values["request_type"],
            "deadline_at": values["deadline_at"],
            "requested_generation_id": values["requested_generation_id"],
            "payload": values["payload"],
        }

    @classmethod
    def create(cls, **kwargs: object) -> "RuntimeRequest":
        values = {"runtime_request_version": RUNTIME_REQUEST_VERSION, **kwargs}
        values["payload"] = _canonical_object(values.get("payload"), "payload")
        values["operation_id"] = _hash(_OPERATION_DOMAIN, cls.operation_identity(values))
        return cls.from_mapping(values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RuntimeRequest":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="RuntimeRequest")
        if values["runtime_request_version"] != RUNTIME_REQUEST_VERSION:
            raise UnsupportedContractVersion("unsupported RuntimeRequest version")
        for field in (
            "request_id",
            "idempotency_key",
            "workspace_id",
            "actor_id",
            "request_type",
        ):
            values[field] = _nonempty(values[field], field)
        values["operation_id"] = _hex64(values["operation_id"], "operation_id")
        values["requested_generation_id"] = _optional_nonempty(
            values["requested_generation_id"], "requested_generation_id"
        )
        values["payload"] = _canonical_object(values["payload"], "payload")
        received = parse_utc_timestamp(values["received_at"], "received_at")
        deadline = parse_utc_timestamp(values["deadline_at"], "deadline_at")
        if deadline <= received:
            raise InvalidContractValue("deadline_at must be after received_at")
        expected = _hash(_OPERATION_DOMAIN, cls.operation_identity(values))
        if values["operation_id"] != expected:
            raise InvalidContractValue("operation_id does not match canonical operation identity")
        return cls(**values)  # type: ignore[arg-type]

    def identity_digest(self) -> str:
        return self.operation_id

    def to_mapping(self) -> dict[str, object]:
        return {
            "runtime_request_version": self.runtime_request_version,
            "request_id": self.request_id,
            "operation_id": self.operation_id,
            "idempotency_key": self.idempotency_key,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "request_type": self.request_type,
            "received_at": self.received_at,
            "deadline_at": self.deadline_at,
            "requested_generation_id": self.requested_generation_id,
            # Return a detached canonical copy.  ``frozen=True`` prevents attribute
            # rebinding, but nested dictionaries remain mutable in Python.  A caller
            # must not be able to mutate the request through a serialization view and
            # thereby make ``operation_id`` describe different semantics.
            "payload": _canonical_object_copy(self.payload),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class CancellationSignal:
    cancellation_signal_version: str
    cancellation_id: str
    workspace_id: str
    actor_id: str
    operation_id: str
    requested_at: str
    reason_code: str

    FIELDS: ClassVar[set[str]] = {
        "cancellation_signal_version",
        "cancellation_id",
        "workspace_id",
        "actor_id",
        "operation_id",
        "requested_at",
        "reason_code",
    }

    @staticmethod
    def identity(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "cancellation_signal_version": CANCELLATION_SIGNAL_VERSION,
            "workspace_id": values["workspace_id"],
            "actor_id": values["actor_id"],
            "operation_id": values["operation_id"],
            "requested_at": values["requested_at"],
            "reason_code": values["reason_code"],
        }

    @classmethod
    def create(cls, **kwargs: object) -> "CancellationSignal":
        values = {"cancellation_signal_version": CANCELLATION_SIGNAL_VERSION, **kwargs}
        values["cancellation_id"] = _hash(_CANCELLATION_DOMAIN, cls.identity(values))
        return cls.from_mapping(values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "CancellationSignal":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="CancellationSignal")
        if values["cancellation_signal_version"] != CANCELLATION_SIGNAL_VERSION:
            raise UnsupportedContractVersion("unsupported CancellationSignal version")
        values["cancellation_id"] = _hex64(values["cancellation_id"], "cancellation_id")
        values["operation_id"] = _hex64(values["operation_id"], "operation_id")
        for field in ("workspace_id", "actor_id"):
            values[field] = _nonempty(values[field], field)
        values["reason_code"] = _safe_code(values["reason_code"], "reason_code")
        parse_utc_timestamp(values["requested_at"], "requested_at")
        if values["cancellation_id"] != _hash(_CANCELLATION_DOMAIN, cls.identity(values)):
            raise InvalidContractValue("cancellation_id does not match canonical cancellation identity")
        return cls(**values)  # type: ignore[arg-type]

    def to_mapping(self) -> dict[str, object]:
        return {
            "cancellation_signal_version": self.cancellation_signal_version,
            "cancellation_id": self.cancellation_id,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "operation_id": self.operation_id,
            "requested_at": self.requested_at,
            "reason_code": self.reason_code,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class StageResultRef:
    stage_result_ref_version: str
    result_id: str
    operation_id: str
    stage_name: str
    input_digest: str
    content_digest: str
    schema_id: str
    created_at: str
    provenance_refs: tuple[str, ...]

    FIELDS: ClassVar[set[str]] = {
        "stage_result_ref_version",
        "result_id",
        "operation_id",
        "stage_name",
        "input_digest",
        "content_digest",
        "schema_id",
        "created_at",
        "provenance_refs",
    }

    @staticmethod
    def identity(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "stage_result_ref_version": STAGE_RESULT_REF_VERSION,
            "operation_id": values["operation_id"],
            "stage_name": values["stage_name"],
            "input_digest": values["input_digest"],
            "content_digest": values["content_digest"],
            "schema_id": values["schema_id"],
            "created_at": values["created_at"],
            "provenance_refs": list(values["provenance_refs"]),
        }

    @classmethod
    def create(cls, **kwargs: object) -> "StageResultRef":
        values = {"stage_result_ref_version": STAGE_RESULT_REF_VERSION, **kwargs}
        refs = tuple(sorted(set(_string_sequence(values.get("provenance_refs", ()), "provenance_refs"))))
        values["provenance_refs"] = refs
        values["result_id"] = _hash(_STAGE_RESULT_DOMAIN, cls.identity(values))
        return cls.from_mapping(values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "StageResultRef":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="StageResultRef")
        if values["stage_result_ref_version"] != STAGE_RESULT_REF_VERSION:
            raise UnsupportedContractVersion("unsupported StageResultRef version")
        for field in ("result_id", "operation_id", "input_digest", "content_digest"):
            values[field] = _hex64(values[field], field)
        for field in ("stage_name", "schema_id"):
            values[field] = _nonempty(values[field], field)
        if values["stage_name"] not in {state.value for state in STAGE_STATES}:
            raise InvalidContractValue("stage_name is not a supported Runtime stage")
        parse_utc_timestamp(values["created_at"], "created_at")
        values["provenance_refs"] = _string_sequence(
            values["provenance_refs"], "provenance_refs", sorted_unique=True
        )
        if values["result_id"] != _hash(_STAGE_RESULT_DOMAIN, cls.identity(values)):
            raise InvalidContractValue("result_id does not match canonical stage result identity")
        return cls(**values)  # type: ignore[arg-type]

    def to_mapping(self) -> dict[str, object]:
        return {
            "stage_result_ref_version": self.stage_result_ref_version,
            "result_id": self.result_id,
            "operation_id": self.operation_id,
            "stage_name": self.stage_name,
            "input_digest": self.input_digest,
            "content_digest": self.content_digest,
            "schema_id": self.schema_id,
            "created_at": self.created_at,
            "provenance_refs": list(self.provenance_refs),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


def _validate_stage_refs(refs: tuple[StageResultRef, ...], operation_id: object) -> None:
    if len({item.stage_name for item in refs}) != len(refs):
        raise InvalidContractValue("stage_result_refs contain duplicate stages")
    if any(item.operation_id != operation_id for item in refs):
        raise InvalidContractValue("stage_result_ref operation mismatch")
    order = {state.value: index for index, state in enumerate(STAGE_STATES)}
    indexes = [order[item.stage_name] for item in refs]
    if indexes != sorted(indexes):
        raise InvalidContractValue("stage_result_refs must follow Runtime stage order")


def _parse_stage_ref(value: object, field: str) -> StageResultRef:
    if isinstance(value, StageResultRef):
        # Re-parse a detached mapping at the boundary.  This also ensures objects
        # created before a contract hardening change cannot bypass current checks.
        return StageResultRef.from_mapping(value.to_mapping())
    if not isinstance(value, Mapping):
        raise InvalidContractValue(f"{field} entries must be objects")
    return StageResultRef.from_mapping(value)


def _validate_state_ref_semantics(
    state: OperationState,
    refs: tuple[StageResultRef, ...],
    *,
    current_stage: str | None = None,
) -> None:
    if state is OperationState.RECEIVED:
        if refs:
            raise InvalidContractValue("received Runtime state cannot contain stage results")
        if current_stage is not None and current_stage != OperationState.PLANNED.value:
            raise InvalidContractValue("received Runtime state must point to planned")
        return
    if state in STAGE_STATES:
        if not refs or refs[-1].stage_name != state.value:
            raise InvalidContractValue("non-terminal state must match the last committed stage")
        if current_stage is not None:
            order = {item.value: index for index, item in enumerate(STAGE_STATES)}
            if order[current_stage] <= order[state.value]:
                raise InvalidContractValue("current_stage must follow the last committed stage")
        return
    if state is OperationState.COMPLETED and not refs:
        raise InvalidContractValue("completed Runtime state requires a committed stage result")


def _validate_terminal_error_semantics(state: OperationState, error_code: str | None) -> None:
    if state is OperationState.COMPLETED:
        if error_code is not None:
            raise InvalidContractValue("completed Runtime state must not carry error_code")
    elif state in TERMINAL_STATES and error_code is None:
        raise InvalidContractValue("non-completed terminal Runtime state requires error_code")


@dataclass(frozen=True)
class RuntimeStatus:
    runtime_status_version: str
    operation_id: str
    workspace_id: str
    state: str
    current_stage: str | None
    attempt: str
    revision: str
    deadline_at: str
    cancellation_id: str | None
    stage_result_refs: tuple[StageResultRef, ...]
    updated_at: str
    error_code: str | None

    FIELDS: ClassVar[set[str]] = {
        "runtime_status_version",
        "operation_id",
        "workspace_id",
        "state",
        "current_stage",
        "attempt",
        "revision",
        "deadline_at",
        "cancellation_id",
        "stage_result_refs",
        "updated_at",
        "error_code",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RuntimeStatus":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="RuntimeStatus")
        if values["runtime_status_version"] != RUNTIME_STATUS_VERSION:
            raise UnsupportedContractVersion("unsupported RuntimeStatus version")
        values["operation_id"] = _hex64(values["operation_id"], "operation_id")
        values["workspace_id"] = _nonempty(values["workspace_id"], "workspace_id")
        try:
            OperationState(_nonempty(values["state"], "state"))
        except ValueError as exc:
            raise InvalidContractValue("unsupported operation state") from exc
        values["current_stage"] = _optional_nonempty(values["current_stage"], "current_stage")
        if values["current_stage"] is not None and values["current_stage"] not in {
            state.value for state in STAGE_STATES
        }:
            raise InvalidContractValue("current_stage is not supported")
        values["attempt"] = canonical_integer(values["attempt"], "attempt")
        values["revision"] = canonical_integer(values["revision"], "revision")
        parse_utc_timestamp(values["deadline_at"], "deadline_at")
        parse_utc_timestamp(values["updated_at"], "updated_at")
        values["cancellation_id"] = (
            None if values["cancellation_id"] is None else _hex64(values["cancellation_id"], "cancellation_id")
        )
        values["error_code"] = (
            None if values["error_code"] is None else _safe_code(values["error_code"], "error_code")
        )
        refs_value = values["stage_result_refs"]
        if not isinstance(refs_value, (list, tuple)) or isinstance(refs_value, (str, bytes)):
            raise InvalidContractValue("stage_result_refs must be an array")
        refs = tuple(_parse_stage_ref(item, "stage_result_refs") for item in refs_value)
        _validate_stage_refs(refs, values["operation_id"])
        state = OperationState(values["state"])
        if state in TERMINAL_STATES and values["current_stage"] is not None:
            raise InvalidContractValue("terminal RuntimeStatus must not expose current_stage")
        if state not in TERMINAL_STATES and values["current_stage"] is None:
            raise InvalidContractValue("non-terminal RuntimeStatus requires current_stage")
        _validate_state_ref_semantics(state, refs, current_stage=values["current_stage"])
        _validate_terminal_error_semantics(state, values["error_code"])
        values["stage_result_refs"] = refs
        return cls(**values)  # type: ignore[arg-type]

    def to_mapping(self) -> dict[str, object]:
        return {
            "runtime_status_version": self.runtime_status_version,
            "operation_id": self.operation_id,
            "workspace_id": self.workspace_id,
            "state": self.state,
            "current_stage": self.current_stage,
            "attempt": self.attempt,
            "revision": self.revision,
            "deadline_at": self.deadline_at,
            "cancellation_id": self.cancellation_id,
            "stage_result_refs": [item.to_mapping() for item in self.stage_result_refs],
            "updated_at": self.updated_at,
            "error_code": self.error_code,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class RuntimeResponse:
    runtime_response_version: str
    request_id: str
    operation_id: str
    workspace_id: str
    status: str
    state: str
    requested_generation_id: str | None
    stage_result_refs: tuple[StageResultRef, ...]
    result_ref: StageResultRef | None
    retryable: bool
    error_code: str | None
    updated_at: str

    FIELDS: ClassVar[set[str]] = {
        "runtime_response_version",
        "request_id",
        "operation_id",
        "workspace_id",
        "status",
        "state",
        "requested_generation_id",
        "stage_result_refs",
        "result_ref",
        "retryable",
        "error_code",
        "updated_at",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RuntimeResponse":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="RuntimeResponse")
        if values["runtime_response_version"] != RUNTIME_RESPONSE_VERSION:
            raise UnsupportedContractVersion("unsupported RuntimeResponse version")
        values["request_id"] = _nonempty(values["request_id"], "request_id")
        values["operation_id"] = _hex64(values["operation_id"], "operation_id")
        values["workspace_id"] = _nonempty(values["workspace_id"], "workspace_id")
        try:
            RuntimeResponseStatus(_nonempty(values["status"], "status"))
            OperationState(_nonempty(values["state"], "state"))
        except ValueError as exc:
            raise InvalidContractValue("unsupported Runtime response status/state") from exc
        values["requested_generation_id"] = _optional_nonempty(
            values["requested_generation_id"], "requested_generation_id"
        )
        if not isinstance(values["retryable"], bool):
            raise InvalidContractValue("retryable must be boolean")
        values["error_code"] = (
            None if values["error_code"] is None else _safe_code(values["error_code"], "error_code")
        )
        parse_utc_timestamp(values["updated_at"], "updated_at")
        refs_value = values["stage_result_refs"]
        if not isinstance(refs_value, (list, tuple)) or isinstance(refs_value, (str, bytes)):
            raise InvalidContractValue("stage_result_refs must be an array")
        refs = tuple(_parse_stage_ref(item, "stage_result_refs") for item in refs_value)
        _validate_stage_refs(refs, values["operation_id"])
        result_value = values["result_ref"]
        result_ref = None if result_value is None else _parse_stage_ref(result_value, "result_ref")
        if result_ref is not None and result_ref not in refs:
            raise InvalidContractValue("result_ref must be one of stage_result_refs")
        if result_ref is not None and (not refs or result_ref != refs[-1]):
            raise InvalidContractValue("result_ref must be the final stage_result_ref")
        status = RuntimeResponseStatus(values["status"])
        state = OperationState(values["state"])
        _validate_state_ref_semantics(state, refs)
        expected_status = response_status_for_state(state)
        if status is RuntimeResponseStatus.RETRY_LATER:
            if state in TERMINAL_STATES:
                raise InvalidContractValue("retry_later response cannot carry terminal state")
            if values["retryable"] is not True or result_ref is not None:
                raise InvalidContractValue("retry_later response must be retryable and omit result_ref")
            if values["error_code"] is None:
                raise InvalidContractValue("retry_later response requires error_code")
        else:
            if status is not expected_status:
                raise InvalidContractValue("Runtime response status/state mismatch")
            if values["retryable"] is not False:
                raise InvalidContractValue("terminal response must not be retryable")
            if status is RuntimeResponseStatus.COMPLETED:
                if values["error_code"] is not None or result_ref is None:
                    raise InvalidContractValue("completed response requires result_ref and no error_code")
            elif status in {RuntimeResponseStatus.FAILED, RuntimeResponseStatus.CANCELLED}:
                if values["error_code"] is None or result_ref is not None:
                    raise InvalidContractValue("failed/cancelled response requires error_code and no result_ref")
            elif status is RuntimeResponseStatus.REJECTED:
                if values["error_code"] is None:
                    raise InvalidContractValue("rejected response requires error_code")
                if result_ref is None and refs:
                    raise InvalidContractValue("rejected response with stage refs requires result_ref")
            elif values["error_code"] is None or result_ref is None:
                raise InvalidContractValue("abstained/degraded response requires result_ref and error_code")
        values["stage_result_refs"] = refs
        values["result_ref"] = result_ref
        return cls(**values)  # type: ignore[arg-type]

    def to_mapping(self) -> dict[str, object]:
        return {
            "runtime_response_version": self.runtime_response_version,
            "request_id": self.request_id,
            "operation_id": self.operation_id,
            "workspace_id": self.workspace_id,
            "status": self.status,
            "state": self.state,
            "requested_generation_id": self.requested_generation_id,
            "stage_result_refs": [item.to_mapping() for item in self.stage_result_refs],
            "result_ref": None if self.result_ref is None else self.result_ref.to_mapping(),
            "retryable": self.retryable,
            "error_code": self.error_code,
            "updated_at": self.updated_at,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


def response_status_for_state(state: OperationState) -> RuntimeResponseStatus:
    mapping = {
        OperationState.COMPLETED: RuntimeResponseStatus.COMPLETED,
        OperationState.REJECTED: RuntimeResponseStatus.REJECTED,
        OperationState.ABSTAINED: RuntimeResponseStatus.ABSTAINED,
        OperationState.DEGRADED: RuntimeResponseStatus.DEGRADED,
        OperationState.FAILED: RuntimeResponseStatus.FAILED,
        OperationState.CANCELLED: RuntimeResponseStatus.CANCELLED,
    }
    return mapping.get(state, RuntimeResponseStatus.RETRY_LATER)


__all__ = [
    "RUNTIME_REQUEST_VERSION",
    "RUNTIME_RESPONSE_VERSION",
    "RUNTIME_STATUS_VERSION",
    "STAGE_RESULT_REF_VERSION",
    "CANCELLATION_SIGNAL_VERSION",
    "OperationState",
    "TERMINAL_STATES",
    "STAGE_STATES",
    "StageDisposition",
    "RuntimeResponseStatus",
    "RuntimeRequest",
    "CancellationSignal",
    "StageResultRef",
    "RuntimeStatus",
    "RuntimeResponse",
    "parse_utc_timestamp",
    "format_utc_timestamp",
    "canonical_integer",
    "response_status_for_state",
]
