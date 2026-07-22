"""Privacy-preserving audit, telemetry, backpressure, and export contracts.

This module is storage-independent. Audit and telemetry records contain bounded
metadata and cryptographic references only; queues and retry state are explicitly
bounded; and export requests create projection jobs rather than external side
effects.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
import hmac
import json
import re
from threading import RLock
from typing import Mapping, Protocol, Sequence

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion
from .policy import CapabilityToken, PolicyEngine, PolicyRequest, Sensitivity

AUDIT_RECORD_VERSION = "phase3-audit-reference-v1"
TELEMETRY_POINT_VERSION = "phase3-telemetry-point-v1"
WORK_ITEM_VERSION = "phase3-bounded-work-item-v1"
EXPORT_REQUEST_VERSION = "phase3-export-request-v1"
EXPORT_JOB_VERSION = "phase3-export-projection-job-v1"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40_OR_64 = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
CODE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
FIELD_PATH = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$")

FORBIDDEN_EXPORT_FIELDS = frozenset({
    "body", "content", "raw_content", "prompt", "response", "token",
    "api_key", "private_key", "secret", "credential", "redaction_mapping",
})
EXPORT_TARGET_CEILINGS: Mapping[str, Sensitivity] = {
    "public_bundle": Sensitivity.PUBLIC,
    "internal_projection": Sensitivity.INTERNAL,
    "private_archive": Sensitivity.PRIVATE,
}


class OperabilityError(RuntimeError):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


class AuditCapacityExceeded(OperabilityError):
    def __init__(self) -> None:
        super().__init__("audit_capacity_exceeded", "bounded audit store is full")


class TelemetryAuditUnavailable(OperabilityError):
    def __init__(self) -> None:
        super().__init__(
            "telemetry_audit_unavailable",
            "telemetry and the required minimal audit are unavailable",
        )


def _strict(data: Mapping[str, object], fields: set[str], label: str) -> dict[str, object]:
    unknown = set(data) - fields
    missing = fields - set(data)
    if unknown:
        raise UnknownContractField(f"unknown {label} fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing {label} fields: {sorted(missing)}")
    return dict(data)


def _nonempty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty string")
    return value


def _code(value: object, field: str) -> str:
    if not isinstance(value, str) or CODE.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a lowercase bounded code")
    return value


def _hex64(value: object, field: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a lowercase SHA-256 digest")
    return value


def _generation(value: object, field: str, *, nullable: bool = True) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or HEX40_OR_64.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a Git/SHA object id")
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be an ISO-8601 timestamp with timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidContractValue(f"{field} is not a valid timestamp") from exc
    if parsed.tzinfo is None:
        raise InvalidContractValue(f"{field} must include a timezone")
    return parsed


def _uint(value: object, field: str, *, positive: bool = False) -> int:
    pattern = r"[1-9][0-9]*" if positive else r"0|[1-9][0-9]*"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        label = "positive" if positive else "non-negative"
        raise InvalidContractValue(f"{field} must be a canonical {label} integer string")
    return int(value)


def _sorted_strings(
    values: object,
    field: str,
    *,
    pattern: re.Pattern[str] | None = None,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or isinstance(values, (str, bytes)):
        raise InvalidContractValue(f"{field} must be an array of strings")
    result = tuple(values)
    if not allow_empty and not result:
        raise InvalidContractValue(f"{field} must not be empty")
    if any(not isinstance(v, str) or not v for v in result):
        raise InvalidContractValue(f"{field} contains an invalid string")
    if tuple(sorted(set(result))) != result:
        raise InvalidContractValue(f"{field} must be sorted and unique")
    if pattern is not None and any(pattern.fullmatch(v) is None for v in result):
        raise InvalidContractValue(f"{field} contains an invalid value")
    return result


class ReferenceHasher:
    """HMAC-based one-way reference hashing; the key is never serialized."""

    def __init__(self, key: bytes, *, namespace: str = "audit-ref-v1") -> None:
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("reference hashing key must contain at least 16 bytes")
        if CODE.fullmatch(namespace) is None:
            raise ValueError("namespace must be a bounded code")
        self._key = key
        self._namespace = namespace.encode("ascii")

    def digest(self, value: str) -> str:
        _nonempty(value, "reference source")
        return hmac.new(
            self._key,
            self._namespace + b"\x00" + value.encode("utf-8"),
            "sha256",
        ).hexdigest()


@dataclass(frozen=True)
class AuditReference:
    audit_record_version: str
    audit_id: str
    workspace_ref_hash: str
    actor_ref_hash: str
    operation_ref_hash: str
    correlation_ref_hash: str
    action: str
    outcome: str
    reason_code: str
    generation_id: str | None
    object_ref_digests: tuple[str, ...]
    policy_version: str
    occurred_at: str

    FIELDS = {
        "audit_record_version", "audit_id", "workspace_ref_hash", "actor_ref_hash",
        "operation_ref_hash", "correlation_ref_hash", "action", "outcome",
        "reason_code", "generation_id", "object_ref_digests", "policy_version",
        "occurred_at",
    }

    @staticmethod
    def _identity(values: Mapping[str, object]) -> dict[str, object]:
        result = {k: values[k] for k in AuditReference.FIELDS - {"audit_id"}}
        result["object_ref_digests"] = list(result["object_ref_digests"])
        return result

    def __post_init__(self) -> None:
        if self.audit_record_version != AUDIT_RECORD_VERSION:
            raise UnsupportedContractVersion("unsupported audit record version")
        for field in ("workspace_ref_hash", "actor_ref_hash", "operation_ref_hash", "correlation_ref_hash"):
            _hex64(getattr(self, field), field)
        for field in ("action", "outcome", "reason_code", "policy_version"):
            _code(getattr(self, field), field)
        _generation(self.generation_id, "generation_id")
        _timestamp(self.occurred_at, "occurred_at")
        refs = _sorted_strings(self.object_ref_digests, "object_ref_digests", pattern=HEX64)
        object.__setattr__(self, "object_ref_digests", refs)
        expected = sha256(canonical_bytes(self._identity(self.to_mapping()))).hexdigest()
        if self.audit_id != expected:
            raise InvalidContractValue("audit_id does not match canonical audit reference")

    @classmethod
    def create(cls, **kwargs: object) -> "AuditReference":
        values = {"audit_record_version": AUDIT_RECORD_VERSION, **kwargs}
        values["object_ref_digests"] = tuple(sorted(set(values.get("object_ref_digests", ()))))
        identity = cls._identity({**values, "audit_id": ""})
        return cls(audit_id=sha256(canonical_bytes(identity)).hexdigest(), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "AuditReference":
        values = _strict(data, cls.FIELDS, "audit record")
        values["object_ref_digests"] = _sorted_strings(
            values["object_ref_digests"], "object_ref_digests", pattern=HEX64
        )
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "audit_record_version": self.audit_record_version,
            "audit_id": self.audit_id,
            "workspace_ref_hash": self.workspace_ref_hash,
            "actor_ref_hash": self.actor_ref_hash,
            "operation_ref_hash": self.operation_ref_hash,
            "correlation_ref_hash": self.correlation_ref_hash,
            "action": self.action,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "generation_id": self.generation_id,
            "object_ref_digests": list(self.object_ref_digests),
            "policy_version": self.policy_version,
            "occurred_at": self.occurred_at,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


class AuditSink(Protocol):
    def append(self, record: AuditReference) -> str: ...


class BoundedInMemoryAuditSink:
    def __init__(self, max_records: int) -> None:
        if max_records < 1:
            raise ValueError("max_records must be positive")
        self.max_records = max_records
        self._records: dict[str, bytes] = {}
        self._lock = RLock()

    def append(self, record: AuditReference) -> str:
        payload = record.canonical_bytes()
        with self._lock:
            existing = self._records.get(record.audit_id)
            if existing is not None:
                if existing != payload:
                    raise OperabilityError("audit_binding_conflict", "audit id binding changed")
                return "duplicate"
            if len(self._records) >= self.max_records:
                raise AuditCapacityExceeded()
            self._records[record.audit_id] = payload
            return "stored"

    def records(self) -> tuple[AuditReference, ...]:
        with self._lock:
            return tuple(AuditReference.from_mapping(json.loads(v)) for _, v in sorted(self._records.items()))

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)


class AuditRecorder:
    def __init__(self, hasher: ReferenceHasher, sink: AuditSink, *, policy_version: str) -> None:
        _code(policy_version, "policy_version")
        self.hasher = hasher
        self.sink = sink
        self.policy_version = policy_version

    def record(
        self,
        *,
        workspace_id: str,
        actor_id: str,
        operation_id: str,
        correlation_id: str,
        action: str,
        outcome: str,
        reason_code: str,
        occurred_at: str,
        generation_id: str | None = None,
        object_refs: Sequence[str] = (),
    ) -> AuditReference:
        # There is intentionally no free-form message/body/prompt parameter.
        record = AuditReference.create(
            workspace_ref_hash=self.hasher.digest(workspace_id),
            actor_ref_hash=self.hasher.digest(actor_id),
            operation_ref_hash=self.hasher.digest(operation_id),
            correlation_ref_hash=self.hasher.digest(correlation_id),
            action=action,
            outcome=outcome,
            reason_code=reason_code,
            generation_id=generation_id,
            object_ref_digests=tuple(sorted({self.hasher.digest(ref) for ref in object_refs})),
            policy_version=self.policy_version,
            occurred_at=occurred_at,
        )
        self.sink.append(record)
        return record


@dataclass(frozen=True)
class TelemetryPoint:
    telemetry_point_version: str
    point_id: str
    workspace_ref_hash: str
    metric_name: str
    time_bucket: str
    value_bucket: str
    count: str
    status_code: str

    FIELDS = {
        "telemetry_point_version", "point_id", "workspace_ref_hash", "metric_name",
        "time_bucket", "value_bucket", "count", "status_code",
    }

    @staticmethod
    def _identity(values: Mapping[str, object]) -> dict[str, object]:
        return {k: values[k] for k in TelemetryPoint.FIELDS - {"point_id"}}

    def __post_init__(self) -> None:
        if self.telemetry_point_version != TELEMETRY_POINT_VERSION:
            raise UnsupportedContractVersion("unsupported telemetry point version")
        _hex64(self.workspace_ref_hash, "workspace_ref_hash")
        for field in ("metric_name", "value_bucket", "status_code"):
            _code(getattr(self, field), field)
        _timestamp(self.time_bucket, "time_bucket")
        _uint(self.count, "count", positive=True)
        expected = sha256(canonical_bytes(self._identity(self.to_mapping()))).hexdigest()
        if self.point_id != expected:
            raise InvalidContractValue("point_id does not match canonical telemetry point")

    @classmethod
    def create(cls, **kwargs: object) -> "TelemetryPoint":
        values = {"telemetry_point_version": TELEMETRY_POINT_VERSION, **kwargs}
        identity = cls._identity({**values, "point_id": ""})
        return cls(point_id=sha256(canonical_bytes(identity)).hexdigest(), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "TelemetryPoint":
        return cls(**_strict(data, cls.FIELDS, "telemetry point"))

    def to_mapping(self) -> dict[str, object]:
        return {
            "telemetry_point_version": self.telemetry_point_version,
            "point_id": self.point_id,
            "workspace_ref_hash": self.workspace_ref_hash,
            "metric_name": self.metric_name,
            "time_bucket": self.time_bucket,
            "value_bucket": self.value_bucket,
            "count": self.count,
            "status_code": self.status_code,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


class TelemetrySink(Protocol):
    def emit(self, point: TelemetryPoint) -> None: ...


@dataclass(frozen=True)
class TelemetryDeliveryResult:
    status: str
    point_id: str
    error_code: str | None
    audit_id: str | None


class PrivacyPreservingTelemetry:
    def __init__(self, sink: TelemetrySink, audit: AuditRecorder) -> None:
        self.sink = sink
        self.audit = audit

    def emit(
        self,
        point: TelemetryPoint,
        *,
        workspace_id: str,
        actor_id: str,
        operation_id: str,
        correlation_id: str,
        occurred_at: str,
    ) -> TelemetryDeliveryResult:
        try:
            self.sink.emit(point)
            return TelemetryDeliveryResult("delivered", point.point_id, None, None)
        except Exception:
            try:
                audit = self.audit.record(
                    workspace_id=workspace_id,
                    actor_id=actor_id,
                    operation_id=operation_id,
                    correlation_id=correlation_id,
                    action="telemetry.emit",
                    outcome="degraded",
                    reason_code="telemetry_unavailable",
                    occurred_at=occurred_at,
                    object_refs=(point.point_id,),
                )
            except Exception as exc:
                raise TelemetryAuditUnavailable() from exc
            return TelemetryDeliveryResult("audit_only", point.point_id, "telemetry_unavailable", audit.audit_id)


@dataclass(frozen=True)
class BoundedWorkItem:
    work_item_version: str
    work_id: str
    workspace_ref_hash: str
    operation_ref_hash: str
    work_type: str
    payload_ref_digest: str
    cost_units: str
    enqueued_at: str
    deadline_at: str

    FIELDS = {
        "work_item_version", "work_id", "workspace_ref_hash", "operation_ref_hash",
        "work_type", "payload_ref_digest", "cost_units", "enqueued_at", "deadline_at",
    }

    @staticmethod
    def _identity(values: Mapping[str, object]) -> dict[str, object]:
        return {k: values[k] for k in BoundedWorkItem.FIELDS - {"work_id"}}

    def __post_init__(self) -> None:
        if self.work_item_version != WORK_ITEM_VERSION:
            raise UnsupportedContractVersion("unsupported work item version")
        for field in ("workspace_ref_hash", "operation_ref_hash", "payload_ref_digest"):
            _hex64(getattr(self, field), field)
        _code(self.work_type, "work_type")
        _uint(self.cost_units, "cost_units", positive=True)
        enqueued = _timestamp(self.enqueued_at, "enqueued_at")
        deadline = _timestamp(self.deadline_at, "deadline_at")
        if deadline <= enqueued:
            raise InvalidContractValue("deadline_at must be later than enqueued_at")
        expected = sha256(canonical_bytes(self._identity(self.to_mapping()))).hexdigest()
        if self.work_id != expected:
            raise InvalidContractValue("work_id does not match canonical work item")

    @classmethod
    def create(cls, **kwargs: object) -> "BoundedWorkItem":
        values = {"work_item_version": WORK_ITEM_VERSION, **kwargs}
        identity = cls._identity({**values, "work_id": ""})
        return cls(work_id=sha256(canonical_bytes(identity)).hexdigest(), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "BoundedWorkItem":
        return cls(**_strict(data, cls.FIELDS, "work item"))

    def to_mapping(self) -> dict[str, object]:
        return {
            "work_item_version": self.work_item_version,
            "work_id": self.work_id,
            "workspace_ref_hash": self.workspace_ref_hash,
            "operation_ref_hash": self.operation_ref_hash,
            "work_type": self.work_type,
            "payload_ref_digest": self.payload_ref_digest,
            "cost_units": self.cost_units,
            "enqueued_at": self.enqueued_at,
            "deadline_at": self.deadline_at,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class QueueDecision:
    status: str
    work_id: str
    error_code: str | None
    retry_after_ms: str | None


class BoundedWorkQueue:
    def __init__(self, *, max_items: int, max_cost_units: int, per_workspace_max_items: int) -> None:
        if min(max_items, max_cost_units, per_workspace_max_items) < 1:
            raise ValueError("queue limits must be positive")
        if per_workspace_max_items > max_items:
            raise ValueError("per_workspace_max_items cannot exceed max_items")
        self.max_items = max_items
        self.max_cost_units = max_cost_units
        self.per_workspace_max_items = per_workspace_max_items
        self._items: deque[BoundedWorkItem] = deque()
        self._by_id: dict[str, bytes] = {}
        self._workspace_counts: dict[str, int] = {}
        self._cost = 0
        self._lock = RLock()

    @staticmethod
    def _expired(item: BoundedWorkItem, now: str) -> bool:
        return _timestamp(now, "now") >= _timestamp(item.deadline_at, "deadline_at")

    def submit(self, item: BoundedWorkItem, *, now: str) -> QueueDecision:
        _timestamp(now, "now")
        payload = item.canonical_bytes()
        with self._lock:
            existing = self._by_id.get(item.work_id)
            if existing is not None:
                if existing != payload:
                    return QueueDecision("rejected", item.work_id, "work_binding_conflict", None)
                return QueueDecision("duplicate", item.work_id, None, None)
            if self._expired(item, now):
                return QueueDecision("rejected", item.work_id, "work_deadline_expired", None)
            if len(self._items) >= self.max_items:
                return QueueDecision("retry_later", item.work_id, "queue_full", "1000")
            count = self._workspace_counts.get(item.workspace_ref_hash, 0)
            if count >= self.per_workspace_max_items:
                return QueueDecision("retry_later", item.work_id, "workspace_queue_full", "1000")
            cost = int(item.cost_units)
            if self._cost + cost > self.max_cost_units:
                return QueueDecision("retry_later", item.work_id, "queue_cost_budget_exceeded", "1000")
            self._items.append(item)
            self._by_id[item.work_id] = payload
            self._workspace_counts[item.workspace_ref_hash] = count + 1
            self._cost += cost
            return QueueDecision("accepted", item.work_id, None, None)

    def _remove_accounting(self, item: BoundedWorkItem) -> None:
        self._by_id.pop(item.work_id, None)
        self._workspace_counts[item.workspace_ref_hash] -= 1
        if self._workspace_counts[item.workspace_ref_hash] == 0:
            self._workspace_counts.pop(item.workspace_ref_hash, None)
        self._cost -= int(item.cost_units)

    def pop(self, *, now: str) -> BoundedWorkItem | None:
        _timestamp(now, "now")
        with self._lock:
            while self._items:
                item = self._items.popleft()
                self._remove_accounting(item)
                if self._expired(item, now):
                    continue
                return item
            return None

    def remove(self, work_id: str) -> bool:
        with self._lock:
            payload = self._by_id.get(work_id)
            if payload is None:
                return False
            item = BoundedWorkItem.from_mapping(json.loads(payload))
            self._items = deque(v for v in self._items if v.work_id != work_id)
            self._remove_accounting(item)
            return True

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._items)

    @property
    def cost_units(self) -> int:
        with self._lock:
            return self._cost


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    error_code: str | None
    attempts: str
    total_cost_units: str


class RetryBudget:
    def __init__(self, *, max_operations: int, max_attempts: int, max_total_cost_units: int) -> None:
        if min(max_operations, max_attempts, max_total_cost_units) < 1:
            raise ValueError("retry budget limits must be positive")
        self.max_operations = max_operations
        self.max_attempts = max_attempts
        self.max_total_cost_units = max_total_cost_units
        self._values: dict[str, tuple[int, int]] = {}
        self._lock = RLock()

    def reserve(self, operation_ref_hash: str, cost_units: str) -> BudgetDecision:
        _hex64(operation_ref_hash, "operation_ref_hash")
        cost = _uint(cost_units, "cost_units", positive=True)
        with self._lock:
            current = self._values.get(operation_ref_hash)
            if current is None and len(self._values) >= self.max_operations:
                return BudgetDecision(False, "operation_budget_store_full", "0", "0")
            attempts, total = current or (0, 0)
            if attempts + 1 > self.max_attempts:
                return BudgetDecision(False, "retry_attempt_budget_exceeded", str(attempts), str(total))
            if total + cost > self.max_total_cost_units:
                return BudgetDecision(False, "retry_cost_budget_exceeded", str(attempts), str(total))
            attempts += 1
            total += cost
            self._values[operation_ref_hash] = (attempts, total)
            return BudgetDecision(True, None, str(attempts), str(total))

    def rollback(self, operation_ref_hash: str, cost_units: str) -> None:
        _hex64(operation_ref_hash, "operation_ref_hash")
        cost = _uint(cost_units, "cost_units", positive=True)
        with self._lock:
            current = self._values.get(operation_ref_hash)
            if current is None:
                return
            attempts, total = current
            if attempts < 1 or total < cost:
                raise OperabilityError("retry_budget_underflow", "retry budget rollback underflow")
            attempts -= 1
            total -= cost
            if attempts == 0:
                self._values.pop(operation_ref_hash, None)
            else:
                self._values[operation_ref_hash] = (attempts, total)

    def complete(self, operation_ref_hash: str) -> None:
        _hex64(operation_ref_hash, "operation_ref_hash")
        with self._lock:
            self._values.pop(operation_ref_hash, None)

    def state(self, operation_ref_hash: str) -> tuple[str, str] | None:
        with self._lock:
            value = self._values.get(operation_ref_hash)
            return None if value is None else (str(value[0]), str(value[1]))


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True)
class CircuitDecision:
    allowed: bool
    state: str
    error_code: str | None
    retry_after_ms: str | None


class CircuitBreaker:
    def __init__(self, *, failure_threshold: int, reset_after_seconds: int) -> None:
        if failure_threshold < 1 or reset_after_seconds < 1:
            raise ValueError("circuit breaker limits must be positive")
        self.failure_threshold = failure_threshold
        self.reset_after_seconds = reset_after_seconds
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._opened_at: datetime | None = None
        self._half_open_inflight = False
        self._lock = RLock()

    def before_call(self, *, now: str) -> CircuitDecision:
        current = _timestamp(now, "now")
        with self._lock:
            if self._state is CircuitState.CLOSED:
                return CircuitDecision(True, self._state.value, None, None)
            if self._state is CircuitState.OPEN:
                assert self._opened_at is not None
                elapsed = (current - self._opened_at).total_seconds()
                if elapsed < self.reset_after_seconds:
                    remaining = max(1, int((self.reset_after_seconds - elapsed) * 1000))
                    return CircuitDecision(False, self._state.value, "circuit_open", str(remaining))
                self._state = CircuitState.HALF_OPEN
                self._half_open_inflight = False
            if self._half_open_inflight:
                return CircuitDecision(False, self._state.value, "circuit_half_open_busy", "1000")
            self._half_open_inflight = True
            return CircuitDecision(True, self._state.value, None, None)

    def cancel_probe(self) -> None:
        with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                self._half_open_inflight = False

    def record_success(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failures = 0
            self._opened_at = None
            self._half_open_inflight = False

    def record_failure(self, *, now: str) -> None:
        current = _timestamp(now, "now")
        with self._lock:
            self._failures += 1
            self._half_open_inflight = False
            if self._state is CircuitState.HALF_OPEN or self._failures >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = current

    @property
    def state(self) -> str:
        with self._lock:
            return self._state.value


class BackpressureController:
    def __init__(self, queue: BoundedWorkQueue, budget: RetryBudget, circuit: CircuitBreaker) -> None:
        self.queue = queue
        self.budget = budget
        self.circuit = circuit
        self._lock = RLock()

    def submit(self, item: BoundedWorkItem, *, now: str) -> QueueDecision:
        with self._lock:
            gate = self.circuit.before_call(now=now)
            if not gate.allowed:
                return QueueDecision("retry_later", item.work_id, gate.error_code, gate.retry_after_ms)
            queued = self.queue.submit(item, now=now)
            if queued.status != "accepted":
                self.circuit.cancel_probe()
                return queued
            budget = self.budget.reserve(item.operation_ref_hash, item.cost_units)
            if not budget.allowed:
                self.queue.remove(item.work_id)
                self.circuit.cancel_probe()
                return QueueDecision("rejected", item.work_id, budget.error_code, None)
            return queued

    def record_success(self, operation_ref_hash: str) -> None:
        self.budget.complete(operation_ref_hash)
        self.circuit.record_success()

    def record_failure(self, *, now: str) -> None:
        self.circuit.record_failure(now=now)

    def cancel(self, item: BoundedWorkItem) -> None:
        with self._lock:
            if self.queue.remove(item.work_id):
                self.budget.rollback(item.operation_ref_hash, item.cost_units)
            self.circuit.cancel_probe()


@dataclass(frozen=True)
class ExportRequest:
    export_request_version: str
    request_id: str
    workspace_id: str
    actor_id: str
    as_of_generation_id: str
    target_class: str
    projection_profile: str
    field_allowlist: tuple[str, ...]
    max_sensitivity: str
    delivery_intent_ref: str
    requested_at: str

    FIELDS = {
        "export_request_version", "request_id", "workspace_id", "actor_id",
        "as_of_generation_id", "target_class", "projection_profile", "field_allowlist",
        "max_sensitivity", "delivery_intent_ref", "requested_at",
    }

    @staticmethod
    def _identity(values: Mapping[str, object]) -> dict[str, object]:
        result = {k: values[k] for k in ExportRequest.FIELDS - {"request_id"}}
        result["field_allowlist"] = list(result["field_allowlist"])
        return result

    def __post_init__(self) -> None:
        if self.export_request_version != EXPORT_REQUEST_VERSION:
            raise UnsupportedContractVersion("unsupported export request version")
        _nonempty(self.workspace_id, "workspace_id")
        _nonempty(self.actor_id, "actor_id")
        _generation(self.as_of_generation_id, "as_of_generation_id", nullable=False)
        if self.target_class not in EXPORT_TARGET_CEILINGS:
            raise InvalidContractValue("unsupported export target_class")
        _code(self.projection_profile, "projection_profile")
        fields = _sorted_strings(self.field_allowlist, "field_allowlist", pattern=FIELD_PATH, allow_empty=False)
        for field in fields:
            if set(field.split(".")) & FORBIDDEN_EXPORT_FIELDS:
                raise InvalidContractValue(f"field_allowlist contains forbidden field: {field}")
        object.__setattr__(self, "field_allowlist", fields)
        sensitivity = Sensitivity(self.max_sensitivity)
        if sensitivity.rank > EXPORT_TARGET_CEILINGS[self.target_class].rank:
            raise InvalidContractValue("max_sensitivity exceeds target class ceiling")
        _hex64(self.delivery_intent_ref, "delivery_intent_ref")
        _timestamp(self.requested_at, "requested_at")
        expected = sha256(canonical_bytes(self._identity(self.to_mapping()))).hexdigest()
        if self.request_id != expected:
            raise InvalidContractValue("request_id does not match canonical export request")

    @classmethod
    def create(cls, **kwargs: object) -> "ExportRequest":
        values = {"export_request_version": EXPORT_REQUEST_VERSION, **kwargs}
        values["field_allowlist"] = tuple(sorted(set(values.get("field_allowlist", ()))))
        identity = cls._identity({**values, "request_id": ""})
        return cls(request_id=sha256(canonical_bytes(identity)).hexdigest(), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "ExportRequest":
        values = _strict(data, cls.FIELDS, "export request")
        values["field_allowlist"] = _sorted_strings(
            values["field_allowlist"], "field_allowlist", pattern=FIELD_PATH, allow_empty=False
        )
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "export_request_version": self.export_request_version,
            "request_id": self.request_id,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "as_of_generation_id": self.as_of_generation_id,
            "target_class": self.target_class,
            "projection_profile": self.projection_profile,
            "field_allowlist": list(self.field_allowlist),
            "max_sensitivity": self.max_sensitivity,
            "delivery_intent_ref": self.delivery_intent_ref,
            "requested_at": self.requested_at,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class ExportProjectionJob:
    export_job_version: str
    job_id: str
    request_id: str
    workspace_id: str
    as_of_generation_id: str
    target_class: str
    projection_profile: str
    field_allowlist: tuple[str, ...]
    max_sensitivity: str
    delivery_intent_ref: str

    FIELDS = {
        "export_job_version", "job_id", "request_id", "workspace_id",
        "as_of_generation_id", "target_class", "projection_profile", "field_allowlist",
        "max_sensitivity", "delivery_intent_ref",
    }

    @staticmethod
    def _identity(values: Mapping[str, object]) -> dict[str, object]:
        result = {k: values[k] for k in ExportProjectionJob.FIELDS - {"job_id"}}
        result["field_allowlist"] = list(result["field_allowlist"])
        return result

    def __post_init__(self) -> None:
        if self.export_job_version != EXPORT_JOB_VERSION:
            raise UnsupportedContractVersion("unsupported export job version")
        _hex64(self.request_id, "request_id")
        _nonempty(self.workspace_id, "workspace_id")
        _generation(self.as_of_generation_id, "as_of_generation_id", nullable=False)
        if self.target_class not in EXPORT_TARGET_CEILINGS:
            raise InvalidContractValue("unsupported export target_class")
        _code(self.projection_profile, "projection_profile")
        fields = _sorted_strings(self.field_allowlist, "field_allowlist", pattern=FIELD_PATH, allow_empty=False)
        object.__setattr__(self, "field_allowlist", fields)
        sensitivity = Sensitivity(self.max_sensitivity)
        if sensitivity.rank > EXPORT_TARGET_CEILINGS[self.target_class].rank:
            raise InvalidContractValue("max_sensitivity exceeds target class ceiling")
        _hex64(self.delivery_intent_ref, "delivery_intent_ref")
        expected = sha256(canonical_bytes(self._identity(self.to_mapping()))).hexdigest()
        if self.job_id != expected:
            raise InvalidContractValue("job_id does not match canonical export projection job")

    @classmethod
    def from_request(cls, request: ExportRequest) -> "ExportProjectionJob":
        values = {
            "export_job_version": EXPORT_JOB_VERSION,
            "request_id": request.request_id,
            "workspace_id": request.workspace_id,
            "as_of_generation_id": request.as_of_generation_id,
            "target_class": request.target_class,
            "projection_profile": request.projection_profile,
            "field_allowlist": request.field_allowlist,
            "max_sensitivity": request.max_sensitivity,
            "delivery_intent_ref": request.delivery_intent_ref,
        }
        identity = cls._identity({**values, "job_id": ""})
        return cls(job_id=sha256(canonical_bytes(identity)).hexdigest(), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "ExportProjectionJob":
        values = _strict(data, cls.FIELDS, "export projection job")
        values["field_allowlist"] = _sorted_strings(
            values["field_allowlist"], "field_allowlist", pattern=FIELD_PATH, allow_empty=False
        )
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "export_job_version": self.export_job_version,
            "job_id": self.job_id,
            "request_id": self.request_id,
            "workspace_id": self.workspace_id,
            "as_of_generation_id": self.as_of_generation_id,
            "target_class": self.target_class,
            "projection_profile": self.projection_profile,
            "field_allowlist": list(self.field_allowlist),
            "max_sensitivity": self.max_sensitivity,
            "delivery_intent_ref": self.delivery_intent_ref,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


class ProjectionJobSubmitter(Protocol):
    def submit(self, job: ExportProjectionJob) -> str: ...
    def cancel(self, job_id: str) -> bool: ...


class BoundedProjectionJobSubmitter:
    def __init__(self, max_jobs: int) -> None:
        if max_jobs < 1:
            raise ValueError("max_jobs must be positive")
        self.max_jobs = max_jobs
        self._jobs: dict[str, bytes] = {}
        self._order: deque[str] = deque()
        self._lock = RLock()

    def submit(self, job: ExportProjectionJob) -> str:
        payload = job.canonical_bytes()
        with self._lock:
            existing = self._jobs.get(job.job_id)
            if existing is not None:
                if existing != payload:
                    raise OperabilityError("export_job_binding_conflict", "job binding changed")
                return "duplicate"
            if len(self._jobs) >= self.max_jobs:
                return "queue_full"
            self._jobs[job.job_id] = payload
            self._order.append(job.job_id)
            return "accepted"

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            if job_id not in self._jobs:
                return False
            self._jobs.pop(job_id)
            self._order = deque(v for v in self._order if v != job_id)
            return True

    def pop(self) -> ExportProjectionJob | None:
        with self._lock:
            if not self._order:
                return None
            job_id = self._order.popleft()
            return ExportProjectionJob.from_mapping(json.loads(self._jobs.pop(job_id)))

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._jobs)


@dataclass(frozen=True)
class ExportSubmissionResult:
    status: str
    request_id: str
    job_id: str | None
    error_code: str | None
    audit_id: str | None


class ExportRequestGateway:
    """Policy-checks and queues a projection job; no destination-write port exists."""

    def __init__(
        self,
        submitter: ProjectionJobSubmitter,
        audit: AuditRecorder,
        *,
        policy: PolicyEngine | None = None,
        now: str,
    ) -> None:
        self.submitter = submitter
        self.audit = audit
        self.policy = policy or PolicyEngine()
        self.now = now

    def submit(self, request: ExportRequest, token: CapabilityToken, *, correlation_id: str) -> ExportSubmissionResult:
        decision = self.policy.authorize(
            token,
            PolicyRequest(
                workspace_id=request.workspace_id,
                actor_id=request.actor_id,
                action="export.request",
                now=self.now,
                object_sensitivity=Sensitivity(request.max_sensitivity),
            ),
        )
        if not decision.allowed:
            audit = self.audit.record(
                workspace_id=request.workspace_id,
                actor_id=request.actor_id,
                operation_id=request.request_id,
                correlation_id=correlation_id,
                action="export.request",
                outcome="denied",
                reason_code=decision.reason.value,
                occurred_at=self.now,
                generation_id=request.as_of_generation_id,
                object_refs=(request.delivery_intent_ref,),
            )
            return ExportSubmissionResult("rejected", request.request_id, None, decision.reason.value, audit.audit_id)

        job = ExportProjectionJob.from_request(request)
        try:
            queue_status = self.submitter.submit(job)
        except Exception:
            queue_status = "unavailable"
        if queue_status == "duplicate":
            return ExportSubmissionResult("accepted", request.request_id, job.job_id, None, None)
        if queue_status != "accepted":
            reason = "export_queue_full" if queue_status == "queue_full" else "export_queue_unavailable"
            audit = self.audit.record(
                workspace_id=request.workspace_id,
                actor_id=request.actor_id,
                operation_id=request.request_id,
                correlation_id=correlation_id,
                action="export.request",
                outcome="deferred",
                reason_code=reason,
                occurred_at=self.now,
                generation_id=request.as_of_generation_id,
                object_refs=(job.job_id, request.delivery_intent_ref),
            )
            return ExportSubmissionResult("retry_later", request.request_id, None, reason, audit.audit_id)

        try:
            audit = self.audit.record(
                workspace_id=request.workspace_id,
                actor_id=request.actor_id,
                operation_id=request.request_id,
                correlation_id=correlation_id,
                action="export.request",
                outcome="accepted",
                reason_code="projection_job_queued",
                occurred_at=self.now,
                generation_id=request.as_of_generation_id,
                object_refs=(job.job_id, request.delivery_intent_ref),
            )
        except Exception:
            self.submitter.cancel(job.job_id)
            raise
        return ExportSubmissionResult("accepted", request.request_id, job.job_id, None, audit.audit_id)
