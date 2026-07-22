"""P4-01 Runtime Orchestrator state machine.

The orchestrator is intentionally storage- and provider-independent. It owns
stable operation identity, cooperative cancellation, absolute deadlines,
stage leases/fencing, retry resumption, and content-bound stage result refs.
Concrete intent/retrieval/model components are injected by later Phase 4 PRs.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
import unicodedata
from threading import RLock
from typing import Callable, Mapping, Protocol, Sequence

from wiki_spike.memory_core.contracts import JsonValue
from .errors import InvalidContractValue

from .contracts import (
    CANCELLATION_SIGNAL_VERSION,
    RUNTIME_RESPONSE_VERSION,
    RUNTIME_STATUS_VERSION,
    CancellationSignal,
    canonical_bytes,
    OperationState,
    RuntimeRequest,
    RuntimeResponse,
    RuntimeResponseStatus,
    RuntimeStatus,
    STAGE_STATES,
    StageDisposition,
    StageResultRef,
    TERMINAL_STATES,
    format_utc_timestamp,
    parse_utc_timestamp,
    response_status_for_state,
)

_STAGE_INPUT_DOMAIN = b"wiki.runtime.stage-input.v1\x00"
_STAGE_CONTENT_DOMAIN = b"wiki.runtime.stage-content.v1\x00"
_CLAIM_DOMAIN = b"wiki.runtime.stage-claim.v1\x00"
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_MAX_CANCELLATION_CLOCK_SKEW = timedelta(minutes=5)


def _runtime_code(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise InvalidContractValue(f"{field} must be a Runtime code")
    normalized = unicodedata.normalize("NFC", value)
    if not _SAFE_CODE.fullmatch(normalized):
        raise InvalidContractValue(
            f"{field} must be a lowercase code using [a-z0-9_.-] and start with a letter"
        )
    return normalized


class RuntimeOrchestrationError(RuntimeError):
    """Stable base error for invalid orchestration state."""


class OperationConflict(RuntimeOrchestrationError):
    pass


class StageClaimConflict(RuntimeOrchestrationError):
    pass


class StageResultConflict(RuntimeOrchestrationError):
    pass


class TransientStageError(RuntimeOrchestrationError):
    def __init__(self, error_code: str = "stage_temporarily_unavailable") -> None:
        error_code = _runtime_code(error_code, "error_code")
        super().__init__(error_code)
        self.error_code = error_code


class FatalStageError(RuntimeOrchestrationError):
    def __init__(self, error_code: str = "stage_failed") -> None:
        error_code = _runtime_code(error_code, "error_code")
        super().__init__(error_code)
        self.error_code = error_code


class OperationCancelled(RuntimeOrchestrationError):
    pass


class OperationDeadlineExceeded(RuntimeOrchestrationError):
    pass


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass(frozen=True)
class RuntimeOperationInput:
    """Semantic request view exposed to stage handlers.

    Delivery-only fields such as ``request_id`` and ``received_at`` are excluded
    so a retried delivery cannot accidentally alter model prompts, retrieval, or
    any other stage semantics.
    """

    operation_id: str
    idempotency_key: str
    workspace_id: str
    actor_id: str
    request_type: str
    deadline_at: str
    requested_generation_id: str | None
    payload: dict[str, JsonValue]

    @classmethod
    def from_request(cls, request: RuntimeRequest) -> "RuntimeOperationInput":
        copied = json.loads(canonical_bytes({"payload": request.payload}).decode("utf-8"))["payload"]
        if not isinstance(copied, dict):
            raise InvalidContractValue("Runtime operation payload must remain an object")
        return cls(
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            workspace_id=request.workspace_id,
            actor_id=request.actor_id,
            request_type=request.request_type,
            deadline_at=request.deadline_at,
            requested_generation_id=request.requested_generation_id,
            payload=copied,
        )


@dataclass(frozen=True)
class RuntimeStageResult:
    stage_name: str
    payload: dict[str, JsonValue]
    disposition: StageDisposition = StageDisposition.CONTINUE
    schema_id: str = "phase4-stage-result-payload-v1"
    provenance_refs: tuple[str, ...] = ()
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.stage_name, str) or self.stage_name not in {item.value for item in STAGE_STATES}:
            raise InvalidContractValue("RuntimeStageResult.stage_name is unsupported")
        object.__setattr__(self, "stage_name", unicodedata.normalize("NFC", self.stage_name))
        if not isinstance(self.disposition, StageDisposition):
            raise InvalidContractValue("RuntimeStageResult.disposition must be a StageDisposition")
        if not isinstance(self.schema_id, str) or not self.schema_id:
            raise InvalidContractValue("RuntimeStageResult.schema_id must be non-empty")
        object.__setattr__(self, "schema_id", unicodedata.normalize("NFC", self.schema_id))
        terminal_defaults = {
            StageDisposition.REJECT: "stage_rejected",
            StageDisposition.ABSTAIN: "stage_abstained",
            StageDisposition.DEGRADE: "stage_degraded",
        }
        if self.disposition in terminal_defaults and self.error_code is None:
            object.__setattr__(self, "error_code", terminal_defaults[self.disposition])
        elif self.disposition in {StageDisposition.CONTINUE, StageDisposition.COMPLETE} and self.error_code is not None:
            raise InvalidContractValue("continue/complete stage result must not carry error_code")
        if self.error_code is not None:
            object.__setattr__(self, "error_code", _runtime_code(self.error_code, "error_code"))
        if not isinstance(self.provenance_refs, (list, tuple)) or isinstance(self.provenance_refs, (str, bytes)):
            raise InvalidContractValue("RuntimeStageResult.provenance_refs must be an array")
        refs = tuple(
            unicodedata.normalize("NFC", item)
            for item in self.provenance_refs
            if isinstance(item, str)
        )
        if len(refs) != len(self.provenance_refs) or any(not item for item in refs):
            raise InvalidContractValue("RuntimeStageResult.provenance_refs must be non-empty strings")
        if tuple(sorted(set(refs))) != refs:
            raise InvalidContractValue("RuntimeStageResult.provenance_refs must be sorted and unique")
        object.__setattr__(self, "provenance_refs", refs)
        if not isinstance(self.payload, Mapping):
            raise InvalidContractValue("RuntimeStageResult.payload must be an object")
        normalized = json.loads(canonical_bytes({"payload": self.payload}).decode("utf-8"))["payload"]
        if not isinstance(normalized, dict):
            raise InvalidContractValue("RuntimeStageResult.payload must be an object")
        object.__setattr__(self, "payload", normalized)

    def semantic_mapping(self) -> dict[str, object]:
        return {
            "stage_name": self.stage_name,
            "payload": json.loads(canonical_bytes({"payload": self.payload}).decode("utf-8"))["payload"],
            "disposition": self.disposition.value,
            "schema_id": self.schema_id,
            "provenance_refs": list(self.provenance_refs),
            "error_code": self.error_code,
        }


class RuntimeStageHandler(Protocol):
    stage_name: str

    def execute(self, context: "StageExecutionContext") -> RuntimeStageResult: ...


@dataclass(frozen=True)
class PipelineDefinition:
    pipeline_id: str
    request_type: str
    stages: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.pipeline_id, str) or not self.pipeline_id:
            raise InvalidContractValue("pipeline_id and request_type must be non-empty")
        if not isinstance(self.request_type, str) or not self.request_type:
            raise InvalidContractValue("pipeline_id and request_type must be non-empty")
        object.__setattr__(self, "pipeline_id", unicodedata.normalize("NFC", self.pipeline_id))
        object.__setattr__(self, "request_type", unicodedata.normalize("NFC", self.request_type))
        if not isinstance(self.stages, (list, tuple)) or isinstance(self.stages, (str, bytes)):
            raise InvalidContractValue("pipeline stages must be an array")
        stages = tuple(self.stages)
        if not stages:
            raise InvalidContractValue("pipeline must contain at least one stage")
        if any(not isinstance(stage, str) or stage not in {item.value for item in STAGE_STATES} for stage in stages):
            raise InvalidContractValue("pipeline contains an unsupported stage")
        object.__setattr__(self, "stages", stages)
        order = {state.value: index for index, state in enumerate(STAGE_STATES)}
        indexes = [order[stage] for stage in stages]
        if indexes != sorted(set(indexes)):
            raise InvalidContractValue("pipeline stages must be strictly ordered and unique")
        if self.stages[0] != OperationState.PLANNED.value:
            raise InvalidContractValue("pipeline must begin with planned")
        if OperationState.GENERATED.value in self.stages and OperationState.VERIFIED.value not in self.stages:
            raise InvalidContractValue("generated stage requires a later verified stage")
        if OperationState.PROPOSED.value in self.stages:
            if OperationState.VERIFIED.value not in self.stages:
                raise InvalidContractValue("proposed stage requires verified")
            if self.stages[-1] != OperationState.PROPOSED.value:
                raise InvalidContractValue("proposed must be the final pipeline stage")


@dataclass(frozen=True)
class StageExecutionContext:
    request: RuntimeOperationInput
    stage_name: str
    previous_result_refs: tuple[StageResultRef, ...]
    input_digest: str
    attempt: str
    _clock: Clock = field(repr=False)
    _cancelled: Callable[[], bool] = field(repr=False)

    def now(self) -> datetime:
        value = self._clock.now()
        if value.tzinfo is None:
            raise RuntimeOrchestrationError("Clock.now() must be timezone-aware")
        return value.astimezone(timezone.utc)

    def raise_if_cancelled(self) -> None:
        if self._cancelled():
            raise OperationCancelled("operation cancellation requested")

    def raise_if_expired(self) -> None:
        if self.now() >= parse_utc_timestamp(self.request.deadline_at, "deadline_at"):
            raise OperationDeadlineExceeded("operation deadline exceeded")

    def checkpoint(self) -> None:
        self.raise_if_cancelled()
        self.raise_if_expired()


@dataclass(frozen=True)
class StageClaim:
    claim_token: str
    stage_name: str
    attempt: int
    input_digest: str


@dataclass(frozen=True)
class ClaimDecision:
    record: "_OperationRecord"
    claim: StageClaim | None
    outcome: str


@dataclass(frozen=True)
class _ActiveClaim:
    claim_token: str
    request_id: str
    stage_name: str
    attempt: int
    lease_expires_at: datetime
    input_digest: str


@dataclass(frozen=True)
class _OperationRecord:
    operation_id: str
    idempotency_key: str
    workspace_id: str
    actor_id: str
    request_type: str
    requested_generation_id: str | None
    deadline_at: str
    pipeline_id: str
    pipeline_stages: tuple[str, ...]
    state: OperationState
    stage_index: int
    stage_result_refs: tuple[StageResultRef, ...]
    attempts: tuple[tuple[str, int], ...]
    revision: int
    created_at: str
    updated_at: str
    cancellation: CancellationSignal | None = None
    active_claim: _ActiveClaim | None = None
    error_code: str | None = None

    def attempt_for(self, stage_name: str) -> int:
        return dict(self.attempts).get(stage_name, 0)

    def with_attempt(self, stage_name: str, value: int) -> "_OperationRecord":
        attempts = dict(self.attempts)
        attempts[stage_name] = value
        return replace(self, attempts=tuple(sorted(attempts.items())))


class OperationStore(Protocol):
    def register(self, request: RuntimeRequest, pipeline: PipelineDefinition, now: datetime) -> _OperationRecord: ...

    def get(self, workspace_id: str, operation_id: str) -> _OperationRecord | None: ...

    def refresh(self, workspace_id: str, operation_id: str, now: datetime) -> _OperationRecord | None: ...

    def request_cancel(self, signal: CancellationSignal, now: datetime) -> _OperationRecord | None: ...

    def is_cancelled(self, workspace_id: str, operation_id: str) -> bool: ...

    def claim_next(
        self,
        request: RuntimeRequest,
        *,
        request_id: str,
        now: datetime,
        lease_duration: timedelta,
        input_digest: str,
        max_attempts: int = 3,
        allow_exhausted: bool = False,
    ) -> ClaimDecision: ...

    def commit_stage(
        self,
        request: RuntimeRequest,
        claim: StageClaim,
        result_ref: StageResultRef,
        disposition: StageDisposition,
        error_code: str | None,
        now: datetime,
    ) -> _OperationRecord: ...

    def release_transient(
        self,
        request: RuntimeRequest,
        claim: StageClaim,
        error_code: str,
        now: datetime,
    ) -> _OperationRecord: ...

    def fail_stage(
        self,
        request: RuntimeRequest,
        claim: StageClaim,
        error_code: str,
        now: datetime,
        *,
        allow_expired: bool = False,
    ) -> _OperationRecord: ...


class InMemoryOperationStore:
    """Reference operation store with workspace-scoped idempotency and fencing."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], _OperationRecord] = {}
        self._idempotency: dict[tuple[str, str], str] = {}
        self._lock = RLock()

    @staticmethod
    def _key(workspace_id: str, operation_id: str) -> tuple[str, str]:
        return workspace_id, operation_id

    @staticmethod
    def _now_text(now: datetime) -> str:
        return format_utc_timestamp(now)

    def register(self, request: RuntimeRequest, pipeline: PipelineDefinition, now: datetime) -> _OperationRecord:
        with self._lock:
            idempotency_key = (request.workspace_id, request.idempotency_key)
            existing_operation = self._idempotency.get(idempotency_key)
            if existing_operation is not None and existing_operation != request.operation_id:
                raise OperationConflict("idempotency_payload_mismatch")
            key = self._key(request.workspace_id, request.operation_id)
            existing = self._records.get(key)
            if existing is not None:
                expected = (
                    request.actor_id,
                    request.request_type,
                    request.requested_generation_id,
                    request.deadline_at,
                    pipeline.pipeline_id,
                    pipeline.stages,
                )
                actual = (
                    existing.actor_id,
                    existing.request_type,
                    existing.requested_generation_id,
                    existing.deadline_at,
                    existing.pipeline_id,
                    existing.pipeline_stages,
                )
                if actual != expected:
                    raise OperationConflict("operation_binding_mismatch")
                return existing
            text = self._now_text(now)
            record = _OperationRecord(
                operation_id=request.operation_id,
                idempotency_key=request.idempotency_key,
                workspace_id=request.workspace_id,
                actor_id=request.actor_id,
                request_type=request.request_type,
                requested_generation_id=request.requested_generation_id,
                deadline_at=request.deadline_at,
                pipeline_id=pipeline.pipeline_id,
                pipeline_stages=pipeline.stages,
                state=OperationState.RECEIVED,
                stage_index=0,
                stage_result_refs=(),
                attempts=(),
                revision=0,
                created_at=text,
                updated_at=text,
            )
            self._records[key] = record
            self._idempotency[idempotency_key] = request.operation_id
            return record

    def get(self, workspace_id: str, operation_id: str) -> _OperationRecord | None:
        with self._lock:
            return self._records.get(self._key(workspace_id, operation_id))

    def refresh(self, workspace_id: str, operation_id: str, now: datetime) -> _OperationRecord | None:
        with self._lock:
            key = self._key(workspace_id, operation_id)
            record = self._records.get(key)
            if record is None:
                return None
            if record.active_claim is not None and record.active_claim.lease_expires_at <= now:
                record = replace(
                    record,
                    active_claim=None,
                    revision=record.revision + 1,
                    updated_at=self._now_text(now),
                )
            normalized = self._normalize_terminal(record, now)
            if normalized != self._records.get(key):
                self._records[key] = normalized
            return normalized

    def request_cancel(self, signal: CancellationSignal, now: datetime) -> _OperationRecord | None:
        with self._lock:
            key = self._key(signal.workspace_id, signal.operation_id)
            record = self._records.get(key)
            if record is None:
                return None
            if signal.actor_id != record.actor_id:
                raise OperationConflict("cancellation_actor_mismatch")
            requested_at = parse_utc_timestamp(signal.requested_at, "requested_at")
            # Producer clocks may lead the local worker slightly; only a signal that
            # predates the operation itself is semantically impossible.
            if requested_at < parse_utc_timestamp(record.created_at, "created_at"):
                raise OperationConflict("cancellation_precedes_operation")
            if requested_at > now + _MAX_CANCELLATION_CLOCK_SKEW:
                raise OperationConflict("cancellation_timestamp_too_far_in_future")
            if record.state in TERMINAL_STATES:
                return record
            if record.cancellation is not None:
                if record.cancellation.cancellation_id != signal.cancellation_id:
                    # First cancellation is immutable; later signals cannot rewrite audit meaning.
                    return record
                return record
            updated = replace(
                record,
                cancellation=signal,
                revision=record.revision + 1,
                updated_at=self._now_text(now),
            )
            if updated.state not in TERMINAL_STATES and updated.active_claim is None:
                updated = replace(
                    updated,
                    state=OperationState.CANCELLED,
                    error_code="cancelled",
                    revision=updated.revision + 1,
                )
            self._records[key] = updated
            return updated

    def is_cancelled(self, workspace_id: str, operation_id: str) -> bool:
        with self._lock:
            record = self._records.get(self._key(workspace_id, operation_id))
            return bool(record and record.cancellation is not None)

    def _normalize_terminal(self, record: _OperationRecord, now: datetime) -> _OperationRecord:
        if record.state in TERMINAL_STATES:
            return record
        if record.cancellation is not None and record.active_claim is None:
            return replace(
                record,
                state=OperationState.CANCELLED,
                error_code="cancelled",
                revision=record.revision + 1,
                updated_at=self._now_text(now),
            )
        if now >= parse_utc_timestamp(record.deadline_at, "deadline_at") and record.active_claim is None:
            return replace(
                record,
                state=OperationState.FAILED,
                error_code="deadline_exceeded",
                revision=record.revision + 1,
                updated_at=self._now_text(now),
            )
        if record.stage_index >= len(record.pipeline_stages) and record.active_claim is None:
            return replace(
                record,
                state=OperationState.COMPLETED,
                error_code=None,
                revision=record.revision + 1,
                updated_at=self._now_text(now),
            )
        return record

    def claim_next(
        self,
        request: RuntimeRequest,
        *,
        request_id: str,
        now: datetime,
        lease_duration: timedelta,
        input_digest: str,
        max_attempts: int = 3,
        allow_exhausted: bool = False,
    ) -> ClaimDecision:
        with self._lock:
            key = self._key(request.workspace_id, request.operation_id)
            record = self._records[key]
            if record.active_claim is not None and record.active_claim.lease_expires_at <= now:
                record = replace(
                    record,
                    active_claim=None,
                    revision=record.revision + 1,
                    updated_at=self._now_text(now),
                )
                self._records[key] = record
            normalized = self._normalize_terminal(record, now)
            if normalized != record:
                self._records[key] = normalized
                record = normalized
            if record.state in TERMINAL_STATES:
                return ClaimDecision(record, None, "terminal")
            active = record.active_claim
            if active is not None and active.lease_expires_at > now:
                return ClaimDecision(record, None, "busy")
            stage_name = record.pipeline_stages[record.stage_index]
            if record.attempt_for(stage_name) >= max_attempts and not allow_exhausted:
                exhausted = replace(
                    record,
                    active_claim=None,
                    state=OperationState.FAILED,
                    error_code="retry_budget_exhausted",
                    revision=record.revision + 1,
                    updated_at=self._now_text(now),
                )
                self._records[key] = exhausted
                return ClaimDecision(exhausted, None, "terminal")
            attempt = record.attempt_for(stage_name) + 1
            claim_token = sha256(
                _CLAIM_DOMAIN
                + canonical_bytes(
                    {
                        "operation_id": record.operation_id,
                        "stage_name": stage_name,
                        "attempt": str(attempt),
                        "request_id": request_id,
                        "input_digest": input_digest,
                    }
                )
            ).hexdigest()
            deadline = parse_utc_timestamp(record.deadline_at, "deadline_at")
            lease_expires = min(deadline, now + lease_duration)
            active_claim = _ActiveClaim(
                claim_token=claim_token,
                request_id=request_id,
                stage_name=stage_name,
                attempt=attempt,
                lease_expires_at=lease_expires,
                input_digest=input_digest,
            )
            updated = record.with_attempt(stage_name, attempt)
            updated = replace(
                updated,
                active_claim=active_claim,
                revision=updated.revision + 1,
                updated_at=self._now_text(now),
            )
            self._records[key] = updated
            return ClaimDecision(
                updated,
                StageClaim(claim_token, stage_name, attempt, input_digest),
                "claimed",
            )

    def _require_claim(
        self,
        record: _OperationRecord,
        claim: StageClaim,
        now: datetime | None = None,
    ) -> _ActiveClaim:
        active = record.active_claim
        if active is None or active.claim_token != claim.claim_token:
            raise StageClaimConflict("stale_stage_claim")
        if (
            active.stage_name != claim.stage_name
            or active.attempt != claim.attempt
            or active.input_digest != claim.input_digest
        ):
            raise StageClaimConflict("stage_claim_binding_mismatch")
        if now is not None and active.lease_expires_at <= now:
            raise StageClaimConflict("expired_stage_claim")
        return active

    def commit_stage(
        self,
        request: RuntimeRequest,
        claim: StageClaim,
        result_ref: StageResultRef,
        disposition: StageDisposition,
        error_code: str | None,
        now: datetime,
    ) -> _OperationRecord:
        with self._lock:
            key = self._key(request.workspace_id, request.operation_id)
            record = self._records[key]
            deadline_reached = now >= parse_utc_timestamp(record.deadline_at, "deadline_at")
            self._require_claim(
                record,
                claim,
                None if record.cancellation is not None or deadline_reached else now,
            )
            if result_ref.operation_id != request.operation_id:
                raise StageClaimConflict("stage_result_operation_mismatch")
            if result_ref.stage_name != claim.stage_name or result_ref.input_digest != claim.input_digest:
                raise StageClaimConflict("stage_result_claim_mismatch")
            # Cancellation/deadline wins over an uncommitted result. The result remains an
            # unreferenced immutable object and cannot become visible through status.
            if record.cancellation is not None:
                updated = replace(
                    record,
                    active_claim=None,
                    state=OperationState.CANCELLED,
                    error_code="cancelled",
                    revision=record.revision + 1,
                    updated_at=self._now_text(now),
                )
                self._records[key] = updated
                return updated
            if deadline_reached:
                updated = replace(
                    record,
                    active_claim=None,
                    state=OperationState.FAILED,
                    error_code="deadline_exceeded",
                    revision=record.revision + 1,
                    updated_at=self._now_text(now),
                )
                self._records[key] = updated
                return updated
            if any(item.stage_name == result_ref.stage_name for item in record.stage_result_refs):
                raise StageClaimConflict("duplicate_stage_commit")
            refs = (*record.stage_result_refs, result_ref)
            state = OperationState(result_ref.stage_name)
            next_index = record.stage_index + 1
            terminal_error = error_code
            if disposition is StageDisposition.REJECT:
                state = OperationState.REJECTED
                terminal_error = error_code or "stage_rejected"
            elif disposition is StageDisposition.ABSTAIN:
                state = OperationState.ABSTAINED
                terminal_error = error_code or "stage_abstained"
            elif disposition is StageDisposition.DEGRADE:
                state = OperationState.DEGRADED
                terminal_error = error_code or "stage_degraded"
            elif disposition is StageDisposition.COMPLETE:
                if next_index < len(record.pipeline_stages):
                    raise OperationConflict("early_stage_completion_denied")
                state = OperationState.COMPLETED
                terminal_error = None
            elif next_index >= len(record.pipeline_stages):
                state = OperationState.COMPLETED
                terminal_error = None
            updated = replace(
                record,
                active_claim=None,
                state=state,
                stage_index=next_index,
                stage_result_refs=refs,
                error_code=terminal_error,
                revision=record.revision + 1,
                updated_at=self._now_text(now),
            )
            self._records[key] = updated
            return updated

    def release_transient(
        self,
        request: RuntimeRequest,
        claim: StageClaim,
        error_code: str,
        now: datetime,
    ) -> _OperationRecord:
        with self._lock:
            key = self._key(request.workspace_id, request.operation_id)
            record = self._records[key]
            deadline_reached = now >= parse_utc_timestamp(record.deadline_at, "deadline_at")
            self._require_claim(
                record,
                claim,
                None if record.cancellation is not None or deadline_reached else now,
            )
            if record.cancellation is not None:
                updated = replace(
                    record, active_claim=None, state=OperationState.CANCELLED,
                    error_code="cancelled", revision=record.revision + 1,
                    updated_at=self._now_text(now),
                )
            elif deadline_reached:
                updated = replace(
                    record, active_claim=None, state=OperationState.FAILED,
                    error_code="deadline_exceeded", revision=record.revision + 1,
                    updated_at=self._now_text(now),
                )
            else:
                updated = replace(
                    record,
                    active_claim=None,
                    error_code=error_code,
                    revision=record.revision + 1,
                    updated_at=self._now_text(now),
                )
            self._records[key] = updated
            return updated

    def fail_stage(
        self,
        request: RuntimeRequest,
        claim: StageClaim,
        error_code: str,
        now: datetime,
        *,
        allow_expired: bool = False,
    ) -> _OperationRecord:
        with self._lock:
            key = self._key(request.workspace_id, request.operation_id)
            record = self._records[key]
            deadline_reached = now >= parse_utc_timestamp(record.deadline_at, "deadline_at")
            self._require_claim(
                record,
                claim,
                None if allow_expired or record.cancellation is not None or deadline_reached else now,
            )
            if record.cancellation is not None:
                state = OperationState.CANCELLED
                final_error = "cancelled"
            else:
                state = OperationState.FAILED
                final_error = "deadline_exceeded" if deadline_reached else error_code
            updated = replace(
                record,
                active_claim=None,
                state=state,
                error_code=final_error,
                revision=record.revision + 1,
                updated_at=self._now_text(now),
            )
            self._records[key] = updated
            return updated


@dataclass(frozen=True)
class _StoredStageResult:
    result_ref: StageResultRef
    result: RuntimeStageResult


@dataclass(frozen=True)
class _PersistedStageResult:
    result_ref: StageResultRef
    semantic_bytes: bytes


class StageResultStore(Protocol):
    def get(
        self,
        workspace_id: str,
        operation_id: str,
        stage_name: str,
        input_digest: str,
    ) -> _StoredStageResult | None: ...

    def put_once(
        self,
        *,
        workspace_id: str,
        operation_id: str,
        input_digest: str,
        result: RuntimeStageResult,
        created_at: str,
    ) -> _StoredStageResult: ...


class InMemoryStageResultStore:
    def __init__(self) -> None:
        self._results: dict[tuple[str, str, str, str], _PersistedStageResult] = {}
        self._lock = RLock()

    @staticmethod
    def _key(
        workspace_id: str,
        operation_id: str,
        stage_name: str,
        input_digest: str,
    ) -> tuple[str, str, str, str]:
        return workspace_id, operation_id, stage_name, input_digest

    @staticmethod
    def _restore(persisted: _PersistedStageResult) -> _StoredStageResult:
        semantic = json.loads(persisted.semantic_bytes.decode("utf-8"))
        result = RuntimeStageResult(
            stage_name=semantic["stage_name"],
            payload=semantic["payload"],
            disposition=StageDisposition(semantic["disposition"]),
            schema_id=semantic["schema_id"],
            provenance_refs=tuple(semantic["provenance_refs"]),
            error_code=semantic["error_code"],
        )
        return _StoredStageResult(persisted.result_ref, result)

    def get(
        self,
        workspace_id: str,
        operation_id: str,
        stage_name: str,
        input_digest: str,
    ) -> _StoredStageResult | None:
        with self._lock:
            persisted = self._results.get(self._key(workspace_id, operation_id, stage_name, input_digest))
            return None if persisted is None else self._restore(persisted)

    def put_once(
        self,
        *,
        workspace_id: str,
        operation_id: str,
        input_digest: str,
        result: RuntimeStageResult,
        created_at: str,
    ) -> _StoredStageResult:
        semantic = result.semantic_mapping()
        semantic_bytes = canonical_bytes(semantic)
        content_digest = sha256(_STAGE_CONTENT_DOMAIN + semantic_bytes).hexdigest()
        result_ref = StageResultRef.create(
            operation_id=operation_id,
            stage_name=result.stage_name,
            input_digest=input_digest,
            content_digest=content_digest,
            schema_id=result.schema_id,
            created_at=created_at,
            provenance_refs=result.provenance_refs,
        )
        key = self._key(workspace_id, operation_id, result.stage_name, input_digest)
        persisted = _PersistedStageResult(result_ref, semantic_bytes)
        with self._lock:
            existing = self._results.get(key)
            if existing is None:
                self._results[key] = persisted
                return self._restore(persisted)
            if existing.semantic_bytes != semantic_bytes:
                raise StageResultConflict("nondeterministic_stage_result")
            return self._restore(existing)


class RuntimeOrchestrator:
    def __init__(
        self,
        *,
        pipelines: Sequence[PipelineDefinition],
        handlers: Mapping[str, RuntimeStageHandler],
        operation_store: OperationStore | None = None,
        result_store: StageResultStore | None = None,
        clock: Clock | None = None,
        lease_duration: timedelta = timedelta(seconds=30),
        max_stage_attempts: int = 3,
    ) -> None:
        if lease_duration <= timedelta(0):
            raise InvalidContractValue("lease_duration must be positive")
        if not isinstance(max_stage_attempts, int) or isinstance(max_stage_attempts, bool) or max_stage_attempts <= 0:
            raise InvalidContractValue("max_stage_attempts must be a positive integer")
        pipeline_items = tuple(pipelines)
        pipeline_map = {item.request_type: item for item in pipeline_items}
        if len(pipeline_map) != len(pipeline_items):
            raise InvalidContractValue("request_type must map to exactly one pipeline")
        for pipeline in pipeline_map.values():
            for stage in pipeline.stages:
                handler = handlers.get(stage)
                if handler is None or getattr(handler, "stage_name", None) != stage:
                    raise InvalidContractValue(f"missing or mismatched handler for stage {stage}")
        self.pipelines = pipeline_map
        self.handlers = dict(handlers)
        self.operation_store = operation_store or InMemoryOperationStore()
        self.result_store = result_store or InMemoryStageResultStore()
        self.clock = clock or SystemClock()
        self.lease_duration = lease_duration
        self.max_stage_attempts = max_stage_attempts

    def _now(self) -> datetime:
        value = self.clock.now()
        if value.tzinfo is None:
            raise RuntimeOrchestrationError("Clock.now() must be timezone-aware")
        return value.astimezone(timezone.utc).replace(microsecond=0)

    @staticmethod
    def _stage_input_digest(request: RuntimeRequest, stage_name: str, refs: tuple[StageResultRef, ...]) -> str:
        return sha256(
            _STAGE_INPUT_DOMAIN
            + canonical_bytes(
                {
                    "operation_id": request.operation_id,
                    "stage_name": stage_name,
                    "request_identity_digest": request.identity_digest(),
                    "previous_result_ids": [item.result_id for item in refs],
                }
            )
        ).hexdigest()

    def _status(self, record: _OperationRecord) -> RuntimeStatus:
        current_stage = None
        if record.state not in TERMINAL_STATES and record.stage_index < len(record.pipeline_stages):
            current_stage = record.pipeline_stages[record.stage_index]
        if current_stage is not None:
            attempt = record.attempt_for(current_stage)
        elif record.pipeline_stages:
            last_index = min(record.stage_index, len(record.pipeline_stages) - 1)
            attempt = record.attempt_for(record.pipeline_stages[last_index])
        else:  # Defensive only; PipelineDefinition forbids empty pipelines.
            attempt = 0
        return RuntimeStatus.from_mapping(
            {
                "runtime_status_version": RUNTIME_STATUS_VERSION,
                "operation_id": record.operation_id,
                "workspace_id": record.workspace_id,
                "state": record.state.value,
                "current_stage": current_stage,
                "attempt": str(attempt),
                "revision": str(record.revision),
                "deadline_at": record.deadline_at,
                "cancellation_id": None if record.cancellation is None else record.cancellation.cancellation_id,
                "stage_result_refs": [item.to_mapping() for item in record.stage_result_refs],
                "updated_at": record.updated_at,
                "error_code": record.error_code,
            }
        )

    def _response(
        self,
        request: RuntimeRequest,
        record: _OperationRecord,
        *,
        forced_status: RuntimeResponseStatus | None = None,
        error_code: str | None = None,
    ) -> RuntimeResponse:
        # A concurrent worker may finish after the caller loses its lease.  Never
        # force a retry status on an already terminal record: that combination is
        # semantically impossible and would itself violate RuntimeResponse.
        status = (
            response_status_for_state(record.state)
            if record.state in TERMINAL_STATES
            else forced_status or response_status_for_state(record.state)
        )
        refs = record.stage_result_refs
        result_ref = (
            refs[-1]
            if refs
            and status
            in {
                RuntimeResponseStatus.COMPLETED,
                RuntimeResponseStatus.REJECTED,
                RuntimeResponseStatus.ABSTAINED,
                RuntimeResponseStatus.DEGRADED,
            }
            else None
        )
        effective_error = error_code if error_code is not None else record.error_code
        return RuntimeResponse.from_mapping(
            {
                "runtime_response_version": RUNTIME_RESPONSE_VERSION,
                "request_id": request.request_id,
                "operation_id": request.operation_id,
                "workspace_id": request.workspace_id,
                "status": status.value,
                "state": record.state.value,
                "requested_generation_id": request.requested_generation_id,
                "stage_result_refs": [item.to_mapping() for item in refs],
                "result_ref": None if result_ref is None else result_ref.to_mapping(),
                "retryable": status is RuntimeResponseStatus.RETRY_LATER,
                "error_code": effective_error,
                "updated_at": record.updated_at,
            }
        )

    def _claim_lost_response(
        self, request: RuntimeRequest, record: _OperationRecord
    ) -> RuntimeResponse:
        current = self.operation_store.get(request.workspace_id, request.operation_id) or record
        if current.state in TERMINAL_STATES:
            return self._response(request, current)
        return self._response(
            request,
            current,
            forced_status=RuntimeResponseStatus.RETRY_LATER,
            error_code="stage_claim_lost",
        )

    def run(self, request: RuntimeRequest) -> RuntimeResponse:
        # Re-parse at the trust boundary so post-construction mutation of nested
        # payloads cannot change the handler input behind a stale operation_id.
        request = RuntimeRequest.from_mapping(request.to_mapping())
        pipeline = self.pipelines.get(request.request_type)
        if pipeline is None:
            now = format_utc_timestamp(self._now())
            # The request remains valid, but an unknown route must not create operation state.
            return RuntimeResponse.from_mapping(
                {
                    "runtime_response_version": RUNTIME_RESPONSE_VERSION,
                    "request_id": request.request_id,
                    "operation_id": request.operation_id,
                    "workspace_id": request.workspace_id,
                    "status": RuntimeResponseStatus.REJECTED.value,
                    "state": OperationState.REJECTED.value,
                    "requested_generation_id": request.requested_generation_id,
                    "stage_result_refs": [],
                    "result_ref": None,
                    "retryable": False,
                    "error_code": "unknown_request_type",
                    "updated_at": now,
                }
            )
        try:
            record = self.operation_store.register(request, pipeline, self._now())
        except OperationConflict as exc:
            now = format_utc_timestamp(self._now())
            return RuntimeResponse.from_mapping(
                {
                    "runtime_response_version": RUNTIME_RESPONSE_VERSION,
                    "request_id": request.request_id,
                    "operation_id": request.operation_id,
                    "workspace_id": request.workspace_id,
                    "status": RuntimeResponseStatus.REJECTED.value,
                    "state": OperationState.REJECTED.value,
                    "requested_generation_id": request.requested_generation_id,
                    "stage_result_refs": [],
                    "result_ref": None,
                    "retryable": False,
                    "error_code": str(exc),
                    "updated_at": now,
                }
            )

        # At most one successful transition per configured stage. The loop cannot be
        # extended by handler output and therefore cannot become unbounded.
        for _ in range(len(pipeline.stages) + 2):
            record = self.operation_store.get(request.workspace_id, request.operation_id) or record
            if record.state in TERMINAL_STATES:
                return self._response(request, record)
            if record.stage_index >= len(record.pipeline_stages):
                return self._response(
                    request,
                    record,
                    forced_status=RuntimeResponseStatus.RETRY_LATER,
                    error_code="operation_state_inconsistent",
                )
            stage_name = record.pipeline_stages[record.stage_index]
            input_digest = self._stage_input_digest(request, stage_name, record.stage_result_refs)
            existing = self.result_store.get(
                request.workspace_id,
                request.operation_id,
                stage_name,
                input_digest,
            )
            decision = self.operation_store.claim_next(
                request,
                request_id=request.request_id,
                now=self._now(),
                lease_duration=self.lease_duration,
                input_digest=input_digest,
                max_attempts=self.max_stage_attempts,
                allow_exhausted=existing is not None,
            )
            record = decision.record
            if decision.outcome == "terminal":
                return self._response(request, record)
            if decision.outcome == "busy" or decision.claim is None:
                return self._response(
                    request,
                    record,
                    forced_status=RuntimeResponseStatus.RETRY_LATER,
                    error_code="operation_stage_busy",
                )
            claim = decision.claim
            if existing is None:
                context = StageExecutionContext(
                    request=RuntimeOperationInput.from_request(request),
                    stage_name=claim.stage_name,
                    previous_result_refs=record.stage_result_refs,
                    input_digest=claim.input_digest,
                    attempt=str(claim.attempt),
                    _clock=self.clock,
                    _cancelled=lambda: self.operation_store.is_cancelled(
                        request.workspace_id, request.operation_id
                    ),
                )
                try:
                    context.checkpoint()
                    result = self.handlers[claim.stage_name].execute(context)
                    context.checkpoint()
                    if not isinstance(result, RuntimeStageResult):
                        raise FatalStageError("invalid_stage_result_type")
                    # Reconstruct from canonical semantic values before persistence;
                    # this detaches caller-owned mutable dictionaries and reapplies
                    # all current result invariants.
                    result = RuntimeStageResult(
                        stage_name=result.stage_name,
                        payload=result.payload,
                        disposition=result.disposition,
                        schema_id=result.schema_id,
                        provenance_refs=result.provenance_refs,
                        error_code=result.error_code,
                    )
                    if result.stage_name != claim.stage_name:
                        raise FatalStageError("stage_result_mismatch")
                    if (
                        result.disposition is StageDisposition.COMPLETE
                        and record.stage_index + 1 < len(record.pipeline_stages)
                    ):
                        raise FatalStageError("early_stage_completion_denied")
                    existing = self.result_store.put_once(
                        workspace_id=request.workspace_id,
                        operation_id=request.operation_id,
                        input_digest=claim.input_digest,
                        result=result,
                        created_at=format_utc_timestamp(self._now()),
                    )
                except OperationCancelled:
                    record = self.operation_store.get(request.workspace_id, request.operation_id) or record
                    signal = record.cancellation
                    if signal is None:
                        signal = CancellationSignal.create(
                            workspace_id=request.workspace_id,
                            actor_id=request.actor_id,
                            operation_id=request.operation_id,
                            requested_at=format_utc_timestamp(self._now()),
                            reason_code="cooperative_cancel",
                        )
                        self.operation_store.request_cancel(signal, self._now())
                    # Commit path applies cancellation precedence without referencing output.
                    placeholder = StageResultRef.create(
                        operation_id=request.operation_id,
                        stage_name=claim.stage_name,
                        input_digest=claim.input_digest,
                        content_digest=sha256(b"cancelled").hexdigest(),
                        schema_id="phase4-cancelled-stage-v1",
                        created_at=format_utc_timestamp(self._now()),
                        provenance_refs=(),
                    )
                    record = self.operation_store.commit_stage(
                        request,
                        claim,
                        placeholder,
                        StageDisposition.CONTINUE,
                        "cancelled",
                        self._now(),
                    )
                    return self._response(request, record)
                except OperationDeadlineExceeded:
                    record = self.operation_store.fail_stage(
                        request, claim, "deadline_exceeded", self._now(), allow_expired=True
                    )
                    return self._response(request, record)
                except TransientStageError as exc:
                    try:
                        if claim.attempt >= self.max_stage_attempts:
                            record = self.operation_store.fail_stage(
                                request, claim, "retry_budget_exhausted", self._now()
                            )
                        else:
                            record = self.operation_store.release_transient(
                                request, claim, exc.error_code, self._now()
                            )
                    except StageClaimConflict:
                        return self._claim_lost_response(request, record)
                    if record.state in TERMINAL_STATES:
                        return self._response(request, record)
                    return self._response(
                        request,
                        record,
                        forced_status=RuntimeResponseStatus.RETRY_LATER,
                        error_code=exc.error_code,
                    )
                except FatalStageError as exc:
                    try:
                        record = self.operation_store.fail_stage(
                            request, claim, exc.error_code, self._now()
                        )
                    except StageClaimConflict:
                        return self._claim_lost_response(request, record)
                    return self._response(request, record)
                except StageResultConflict:
                    try:
                        record = self.operation_store.fail_stage(
                            request, claim, "nondeterministic_stage_result", self._now()
                        )
                    except StageClaimConflict:
                        return self._claim_lost_response(request, record)
                    return self._response(request, record)
                except Exception:
                    try:
                        record = self.operation_store.fail_stage(
                            request, claim, "stage_unhandled_failure", self._now()
                        )
                    except StageClaimConflict:
                        return self._claim_lost_response(request, record)
                    return self._response(request, record)
            try:
                record = self.operation_store.commit_stage(
                    request,
                    claim,
                    existing.result_ref,
                    existing.result.disposition,
                    existing.result.error_code,
                    self._now(),
                )
            except StageClaimConflict:
                record = self.operation_store.get(request.workspace_id, request.operation_id) or record
                return self._claim_lost_response(request, record)
            if record.state in TERMINAL_STATES:
                return self._response(request, record)
        record = self.operation_store.get(request.workspace_id, request.operation_id) or record
        return self._response(
            request,
            record,
            forced_status=RuntimeResponseStatus.RETRY_LATER,
            error_code="orchestrator_transition_limit",
        )

    def cancel(self, signal: CancellationSignal) -> RuntimeStatus | None:
        signal = CancellationSignal.from_mapping(signal.to_mapping())
        record = self.operation_store.request_cancel(signal, self._now())
        return None if record is None else self._status(record)

    def status(self, workspace_id: str, operation_id: str) -> RuntimeStatus | None:
        record = self.operation_store.refresh(workspace_id, operation_id, self._now())
        return None if record is None else self._status(record)


__all__ = [
    "RuntimeOrchestrationError",
    "OperationConflict",
    "StageClaimConflict",
    "StageResultConflict",
    "TransientStageError",
    "FatalStageError",
    "OperationCancelled",
    "OperationDeadlineExceeded",
    "Clock",
    "SystemClock",
    "RuntimeOperationInput",
    "RuntimeStageResult",
    "RuntimeStageHandler",
    "PipelineDefinition",
    "StageExecutionContext",
    "StageClaim",
    "ClaimDecision",
    "OperationStore",
    "InMemoryOperationStore",
    "StageResultStore",
    "InMemoryStageResultStore",
    "RuntimeOrchestrator",
]
