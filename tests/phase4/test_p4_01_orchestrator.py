from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from threading import Event, Lock, Thread

import pytest

from wiki_spike.memory_runtime.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_runtime.contracts import (
    CANCELLATION_SIGNAL_VERSION,
    RUNTIME_REQUEST_VERSION,
    RUNTIME_RESPONSE_VERSION,
    RUNTIME_STATUS_VERSION,
    STAGE_RESULT_REF_VERSION,
    CancellationSignal,
    OperationState,
    RuntimeRequest,
    RuntimeResponse,
    RuntimeResponseStatus,
    RuntimeStatus,
    StageDisposition,
    StageResultRef,
)
from wiki_spike.memory_runtime.orchestrator import (
    FatalStageError,
    InMemoryOperationStore,
    InMemoryStageResultStore,
    OperationConflict,
    PipelineDefinition,
    RuntimeOrchestrationError,
    RuntimeOrchestrator,
    RuntimeStageResult,
    StageClaimConflict,
    StageExecutionContext,
    StageResultConflict,
    TransientStageError,
)

UTC = timezone.utc
BASE_TIME = datetime(2026, 7, 22, 0, 0, 0, tzinfo=UTC)


@dataclass
class ManualClock:
    current: datetime = BASE_TIME

    def __post_init__(self) -> None:
        self._lock = Lock()

    def now(self) -> datetime:
        with self._lock:
            return self.current

    def set(self, value: datetime) -> None:
        with self._lock:
            self.current = value

    def advance(self, **kwargs: int) -> None:
        with self._lock:
            self.current += timedelta(**kwargs)


class Handler:
    def __init__(self, stage_name: str, actions=None) -> None:
        self.stage_name = stage_name
        self.actions = list(actions or [])
        self.calls: list[StageExecutionContext] = []

    def execute(self, context: StageExecutionContext) -> RuntimeStageResult:
        self.calls.append(context)
        action = self.actions.pop(0) if self.actions else None
        if isinstance(action, BaseException):
            raise action
        if callable(action):
            return action(context)
        if isinstance(action, RuntimeStageResult):
            return action
        return RuntimeStageResult(
            stage_name=self.stage_name,
            payload={"stage": self.stage_name, "attempt": context.attempt},
            provenance_refs=(f"prov:{self.stage_name}",),
        )


class BlockingHandler(Handler):
    def __init__(self, stage_name: str) -> None:
        super().__init__(stage_name)
        self.started = Event()
        self.release = Event()

    def execute(self, context: StageExecutionContext) -> RuntimeStageResult:
        self.calls.append(context)
        self.started.set()
        assert self.release.wait(timeout=10)
        context.checkpoint()
        return RuntimeStageResult(stage_name=self.stage_name, payload={"ok": "yes"})


def request(
    *,
    request_id: str = "req-1",
    idempotency_key: str = "idem-1",
    request_type: str = "runtime.demo",
    received_at: str = "2026-07-22T00:00:00Z",
    deadline_at: str = "2026-07-22T00:10:00Z",
    payload=None,
    workspace_id: str = "ws-1",
    actor_id: str = "user-1",
    requested_generation_id: str | None = "gen-1",
) -> RuntimeRequest:
    return RuntimeRequest.create(
        request_id=request_id,
        idempotency_key=idempotency_key,
        workspace_id=workspace_id,
        actor_id=actor_id,
        request_type=request_type,
        received_at=received_at,
        deadline_at=deadline_at,
        requested_generation_id=requested_generation_id,
        payload={"topic": "alpha"} if payload is None else payload,
    )


def orchestrator(
    *stages: str,
    handlers=None,
    clock: ManualClock | None = None,
    operation_store=None,
    result_store=None,
) -> RuntimeOrchestrator:
    stages = stages or ("planned", "retrieved", "generated", "verified", "proposed")
    handlers = handlers or {name: Handler(name) for name in stages}
    return RuntimeOrchestrator(
        pipelines=(PipelineDefinition("pipeline-demo-v1", "runtime.demo", tuple(stages)),),
        handlers=handlers,
        operation_store=operation_store,
        result_store=result_store,
        clock=clock or ManualClock(),
        lease_duration=timedelta(seconds=30),
    )


def stage_ref(operation_id: str, stage_name: str = "planned", input_digest: str = "1" * 64):
    return StageResultRef.create(
        operation_id=operation_id,
        stage_name=stage_name,
        input_digest=input_digest,
        content_digest="2" * 64,
        schema_id="phase4-test-result-v1",
        created_at="2026-07-22T00:00:01Z",
        provenance_refs=("prov:a",),
    )


# --- Versioned contracts -------------------------------------------------


def test_operation_id_is_stable_across_delivery_request_id_and_received_time():
    first = request(request_id="delivery-a", received_at="2026-07-22T00:00:00Z")
    second = request(request_id="delivery-b", received_at="2026-07-22T00:00:05Z")
    assert first.operation_id == second.operation_id
    assert first.canonical_bytes() != second.canonical_bytes()


def test_semantic_payload_change_changes_operation_id():
    assert request(payload={"topic": "alpha"}).operation_id != request(payload={"topic": "beta"}).operation_id


def test_tampered_operation_id_is_rejected():
    value = request().to_mapping()
    value["operation_id"] = "0" * 64
    with pytest.raises(InvalidContractValue, match="operation_id"):
        RuntimeRequest.from_mapping(value)


def test_runtime_request_rejects_unknown_version_field_and_raw_number():
    value = request().to_mapping()
    value["runtime_request_version"] = "phase4-runtime-request-v999"
    with pytest.raises(UnsupportedContractVersion):
        RuntimeRequest.from_mapping(value)
    value = request().to_mapping()
    value["extra"] = "x"
    with pytest.raises(UnknownContractField):
        RuntimeRequest.from_mapping(value)
    value = request().to_mapping()
    value["payload"] = {"raw": 1}
    with pytest.raises(InvalidContractValue, match="raw numbers"):
        RuntimeRequest.from_mapping(value)


def test_runtime_request_requires_canonical_utc_deadline_after_received():
    with pytest.raises(InvalidContractValue, match="canonical UTC"):
        request(received_at="2026-07-22T09:00:00+09:00")
    with pytest.raises(InvalidContractValue, match="after received"):
        request(deadline_at="2026-07-22T00:00:00Z")


def test_cancellation_and_stage_ref_are_content_bound():
    req = request()
    signal = CancellationSignal.create(
        workspace_id=req.workspace_id,
        actor_id=req.actor_id,
        operation_id=req.operation_id,
        requested_at="2026-07-22T00:00:01Z",
        reason_code="user_requested",
    )
    value = signal.to_mapping()
    value["reason_code"] = "changed"
    with pytest.raises(InvalidContractValue, match="cancellation_id"):
        CancellationSignal.from_mapping(value)

    ref = stage_ref(req.operation_id)
    value = ref.to_mapping()
    value["schema_id"] = "changed"
    with pytest.raises(InvalidContractValue, match="result_id"):
        StageResultRef.from_mapping(value)


def test_stage_ref_normalizes_provenance_and_requires_supported_stage():
    req = request()
    ref = StageResultRef.create(
        operation_id=req.operation_id,
        stage_name="planned",
        input_digest="1" * 64,
        content_digest="2" * 64,
        schema_id="schema-v1",
        created_at="2026-07-22T00:00:01Z",
        provenance_refs=("z", "a", "z"),
    )
    assert ref.provenance_refs == ("a", "z")
    with pytest.raises(InvalidContractValue, match="supported Runtime stage"):
        StageResultRef.create(
            operation_id=req.operation_id,
            stage_name="invented",
            input_digest="1" * 64,
            content_digest="2" * 64,
            schema_id="schema-v1",
            created_at="2026-07-22T00:00:01Z",
            provenance_refs=(),
        )


def test_response_requires_result_ref_membership_and_boolean_retryable():
    req = request()
    ref = stage_ref(req.operation_id)
    base = {
        "runtime_response_version": RUNTIME_RESPONSE_VERSION,
        "request_id": req.request_id,
        "operation_id": req.operation_id,
        "workspace_id": req.workspace_id,
        "status": "completed",
        "state": "completed",
        "requested_generation_id": req.requested_generation_id,
        "stage_result_refs": [],
        "result_ref": ref.to_mapping(),
        "retryable": False,
        "error_code": None,
        "updated_at": "2026-07-22T00:00:01Z",
    }
    with pytest.raises(InvalidContractValue, match="one of stage_result_refs"):
        RuntimeResponse.from_mapping(base)
    base["result_ref"] = None
    base["retryable"] = "false"
    with pytest.raises(InvalidContractValue, match="boolean"):
        RuntimeResponse.from_mapping(base)


def test_status_rejects_duplicate_stage_refs_and_operation_mismatch():
    req = request()
    ref = stage_ref(req.operation_id)
    base = {
        "runtime_status_version": RUNTIME_STATUS_VERSION,
        "operation_id": req.operation_id,
        "workspace_id": req.workspace_id,
        "state": "completed",
        "current_stage": None,
        "attempt": "0",
        "revision": "1",
        "deadline_at": req.deadline_at,
        "cancellation_id": None,
        "stage_result_refs": [ref.to_mapping(), ref.to_mapping()],
        "updated_at": "2026-07-22T00:00:01Z",
        "error_code": None,
    }
    with pytest.raises(InvalidContractValue, match="duplicate stages"):
        RuntimeStatus.from_mapping(base)
    base["stage_result_refs"] = [{**ref.to_mapping(), "operation_id": "3" * 64}]
    with pytest.raises(InvalidContractValue):
        RuntimeStatus.from_mapping(base)


# --- State machine, retries, cancellation, and fencing -------------------


def test_happy_path_is_ordered_and_returns_metadata_refs_only():
    stages = ("planned", "retrieved", "generated", "verified", "proposed")
    handlers = {name: Handler(name) for name in stages}
    runtime = orchestrator(*stages, handlers=handlers)
    result = runtime.run(request())
    assert result.status == "completed"
    assert result.state == "completed"
    assert [ref.stage_name for ref in result.stage_result_refs] == list(stages)
    assert result.result_ref == result.stage_result_refs[-1]
    assert all(len(handler.calls) == 1 for handler in handlers.values())
    serialized = result.canonical_bytes().decode("utf-8")
    assert '"payload"' not in serialized
    assert "alpha" not in serialized


def test_terminal_replay_does_not_rerun_handlers_and_uses_new_request_id():
    handler = Handler("planned")
    runtime = orchestrator("planned", handlers={"planned": handler})
    first = runtime.run(request(request_id="delivery-a"))
    second = runtime.run(request(request_id="delivery-b", received_at="2026-07-22T00:00:05Z"))
    assert first.operation_id == second.operation_id
    assert second.request_id == "delivery-b"
    assert second.result_ref == first.result_ref
    assert len(handler.calls) == 1


def test_same_idempotency_key_with_different_payload_is_rejected_without_handler_call():
    handler = Handler("planned")
    runtime = orchestrator("planned", handlers={"planned": handler})
    assert runtime.run(request(payload={"topic": "alpha"})).status == "completed"
    result = runtime.run(request(request_id="req-2", payload={"topic": "beta"}))
    assert result.status == "rejected"
    assert result.error_code == "idempotency_payload_mismatch"
    assert len(handler.calls) == 1


def test_transient_failure_retries_same_stage_without_repeating_completed_stages():
    planned = Handler("planned", [TransientStageError("provider_503"), None])
    retrieved = Handler("retrieved")
    runtime = orchestrator(
        "planned", "retrieved", handlers={"planned": planned, "retrieved": retrieved}
    )
    first = runtime.run(request(request_id="req-1"))
    assert first.status == "retry_later"
    assert first.error_code == "provider_503"
    second = runtime.run(request(request_id="req-2", received_at="2026-07-22T00:00:05Z"))
    assert second.status == "completed"
    assert len(planned.calls) == 2
    assert len(retrieved.calls) == 1
    assert [ref.stage_name for ref in second.stage_result_refs] == ["planned", "retrieved"]


def test_preexisting_content_bound_stage_result_recovers_without_handler_execution():
    req = request()
    results = InMemoryStageResultStore()
    input_digest = RuntimeOrchestrator._stage_input_digest(req, "planned", ())
    results.put_once(
        workspace_id=req.workspace_id,
        operation_id=req.operation_id,
        input_digest=input_digest,
        result=RuntimeStageResult("planned", {"recovered": "yes"}),
        created_at="2026-07-22T00:00:01Z",
    )
    handler = Handler("planned")
    runtime = orchestrator("planned", handlers={"planned": handler}, result_store=results)
    response = runtime.run(req)
    assert response.status == "completed"
    assert len(handler.calls) == 0


def test_cancellation_before_stage_is_terminal_and_handler_is_not_called():
    clock = ManualClock()
    store = InMemoryOperationStore()
    handler = Handler("planned")
    runtime = orchestrator("planned", handlers={"planned": handler}, clock=clock, operation_store=store)
    req = request()
    pipeline = runtime.pipelines[req.request_type]
    store.register(req, pipeline, clock.now())
    signal = CancellationSignal.create(
        workspace_id=req.workspace_id,
        actor_id=req.actor_id,
        operation_id=req.operation_id,
        requested_at="2026-07-22T00:00:01Z",
        reason_code="user_requested",
    )
    status = runtime.cancel(signal)
    assert status is not None and status.state == "cancelled"
    response = runtime.run(request(request_id="req-2", received_at="2026-07-22T00:00:02Z"))
    assert response.status == "cancelled"
    assert len(handler.calls) == 0


def test_first_cancellation_is_immutable_and_duplicate_is_idempotent():
    clock = ManualClock()
    store = InMemoryOperationStore()
    runtime = orchestrator("planned", operation_store=store, clock=clock)
    req = request()
    store.register(req, runtime.pipelines[req.request_type], clock.now())
    first = CancellationSignal.create(
        workspace_id=req.workspace_id,
        actor_id=req.actor_id,
        operation_id=req.operation_id,
        requested_at="2026-07-22T00:00:01Z",
        reason_code="first",
    )
    other = CancellationSignal.create(
        workspace_id=req.workspace_id,
        actor_id=req.actor_id,
        operation_id=req.operation_id,
        requested_at="2026-07-22T00:00:02Z",
        reason_code="rewrite",
    )
    assert runtime.cancel(first).cancellation_id == first.cancellation_id
    assert runtime.cancel(first).cancellation_id == first.cancellation_id
    assert runtime.cancel(other).cancellation_id == first.cancellation_id


def test_cooperative_cancellation_during_stage_discards_uncommitted_output():
    clock = ManualClock()
    holder = {}

    def action(context: StageExecutionContext):
        signal = CancellationSignal.create(
            workspace_id=context.request.workspace_id,
            actor_id=context.request.actor_id,
            operation_id=context.request.operation_id,
            requested_at="2026-07-22T00:00:01Z",
            reason_code="during_stage",
        )
        holder["runtime"].cancel(signal)
        context.checkpoint()
        raise AssertionError("unreachable")

    handler = Handler("planned", [action])
    runtime = orchestrator("planned", handlers={"planned": handler}, clock=clock)
    holder["runtime"] = runtime
    response = runtime.run(request())
    assert response.status == "cancelled"
    assert response.stage_result_refs == ()
    assert response.result_ref is None


def test_deadline_before_claim_and_deadline_during_handler_do_not_publish_result():
    clock = ManualClock(BASE_TIME + timedelta(minutes=10))
    handler = Handler("planned")
    runtime = orchestrator("planned", handlers={"planned": handler}, clock=clock)
    expired = runtime.run(request())
    assert expired.status == "failed"
    assert expired.error_code == "deadline_exceeded"
    assert len(handler.calls) == 0

    clock = ManualClock(BASE_TIME)

    def advance(context: StageExecutionContext):
        clock.advance(minutes=11)
        return RuntimeStageResult(context.stage_name, {"late": "result"})

    late_handler = Handler("planned", [advance])
    runtime = orchestrator("planned", handlers={"planned": late_handler}, clock=clock)
    late = runtime.run(request())
    assert late.status == "failed"
    assert late.error_code == "deadline_exceeded"
    assert late.stage_result_refs == ()


@pytest.mark.parametrize(
    ("disposition", "expected_status", "expected_state"),
    [
        (StageDisposition.REJECT, "rejected", "rejected"),
        (StageDisposition.ABSTAIN, "abstained", "abstained"),
        (StageDisposition.DEGRADE, "degraded", "degraded"),
        (StageDisposition.COMPLETE, "completed", "completed"),
    ],
)
def test_terminal_stage_dispositions(disposition, expected_status, expected_state):
    handler = Handler(
        "planned",
        [RuntimeStageResult("planned", {"decision": disposition.value}, disposition=disposition)],
    )
    response = orchestrator("planned", handlers={"planned": handler}).run(request())
    assert response.status == expected_status
    assert response.state == expected_state


def test_fatal_and_unhandled_stage_failures_are_terminal_and_not_retried():
    for action, code in [(FatalStageError("bad_schema"), "bad_schema"), (RuntimeError("boom"), "stage_unhandled_failure")]:
        handler = Handler("planned", [action])
        runtime = orchestrator("planned", handlers={"planned": handler})
        first = runtime.run(request(idempotency_key=code))
        second = runtime.run(request(request_id="req-2", idempotency_key=code, received_at="2026-07-22T00:00:05Z"))
        assert first.status == "failed" and first.error_code == code
        assert second.status == "failed" and len(handler.calls) == 1


def test_wrong_stage_result_fails_terminally():
    handler = Handler("planned", [RuntimeStageResult("retrieved", {"bad": "stage"})])
    response = orchestrator("planned", handlers={"planned": handler}).run(request())
    assert response.status == "failed"
    assert response.error_code == "stage_result_mismatch"


def test_invalid_pipeline_and_missing_handler_fail_closed():
    with pytest.raises(InvalidContractValue, match="begin with planned"):
        PipelineDefinition("p", "x", ("retrieved",))
    with pytest.raises(InvalidContractValue, match="strictly ordered"):
        PipelineDefinition("p", "x", ("planned", "planned"))
    with pytest.raises(InvalidContractValue, match="requires a later verified"):
        PipelineDefinition("p", "x", ("planned", "generated"))
    with pytest.raises(InvalidContractValue, match="missing or mismatched handler"):
        RuntimeOrchestrator(
            pipelines=(PipelineDefinition("p", "x", ("planned",)),),
            handlers={},
            clock=ManualClock(),
        )


def test_stage_result_store_is_put_once_and_detects_nondeterminism():
    store = InMemoryStageResultStore()
    req = request()
    kwargs = {
        "workspace_id": req.workspace_id,
        "operation_id": req.operation_id,
        "input_digest": "1" * 64,
        "created_at": "2026-07-22T00:00:01Z",
    }
    first = store.put_once(result=RuntimeStageResult("planned", {"value": "a"}), **kwargs)
    second = store.put_once(result=RuntimeStageResult("planned", {"value": "a"}), **kwargs)
    assert first == second
    with pytest.raises(StageResultConflict, match="nondeterministic"):
        store.put_once(result=RuntimeStageResult("planned", {"value": "b"}), **kwargs)


def test_stale_stage_claim_cannot_commit_after_fencing_takeover():
    clock = ManualClock()
    store = InMemoryOperationStore()
    req = request()
    pipeline = PipelineDefinition("p", req.request_type, ("planned",))
    store.register(req, pipeline, clock.now())
    digest = "1" * 64
    first = store.claim_next(req, request_id="r1", now=clock.now(), lease_duration=timedelta(seconds=1), input_digest=digest)
    clock.advance(seconds=2)
    second = store.claim_next(req, request_id="r2", now=clock.now(), lease_duration=timedelta(seconds=1), input_digest=digest)
    assert first.claim is not None and second.claim is not None
    with pytest.raises(StageClaimConflict, match="stale_stage_claim"):
        store.commit_stage(
            req,
            first.claim,
            stage_ref(req.operation_id, input_digest=digest),
            StageDisposition.CONTINUE,
            None,
            clock.now(),
        )


def test_concurrent_delivery_observes_busy_claim_and_handler_runs_once():
    blocker = BlockingHandler("planned")
    runtime = orchestrator("planned", handlers={"planned": blocker})
    first_response = {}

    def run_first():
        first_response["value"] = runtime.run(request(request_id="req-a"))

    thread = Thread(target=run_first)
    thread.start()
    assert blocker.started.wait(timeout=10)
    second = runtime.run(request(request_id="req-b", received_at="2026-07-22T00:00:05Z"))
    assert second.status == "retry_later"
    assert second.error_code == "operation_stage_busy"
    blocker.release.set()
    thread.join(timeout=10)
    assert first_response["value"].status == "completed"
    assert len(blocker.calls) == 1


def test_unknown_request_type_and_missing_status_do_not_create_state():
    runtime = orchestrator("planned")
    req = request(request_type="unknown.route")
    response = runtime.run(req)
    assert response.status == "rejected"
    assert response.error_code == "unknown_request_type"
    assert runtime.status(req.workspace_id, req.operation_id) is None
    assert runtime.status("ws-x", "0" * 64) is None


def test_naive_clock_and_raw_stage_payload_fail_closed():
    class NaiveClock:
        def now(self):
            return datetime(2026, 7, 22)

    runtime = orchestrator("planned", clock=NaiveClock())
    with pytest.raises(RuntimeOrchestrationError, match="timezone-aware"):
        runtime.run(request())
    with pytest.raises(InvalidContractValue, match="raw numbers"):
        RuntimeStageResult("planned", {"raw": 1})


def test_contract_version_constants_are_distinct_and_adversarial_document_is_exact():
    assert len({
        RUNTIME_REQUEST_VERSION,
        RUNTIME_RESPONSE_VERSION,
        RUNTIME_STATUS_VERSION,
        STAGE_RESULT_REF_VERSION,
        CANCELLATION_SIGNAL_VERSION,
    }) == 5
    root = Path(__file__).resolve().parents[2]
    doc = root / "docs/adversarial/P4-01_ADVERSARIAL_VALIDATION_20R_KR.md"
    if doc.exists():
        rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", doc.read_text("utf-8"), re.M)]
        assert rounds == list(range(1, 21))


def test_response_status_state_and_retryability_are_consistent():
    req = request()
    ref = stage_ref(req.operation_id)
    base = {
        "runtime_response_version": RUNTIME_RESPONSE_VERSION,
        "request_id": req.request_id,
        "operation_id": req.operation_id,
        "workspace_id": req.workspace_id,
        "status": "completed",
        "state": "failed",
        "requested_generation_id": req.requested_generation_id,
        "stage_result_refs": [ref.to_mapping()],
        "result_ref": ref.to_mapping(),
        "retryable": False,
        "error_code": None,
        "updated_at": "2026-07-22T00:00:01Z",
    }
    with pytest.raises(InvalidContractValue, match="status/state mismatch"):
        RuntimeResponse.from_mapping(base)
    base.update(status="retry_later", state="planned", result_ref=None, retryable=False, error_code="busy")
    with pytest.raises(InvalidContractValue, match="must be retryable"):
        RuntimeResponse.from_mapping(base)


def test_late_cancellation_does_not_rewrite_terminal_operation():
    runtime = orchestrator("planned")
    req = request()
    completed = runtime.run(req)
    assert completed.status == "completed"
    before = runtime.status(req.workspace_id, req.operation_id)
    signal = CancellationSignal.create(
        workspace_id=req.workspace_id,
        actor_id=req.actor_id,
        operation_id=req.operation_id,
        requested_at="2026-07-22T00:00:02Z",
        reason_code="too_late",
    )
    after = runtime.cancel(signal)
    assert after == before
    assert after is not None and after.cancellation_id is None


def test_expired_claim_cannot_commit_without_takeover():
    clock = ManualClock()
    store = InMemoryOperationStore()
    req = request()
    pipeline = PipelineDefinition("p", req.request_type, ("planned",))
    store.register(req, pipeline, clock.now())
    claim = store.claim_next(
        req,
        request_id=req.request_id,
        now=clock.now(),
        lease_duration=timedelta(seconds=1),
        input_digest="1" * 64,
    ).claim
    assert claim is not None
    clock.advance(seconds=2)
    with pytest.raises(StageClaimConflict, match="expired_stage_claim"):
        store.commit_stage(
            req,
            claim,
            stage_ref(req.operation_id, input_digest="1" * 64),
            StageDisposition.CONTINUE,
            None,
            clock.now(),
        )


def test_slow_handler_loses_lease_then_reuses_immutable_result_on_retry():
    clock = ManualClock()

    def slow(context: StageExecutionContext):
        clock.advance(seconds=31)
        return RuntimeStageResult(context.stage_name, {"stable": "result"})

    handler = Handler("planned", [slow, RuntimeError("must not rerun")])
    runtime = orchestrator("planned", handlers={"planned": handler}, clock=clock)
    first = runtime.run(request())
    assert first.status == "retry_later"
    assert first.error_code == "stage_claim_lost"
    second = runtime.run(request(request_id="req-2", received_at="2026-07-22T00:00:01Z"))
    assert second.status == "completed"
    assert len(handler.calls) == 1


def test_json_schema_tracks_runtime_contract_fields_and_forbids_numbers():
    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas/phase4/runtime-contracts.schema.json").read_text("utf-8"))
    defs = schema["$defs"]
    assert set(defs["runtimeRequest"]["required"]) == RuntimeRequest.FIELDS
    assert set(defs["cancellationSignal"]["required"]) == CancellationSignal.FIELDS
    assert set(defs["stageResultRef"]["required"]) == StageResultRef.FIELDS
    assert set(defs["runtimeStatus"]["required"]) == RuntimeStatus.FIELDS
    assert set(defs["runtimeResponse"]["required"]) == RuntimeResponse.FIELDS
    canonical_types = defs["canonicalValue"]["oneOf"]
    assert not any(item.get("type") in {"number", "integer"} for item in canonical_types)

# --- Additional adversarial hardening discovered during full P4-01 review ---


def test_runtime_contract_strings_are_nfc_normalized_before_binding():
    import unicodedata

    decomposed = unicodedata.normalize("NFD", "café")
    composed = unicodedata.normalize("NFC", "café")
    first = request(actor_id=decomposed, payload={"topic": decomposed})
    second = request(request_id="req-2", received_at="2026-07-22T00:00:05Z", actor_id=composed, payload={"topic": composed})
    assert first.operation_id == second.operation_id
    assert first.actor_id == composed
    assert first.payload == {"topic": composed}

    handler = Handler("planned")
    runtime = orchestrator("planned", handlers={"planned": handler})
    assert runtime.run(first).status == "completed"
    assert runtime.run(second).status == "completed"
    assert len(handler.calls) == 1


def test_post_construction_request_payload_mutation_is_rejected_before_handler():
    req = request(payload={"topic": "alpha"})
    req.payload["topic"] = "tampered"
    handler = Handler("planned")
    runtime = orchestrator("planned", handlers={"planned": handler})
    with pytest.raises(InvalidContractValue, match="operation_id"):
        runtime.run(req)
    assert handler.calls == []


def test_handler_receives_stage_local_request_copy():
    seen = []

    def mutate(context: StageExecutionContext):
        context.request.payload["topic"] = "mutated-by-handler"
        return RuntimeStageResult("planned", {"ok": "yes"})

    def observe(context: StageExecutionContext):
        seen.append(context.request.payload["topic"])
        return RuntimeStageResult("retrieved", {"ok": "yes"})

    runtime = orchestrator(
        "planned",
        "retrieved",
        handlers={"planned": Handler("planned", [mutate]), "retrieved": Handler("retrieved", [observe])},
    )
    assert runtime.run(request(payload={"topic": "original"})).status == "completed"
    assert seen == ["original"]


def test_runtime_stage_result_types_and_mutable_sequences_fail_closed_or_normalize():
    with pytest.raises(InvalidContractValue, match="StageDisposition"):
        RuntimeStageResult("planned", {"ok": "yes"}, disposition="continue")  # type: ignore[arg-type]
    with pytest.raises(InvalidContractValue, match="must be an array"):
        RuntimeStageResult("planned", {"ok": "yes"}, provenance_refs="abc")  # type: ignore[arg-type]

    refs = ["a", "b"]
    result = RuntimeStageResult("planned", {"ok": "yes"}, provenance_refs=refs)  # type: ignore[arg-type]
    refs.append("c")
    assert result.provenance_refs == ("a", "b")


def test_pipeline_definition_copies_mutable_stage_sequence_and_generator_input():
    stages = ["planned", "retrieved"]
    pipeline = PipelineDefinition("pipe", "runtime.demo", stages)  # type: ignore[arg-type]
    stages.append("generated")
    assert pipeline.stages == ("planned", "retrieved")

    handlers = {"planned": Handler("planned"), "retrieved": Handler("retrieved")}
    runtime = RuntimeOrchestrator(
        pipelines=(item for item in [pipeline]),  # type: ignore[arg-type]
        handlers=handlers,
        clock=ManualClock(),
    )
    assert runtime.run(request()).status == "completed"


def test_stage_result_store_isolated_from_caller_and_reader_mutation():
    store = InMemoryStageResultStore()
    req = request()
    result = RuntimeStageResult("planned", {"nested": {"value": "original"}})
    stored = store.put_once(
        workspace_id=req.workspace_id,
        operation_id=req.operation_id,
        input_digest="1" * 64,
        result=result,
        created_at="2026-07-22T00:00:01Z",
    )
    result.payload["nested"]["value"] = "caller-mutated"
    stored.result.payload["nested"]["value"] = "reader-mutated"

    reread = store.get(req.workspace_id, req.operation_id, "planned", "1" * 64)
    assert reread is not None
    assert reread.result.payload == {"nested": {"value": "original"}}


def test_cancellation_wins_race_with_fatal_and_transient_failure():
    for failure in (FatalStageError("fatal_after_cancel"), TransientStageError("transient_after_cancel")):
        clock = ManualClock()
        holder = {}

        def action(context: StageExecutionContext, failure=failure):
            holder["runtime"].cancel(
                CancellationSignal.create(
                    workspace_id=context.request.workspace_id,
                    actor_id=context.request.actor_id,
                    operation_id=context.request.operation_id,
                    requested_at="2026-07-22T00:00:01Z",
                    reason_code="race_cancel",
                )
            )
            raise failure

        runtime = orchestrator("planned", handlers={"planned": Handler("planned", [action])}, clock=clock)
        holder["runtime"] = runtime
        response = runtime.run(request())
        assert response.status == "cancelled"
        assert response.error_code == "cancelled"


def test_expired_claim_with_existing_result_terminalizes_deadline_not_retry():
    clock = ManualClock()
    store = InMemoryOperationStore()
    req = request(deadline_at="2026-07-22T00:00:10Z")
    pipeline = PipelineDefinition("pipe", req.request_type, ("planned",))
    record = store.register(req, pipeline, clock.now())
    digest = RuntimeOrchestrator._stage_input_digest(req, "planned", record.stage_result_refs)
    decision = store.claim_next(
        req,
        request_id=req.request_id,
        now=clock.now(),
        lease_duration=timedelta(seconds=30),
        input_digest=digest,
    )
    assert decision.claim is not None
    result_ref = stage_ref(req.operation_id, stage_name="planned", input_digest=digest)
    clock.set(datetime(2026, 7, 22, 0, 0, 10, tzinfo=UTC))
    terminal = store.commit_stage(
        req,
        decision.claim,
        result_ref,
        StageDisposition.CONTINUE,
        None,
        clock.now(),
    )
    assert terminal.state.value == "failed"
    assert terminal.error_code == "deadline_exceeded"
    assert terminal.stage_result_refs == ()


def test_cancellation_signal_cannot_predate_operation_creation():
    clock = ManualClock(datetime(2026, 7, 22, 0, 0, 5, tzinfo=UTC))
    store = InMemoryOperationStore()
    req = request(received_at="2026-07-22T00:00:05Z")
    store.register(req, PipelineDefinition("pipe", req.request_type, ("planned",)), clock.now())
    signal = CancellationSignal.create(
        workspace_id=req.workspace_id,
        actor_id=req.actor_id,
        operation_id=req.operation_id,
        requested_at="2026-07-22T00:00:01Z",
        reason_code="stale_signal",
    )
    with pytest.raises(OperationConflict, match="precedes_operation"):
        store.request_cancel(signal, clock.now())


def test_runtime_status_rejects_stage_state_not_matching_committed_refs():
    req = request()
    ref = stage_ref(req.operation_id, stage_name="planned")
    with pytest.raises(InvalidContractValue, match="last committed stage"):
        RuntimeStatus.from_mapping(
            {
                "runtime_status_version": RUNTIME_STATUS_VERSION,
                "operation_id": req.operation_id,
                "workspace_id": req.workspace_id,
                "state": "retrieved",
                "current_stage": "generated",
                "attempt": "0",
                "revision": "1",
                "deadline_at": req.deadline_at,
                "cancellation_id": None,
                "stage_result_refs": [ref.to_mapping()],
                "updated_at": "2026-07-22T00:00:01Z",
                "error_code": None,
            }
        )


def test_cancellation_is_actor_bound_and_foreign_actor_cannot_change_state():
    clock = ManualClock()
    store = InMemoryOperationStore()
    runtime = orchestrator("planned", operation_store=store, clock=clock)
    req = request()
    store.register(req, runtime.pipelines[req.request_type], clock.now())
    signal = CancellationSignal.create(
        workspace_id=req.workspace_id,
        actor_id="intruder",
        operation_id=req.operation_id,
        requested_at="2026-07-22T00:00:01Z",
        reason_code="user_requested",
    )
    with pytest.raises(OperationConflict, match="actor_mismatch"):
        runtime.cancel(signal)
    status = runtime.status(req.workspace_id, req.operation_id)
    assert status is not None
    assert status.state == "received"
    assert status.cancellation_id is None


def test_cancellation_timestamp_too_far_in_future_is_rejected():
    clock = ManualClock()
    store = InMemoryOperationStore()
    runtime = orchestrator("planned", operation_store=store, clock=clock)
    req = request()
    store.register(req, runtime.pipelines[req.request_type], clock.now())
    signal = CancellationSignal.create(
        workspace_id=req.workspace_id,
        actor_id=req.actor_id,
        operation_id=req.operation_id,
        requested_at="2026-07-22T00:06:00Z",
        reason_code="user_requested",
    )
    with pytest.raises(OperationConflict, match="too_far_in_future"):
        runtime.cancel(signal)


def test_early_complete_cannot_bypass_later_verification_stage():
    planned = Handler(
        "planned",
        [RuntimeStageResult("planned", {"shortcut": "attempt"}, disposition=StageDisposition.COMPLETE)],
    )
    generated = Handler("generated")
    verified = Handler("verified")
    runtime = orchestrator(
        "planned",
        "generated",
        "verified",
        handlers={"planned": planned, "generated": generated, "verified": verified},
    )
    response = runtime.run(request())
    assert response.status == "failed"
    assert response.error_code == "early_stage_completion_denied"
    assert response.stage_result_refs == ()
    assert len(planned.calls) == 1
    assert generated.calls == []
    assert verified.calls == []


def test_transient_retry_budget_is_finite_and_terminal_on_last_attempt():
    handler = Handler(
        "planned",
        [
            TransientStageError("provider_503"),
            TransientStageError("provider_503"),
            TransientStageError("provider_503"),
            RuntimeError("must_not_run"),
        ],
    )
    runtime = RuntimeOrchestrator(
        pipelines=(PipelineDefinition("p", "runtime.demo", ("planned",)),),
        handlers={"planned": handler},
        clock=ManualClock(),
        max_stage_attempts=3,
    )
    first = runtime.run(request(request_id="r1"))
    second = runtime.run(request(request_id="r2", received_at="2026-07-22T00:00:01Z"))
    third = runtime.run(request(request_id="r3", received_at="2026-07-22T00:00:02Z"))
    fourth = runtime.run(request(request_id="r4", received_at="2026-07-22T00:00:03Z"))
    assert (first.status, second.status) == ("retry_later", "retry_later")
    assert third.status == "failed"
    assert third.error_code == "retry_budget_exhausted"
    assert fourth.status == "failed"
    assert len(handler.calls) == 3


def test_claim_loss_after_other_worker_completed_returns_terminal_response():
    class CommitThenReportLost(InMemoryOperationStore):
        def commit_stage(self, *args, **kwargs):
            super().commit_stage(*args, **kwargs)
            raise StageClaimConflict("simulated_race")

    handler = Handler("planned")
    runtime = orchestrator(
        "planned",
        handlers={"planned": handler},
        operation_store=CommitThenReportLost(),
    )
    response = runtime.run(request())
    assert response.status == "completed"
    assert response.state == "completed"
    assert response.result_ref is not None


def test_response_result_ref_must_be_the_final_committed_ref():
    req = request()
    planned = stage_ref(req.operation_id, "planned", "1" * 64)
    retrieved = StageResultRef.create(
        operation_id=req.operation_id,
        stage_name="retrieved",
        input_digest="3" * 64,
        content_digest="4" * 64,
        schema_id="phase4-test-result-v1",
        created_at="2026-07-22T00:00:02Z",
        provenance_refs=(),
    )
    with pytest.raises(InvalidContractValue, match="final stage_result_ref"):
        RuntimeResponse.from_mapping(
            {
                "runtime_response_version": RUNTIME_RESPONSE_VERSION,
                "request_id": req.request_id,
                "operation_id": req.operation_id,
                "workspace_id": req.workspace_id,
                "status": "completed",
                "state": "completed",
                "requested_generation_id": req.requested_generation_id,
                "stage_result_refs": [planned.to_mapping(), retrieved.to_mapping()],
                "result_ref": planned.to_mapping(),
                "retryable": False,
                "error_code": None,
                "updated_at": "2026-07-22T00:00:03Z",
            }
        )


def test_nested_stage_ref_type_confusion_raises_contract_error_not_python_type_error():
    req = request()
    status = {
        "runtime_status_version": RUNTIME_STATUS_VERSION,
        "operation_id": req.operation_id,
        "workspace_id": req.workspace_id,
        "state": "completed",
        "current_stage": None,
        "attempt": "1",
        "revision": "1",
        "deadline_at": req.deadline_at,
        "cancellation_id": None,
        "stage_result_refs": [42],
        "updated_at": "2026-07-22T00:00:01Z",
        "error_code": None,
    }
    with pytest.raises(InvalidContractValue, match="entries must be objects"):
        RuntimeStatus.from_mapping(status)


def test_stage_handler_receives_semantic_input_without_transport_fields():
    observed = {}

    def inspect(context: StageExecutionContext):
        observed["has_request_id"] = hasattr(context.request, "request_id")
        observed["has_received_at"] = hasattr(context.request, "received_at")
        observed["operation_id"] = context.request.operation_id
        return RuntimeStageResult("planned", {"ok": "yes"})

    req = request(request_id="delivery-only")
    response = orchestrator("planned", handlers={"planned": Handler("planned", [inspect])}).run(req)
    assert response.status == "completed"
    assert observed == {
        "has_request_id": False,
        "has_received_at": False,
        "operation_id": req.operation_id,
    }


def test_runtime_codes_and_stage_result_error_semantics_are_fail_closed():
    req = request()
    with pytest.raises(InvalidContractValue, match="lowercase code"):
        CancellationSignal.create(
            workspace_id=req.workspace_id,
            actor_id=req.actor_id,
            operation_id=req.operation_id,
            requested_at="2026-07-22T00:00:01Z",
            reason_code="Bad Reason",
        )
    with pytest.raises(InvalidContractValue, match="must not carry error_code"):
        RuntimeStageResult("planned", {"ok": "yes"}, error_code="unexpected")
    rejected = RuntimeStageResult("planned", {"ok": "no"}, disposition=StageDisposition.REJECT)
    assert rejected.error_code == "stage_rejected"
    with pytest.raises(InvalidContractValue, match="lowercase code"):
        RuntimeStageResult(
            "planned",
            {"ok": "no"},
            disposition=StageDisposition.REJECT,
            error_code="Bad Code",
        )


def test_status_poll_refreshes_deadline_without_running_handler():
    clock = ManualClock()
    store = InMemoryOperationStore()
    runtime = orchestrator("planned", operation_store=store, clock=clock)
    req = request()
    store.register(req, runtime.pipelines[req.request_type], clock.now())
    clock.advance(minutes=11)
    status = runtime.status(req.workspace_id, req.operation_id)
    assert status is not None
    assert status.state == "failed"
    assert status.error_code == "deadline_exceeded"


def test_mutated_cancellation_and_detached_request_mapping_are_revalidated():
    req = request(payload={"nested": {"value": "original"}})
    mapping = req.to_mapping()
    mapping["payload"]["nested"]["value"] = "mapping-mutated"
    assert req.payload == {"nested": {"value": "original"}}

    clock = ManualClock()
    store = InMemoryOperationStore()
    runtime = orchestrator("planned", operation_store=store, clock=clock)
    store.register(req, runtime.pipelines[req.request_type], clock.now())
    signal = CancellationSignal.create(
        workspace_id=req.workspace_id,
        actor_id=req.actor_id,
        operation_id=req.operation_id,
        requested_at="2026-07-22T00:00:01Z",
        reason_code="user_requested",
    )
    object.__setattr__(signal, "reason_code", "tampered")
    with pytest.raises(InvalidContractValue, match="cancellation_id"):
        runtime.cancel(signal)


def test_terminal_status_reports_last_stage_attempt_and_retry_configuration_rejects_bool():
    runtime = orchestrator("planned")
    req = request()
    assert runtime.run(req).status == "completed"
    status = runtime.status(req.workspace_id, req.operation_id)
    assert status is not None and status.attempt == "1"
    with pytest.raises(InvalidContractValue, match="positive integer"):
        RuntimeOrchestrator(
            pipelines=(PipelineDefinition("p", "x", ("planned",)),),
            handlers={"planned": Handler("planned")},
            max_stage_attempts=True,  # type: ignore[arg-type]
        )
