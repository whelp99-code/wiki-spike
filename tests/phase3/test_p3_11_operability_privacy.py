from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion
from wiki_spike.memory_core.operability import (
    AUDIT_RECORD_VERSION,
    EXPORT_REQUEST_VERSION,
    AuditCapacityExceeded,
    AuditRecorder,
    AuditReference,
    BackpressureController,
    BoundedInMemoryAuditSink,
    BoundedProjectionJobSubmitter,
    BoundedWorkItem,
    BoundedWorkQueue,
    CircuitBreaker,
    ExportProjectionJob,
    ExportRequest,
    ExportRequestGateway,
    PrivacyPreservingTelemetry,
    ReferenceHasher,
    RetryBudget,
    TelemetryAuditUnavailable,
    TelemetryPoint,
)
from wiki_spike.memory_core.policy import CapabilityToken, Sensitivity

NOW = "2026-07-22T00:00:00Z"
LATER = "2026-07-22T00:10:00Z"
AFTER_RESET = "2026-07-22T00:00:11Z"
GEN = "a" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def make_audit(max_records=20):
    sink = BoundedInMemoryAuditSink(max_records)
    return AuditRecorder(ReferenceHasher(b"reference-key-material-32-bytes!!"), sink, policy_version="core-policy-v1"), sink


def make_point(**overrides):
    values = dict(workspace_ref_hash=HASH_A, metric_name="queue.depth", time_bucket=NOW,
                  value_bucket="small", count="3", status_code="ok")
    values.update(overrides)
    return TelemetryPoint.create(**values)


def make_work(label="1", **overrides):
    values = dict(
        workspace_ref_hash=HASH_A,
        operation_ref_hash=hashlib.sha256(label.encode()).hexdigest(),
        work_type="projection.rebuild",
        payload_ref_digest=hashlib.sha256(("payload-" + label).encode()).hexdigest(),
        cost_units="2", enqueued_at=NOW, deadline_at=LATER,
    )
    values.update(overrides)
    return BoundedWorkItem.create(**values)


def make_request(**overrides):
    values = dict(
        workspace_id="workspace-private", actor_id="actor-private", as_of_generation_id=GEN,
        target_class="internal_projection", projection_profile="memory.summary",
        field_allowlist=("metadata.created_at", "title"), max_sensitivity="internal",
        delivery_intent_ref=HASH_B, requested_at=NOW,
    )
    values.update(overrides)
    return ExportRequest.create(**values)


def make_token(**overrides):
    values = dict(token_id="token-1", workspace_id="workspace-private", actor_id="actor-private",
                  actions=frozenset({"export.request"}), max_sensitivity=Sensitivity.PRIVATE,
                  expires_at="2026-07-23T00:00:00Z")
    values.update(overrides)
    return CapabilityToken(**values)


class TelemetrySink:
    def __init__(self, fail=False): self.fail, self.points = fail, []
    def emit(self, point):
        if self.fail: raise RuntimeError("down")
        self.points.append(point)


class AlwaysFailAudit:
    def append(self, record): raise AuditCapacityExceeded()


class BrokenSubmitter:
    def submit(self, job): raise RuntimeError("down")
    def cancel(self, job_id): return False


def test_reference_hasher_is_deterministic_and_namespace_separated():
    a = ReferenceHasher(b"k" * 32, namespace="audit-ref-v1")
    b = ReferenceHasher(b"k" * 32, namespace="telemetry-ref-v1")
    assert a.digest("same") == a.digest("same")
    assert a.digest("same") != a.digest("different") != b.digest("different")
    assert a.digest("same") != b.digest("same")


def test_audit_contains_only_hashed_references_and_no_payload_fields():
    recorder, sink = make_audit()
    raw = ("workspace-private", "actor-personal", "operation-sensitive", "correlation-sensitive", "document-body-private")
    record = recorder.record(workspace_id=raw[0], actor_id=raw[1], operation_id=raw[2], correlation_id=raw[3],
                             action="memory.revise", outcome="accepted", reason_code="revision_stored",
                             occurred_at=NOW, generation_id=GEN, object_refs=(raw[4],))
    encoded = record.canonical_bytes().decode()
    assert all(value not in encoded for value in raw)
    assert not ({"body", "prompt", "token", "message"} & set(record.to_mapping()))
    assert len(sink) == 1


def test_audit_id_binds_metadata_and_strict_fields():
    recorder, _ = make_audit()
    record = recorder.record(workspace_id="ws", actor_id="actor", operation_id="op", correlation_id="corr",
                             action="memory.read", outcome="accepted", reason_code="ok", occurred_at=NOW)
    mapping = record.to_mapping(); mapping["reason_code"] = "different"
    with pytest.raises(InvalidContractValue, match="audit_id"): AuditReference.from_mapping(mapping)
    mapping = record.to_mapping(); mapping["body"] = "forbidden"
    with pytest.raises(UnknownContractField): AuditReference.from_mapping(mapping)
    with pytest.raises(UnsupportedContractVersion): replace(record, audit_record_version=AUDIT_RECORD_VERSION + "-future")


def test_audit_sink_is_idempotent_and_never_evicts():
    recorder, sink = make_audit(1)
    record = recorder.record(workspace_id="ws", actor_id="actor", operation_id="op", correlation_id="corr",
                             action="memory.read", outcome="accepted", reason_code="ok", occurred_at=NOW)
    assert sink.append(record) == "duplicate"
    with pytest.raises(AuditCapacityExceeded):
        recorder.record(workspace_id="ws", actor_id="actor", operation_id="op2", correlation_id="corr2",
                        action="memory.read", outcome="accepted", reason_code="ok", occurred_at=NOW)
    assert sink.records() == (record,)


def test_telemetry_is_aggregate_only_content_bound_and_strict():
    point = make_point(); mapping = point.to_mapping()
    assert not ({"actor_id", "operation_id", "body", "prompt"} & set(mapping))
    tampered = dict(mapping, count="4")
    with pytest.raises(InvalidContractValue, match="point_id"): TelemetryPoint.from_mapping(tampered)
    mapping = point.to_mapping(); mapping["count"] = 3
    with pytest.raises(InvalidContractValue, match="canonical"): TelemetryPoint.from_mapping(mapping)
    mapping = point.to_mapping(); mapping["workspace_id"] = "raw"
    with pytest.raises(UnknownContractField): TelemetryPoint.from_mapping(mapping)
    with pytest.raises(InvalidContractValue, match="bounded code"): make_point(value_bucket="user email@example.com")


def test_telemetry_success_and_outage_paths():
    recorder, audits = make_audit(); sink = TelemetrySink(); point = make_point()
    delivered = PrivacyPreservingTelemetry(sink, recorder).emit(point, workspace_id="ws", actor_id="actor",
                  operation_id="op", correlation_id="corr", occurred_at=NOW)
    assert delivered.status == "delivered" and sink.points == [point] and len(audits) == 0
    degraded = PrivacyPreservingTelemetry(TelemetrySink(True), recorder).emit(point, workspace_id="workspace-raw",
                  actor_id="actor-raw", operation_id="op-raw", correlation_id="corr-raw", occurred_at=NOW)
    assert degraded.status == "audit_only" and degraded.error_code == "telemetry_unavailable"
    encoded = audits.records()[0].canonical_bytes().decode()
    assert "workspace-raw" not in encoded and "actor-raw" not in encoded


def test_telemetry_and_audit_double_outage_fails_closed():
    recorder = AuditRecorder(ReferenceHasher(b"x" * 32), AlwaysFailAudit(), policy_version="policy-v1")
    with pytest.raises(TelemetryAuditUnavailable):
        PrivacyPreservingTelemetry(TelemetrySink(True), recorder).emit(make_point(), workspace_id="ws", actor_id="actor",
                     operation_id="op", correlation_id="corr", occurred_at=NOW)


def test_work_item_is_reference_only_content_bound_and_strict():
    item = make_work(); assert "payload" not in item.to_mapping()
    mapping = item.to_mapping(); mapping["payload_ref_digest"] = HASH_C
    with pytest.raises(InvalidContractValue, match="work_id"): BoundedWorkItem.from_mapping(mapping)
    mapping = item.to_mapping(); mapping["payload"] = {"body": "x"}
    with pytest.raises(UnknownContractField): BoundedWorkItem.from_mapping(mapping)
    with pytest.raises(InvalidContractValue, match="later"): make_work(deadline_at=NOW)


def test_queue_enforces_global_workspace_cost_deadline_and_duplicate_limits():
    q = BoundedWorkQueue(max_items=2, max_cost_units=3, per_workspace_max_items=1)
    first = make_work("first", cost_units="2")
    assert q.submit(first, now=NOW).status == "accepted"
    assert q.submit(first, now=NOW).status == "duplicate"
    assert q.submit(make_work("same"), now=NOW).error_code == "workspace_queue_full"
    assert q.submit(make_work("other", workspace_ref_hash=HASH_B, cost_units="2"), now=NOW).error_code == "queue_cost_budget_exceeded"
    expired = make_work("expired", workspace_ref_hash=HASH_B, deadline_at="2026-07-22T00:00:01Z")
    assert q.submit(expired, now="2026-07-22T00:00:01Z").error_code == "work_deadline_expired"
    assert q.size == 1 and q.cost_units == 2


def test_queue_pop_discards_expired_and_releases_accounting():
    q = BoundedWorkQueue(max_items=2, max_cost_units=10, per_workspace_max_items=2)
    item = make_work("live", deadline_at="2026-07-22T00:00:05Z")
    assert q.submit(item, now=NOW).status == "accepted"
    assert q.pop(now="2026-07-22T00:00:06Z") is None
    assert q.size == 0 and q.cost_units == 0


def test_retry_budget_blocks_attempt_cost_and_table_storms():
    b = RetryBudget(max_operations=2, max_attempts=2, max_total_cost_units=3)
    assert b.reserve(HASH_A, "1").allowed and b.reserve(HASH_A, "1").allowed
    assert b.reserve(HASH_A, "1").error_code == "retry_attempt_budget_exceeded"
    assert b.reserve(HASH_B, "3").allowed
    assert b.reserve(HASH_B, "1").error_code == "retry_cost_budget_exceeded"
    assert b.reserve(HASH_C, "1").error_code == "operation_budget_store_full"


def test_retry_budget_rollback_and_complete():
    b = RetryBudget(max_operations=2, max_attempts=5, max_total_cost_units=3)
    assert b.reserve(HASH_A, "2").allowed
    b.rollback(HASH_A, "2"); assert b.state(HASH_A) is None
    assert b.reserve(HASH_A, "1").allowed
    b.complete(HASH_A); assert b.state(HASH_A) is None


def test_circuit_breaker_open_half_open_busy_and_recovery():
    c = CircuitBreaker(failure_threshold=2, reset_after_seconds=10)
    c.record_failure(now=NOW); assert c.state == "closed"
    c.record_failure(now=NOW); assert c.state == "open"
    assert c.before_call(now="2026-07-22T00:00:05Z").error_code == "circuit_open"
    assert c.before_call(now=AFTER_RESET).state == "half_open"
    assert c.before_call(now=AFTER_RESET).error_code == "circuit_half_open_busy"
    c.record_success(); assert c.state == "closed"


def test_backpressure_does_not_consume_budget_for_duplicate_or_queue_rejection():
    q = BoundedWorkQueue(max_items=1, max_cost_units=10, per_workspace_max_items=1)
    b = RetryBudget(max_operations=3, max_attempts=2, max_total_cost_units=10)
    c = CircuitBreaker(failure_threshold=2, reset_after_seconds=10)
    controller = BackpressureController(q, b, c); first = make_work("first")
    assert controller.submit(first, now=NOW).status == "accepted"
    assert b.state(first.operation_ref_hash) == ("1", "2")
    assert controller.submit(first, now=NOW).status == "duplicate"
    assert b.state(first.operation_ref_hash) == ("1", "2")
    second = make_work("second", workspace_ref_hash=HASH_B)
    assert controller.submit(second, now=NOW).error_code == "queue_full"
    assert b.state(second.operation_ref_hash) is None


def test_backpressure_rolls_queue_back_on_budget_denial_and_open_circuit():
    q = BoundedWorkQueue(max_items=2, max_cost_units=10, per_workspace_max_items=2)
    b = RetryBudget(max_operations=1, max_attempts=1, max_total_cost_units=1)
    c = CircuitBreaker(failure_threshold=1, reset_after_seconds=10)
    controller = BackpressureController(q, b, c); expensive = make_work("expensive", cost_units="2")
    assert controller.submit(expensive, now=NOW).error_code == "retry_cost_budget_exceeded"
    assert q.size == 0 and b.state(expensive.operation_ref_hash) is None
    c.record_failure(now=NOW); blocked = make_work("blocked")
    assert controller.submit(blocked, now="2026-07-22T00:00:05Z").error_code == "circuit_open"
    assert q.size == 0


def test_export_request_content_binding_no_destination_and_forbidden_fields():
    request = make_request(field_allowlist=("title", "metadata.created_at"))
    assert request.field_allowlist == ("metadata.created_at", "title")
    mapping = request.to_mapping(); assert "destination_url" not in mapping and "credential" not in mapping
    mapping["destination_url"] = "https://example.invalid"
    with pytest.raises(UnknownContractField): ExportRequest.from_mapping(mapping)
    for field in ("body", "document.prompt", "metadata.token", "secret.value"):
        with pytest.raises(InvalidContractValue, match="forbidden field"): make_request(field_allowlist=(field,))


def test_export_target_sensitivity_ceiling_and_version_are_enforced():
    with pytest.raises(InvalidContractValue, match="ceiling"): make_request(target_class="public_bundle", max_sensitivity="internal")
    assert make_request(target_class="private_archive", max_sensitivity="private")
    with pytest.raises(InvalidContractValue, match="unsupported"): make_request(target_class="external_database")
    with pytest.raises(UnsupportedContractVersion): replace(make_request(), export_request_version=EXPORT_REQUEST_VERSION + "-future")


def test_export_projection_job_and_bounded_submitter_are_content_bound():
    first = ExportProjectionJob.from_request(make_request())
    mapping = first.to_mapping(); mapping["target_class"] = "public_bundle"
    with pytest.raises(InvalidContractValue): ExportProjectionJob.from_mapping(mapping)
    submitter = BoundedProjectionJobSubmitter(1); assert submitter.submit(first) == "accepted"
    assert submitter.submit(first) == "duplicate"
    second = ExportProjectionJob.from_request(make_request(delivery_intent_ref=HASH_C))
    assert submitter.submit(second) == "queue_full" and submitter.pop() == first


def test_export_gateway_policy_first_queue_audit_and_non_disclosure():
    audit, sink = make_audit(); submitter = BoundedProjectionJobSubmitter(2); request = make_request()
    result = ExportRequestGateway(submitter, audit, now=NOW).submit(request, make_token(), correlation_id="corr-private")
    assert result.status == "accepted" and submitter.size == 1 and len(sink) == 1
    encoded = sink.records()[0].canonical_bytes().decode()
    assert request.workspace_id not in encoded and request.actor_id not in encoded and "corr-private" not in encoded
    denied = ExportRequestGateway(BoundedProjectionJobSubmitter(2), audit, now=NOW).submit(
        request, make_token(actions=frozenset()), correlation_id="corr")
    assert denied.status == "rejected" and denied.error_code == "capability_missing"


def test_export_queue_full_unavailable_and_audit_failure_paths():
    audit, sink = make_audit(); full = BoundedProjectionJobSubmitter(1)
    assert full.submit(ExportProjectionJob.from_request(make_request())) == "accepted"
    result = ExportRequestGateway(full, audit, now=NOW).submit(make_request(delivery_intent_ref=HASH_C), make_token(), correlation_id="corr")
    assert result.status == "retry_later" and result.error_code == "export_queue_full"
    unavailable = ExportRequestGateway(BrokenSubmitter(), audit, now=NOW).submit(make_request(), make_token(), correlation_id="corr")
    assert unavailable.error_code == "export_queue_unavailable"
    submitter = BoundedProjectionJobSubmitter(1)
    recorder = AuditRecorder(ReferenceHasher(b"x" * 32), AlwaysFailAudit(), policy_version="policy-v1")
    with pytest.raises(AuditCapacityExceeded):
        ExportRequestGateway(submitter, recorder, now=NOW).submit(make_request(), make_token(), correlation_id="corr")
    assert submitter.size == 0


def test_export_duplicate_replay_is_idempotent():
    audit, sink = make_audit(); submitter = BoundedProjectionJobSubmitter(2)
    gateway = ExportRequestGateway(submitter, audit, now=NOW); request = make_request()
    first = gateway.submit(request, make_token(), correlation_id="corr")
    second = gateway.submit(request, make_token(), correlation_id="corr")
    assert first.job_id == second.job_id and submitter.size == 1 and len(sink) == 1


def test_no_external_destination_writer_in_core_module():
    from wiki_spike.memory_core import operability
    names = set(vars(operability))
    assert not ({"ExternalDestinationWriter", "DestinationClient", "write_external_destination"} & names)


def test_schema_is_strict_and_adversarial_document_has_20_rounds():
    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas/phase3/operability-contracts.schema.json").read_text())
    for name in ("auditReference", "telemetryPoint", "boundedWorkItem", "exportRequest", "exportProjectionJob"):
        assert schema["$defs"][name]["additionalProperties"] is False
    assert "destination_url" not in schema["$defs"]["exportRequest"]["properties"]
    import re
    text = (root / "docs/adversarial/P3-11_ADVERSARIAL_VALIDATION_20R_KR.md").read_text()
    assert [int(x) for x in re.findall(r"^## Round (\d{2})", text, re.M)] == list(range(1, 21))
