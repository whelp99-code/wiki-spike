import pytest

from wiki_spike.memory_core.operability import (
    AuditRecorder,
    BoundedInMemoryAuditSink,
    PrivacyPreservingTelemetry,
    ReferenceHasher,
    TelemetryAllowlist,
    TelemetryMetricAllowlist,
    TelemetryPoint,
)
from wiki_spike.memory_core.second_brain_egress import (
    EgressAuthorizationRequest,
    LocalFirstEgressPolicy,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    CapabilityReceiptV1,
    EgressPolicyV1,
    SourceConsentRetentionV1,
)

NOW = "2026-07-28T00:00:00Z"
HASH = "a" * 64


class Sink:
    def __init__(self, fails=False):
        self.fails = fails
        self.points = []

    def emit(self, point):
        if self.fails:
            raise RuntimeError("unavailable")
        self.points.append(point)


def point(**overrides):
    values = {
        "workspace_ref_hash": HASH,
        "metric_name": "egress.count",
        "time_bucket": NOW,
        "value_bucket": "zero",
        "count": "1",
        "status_code": "denied",
    }
    values.update(overrides)
    return TelemetryPoint.create(**values)


def telemetry(sink):
    audit = AuditRecorder(
        ReferenceHasher(b"reference-key-material-32-bytes!!"),
        BoundedInMemoryAuditSink(4),
        policy_version="core-policy-v1",
    )
    return PrivacyPreservingTelemetry(
        sink,
        audit,
        allowlist=TelemetryAllowlist({
            "egress.count": TelemetryMetricAllowlist(("one", "zero"), ("denied", "ok"), 1, 60),
        }),
    ), audit


def emit(service, value):
    return service.emit(
        value,
        workspace_id="raw-workspace-id",
        actor_id="raw-actor-id",
        operation_id="raw-operation-id",
        correlation_id="raw-correlation-id",
        occurred_at=NOW,
    )


def test_local_default_and_unresolved_db06_never_invoke_external_callable():
    request = EgressAuthorizationRequest(
        data_class_ref="class:1", provider_ref="provider:1", route_ref="route:1",
        consent_ref="consent:1", capability_ref="capability:1", policy_digest=HASH,
        receipt_intent_ref="receipt:1",
    )
    called = []
    policy = LocalFirstEgressPolicy()
    assert not policy.authorize(request, now=NOW).allowed
    assert policy.invoke(request, lambda: called.append("external"), now=NOW) is None
    assert called == []
def test_caller_supplied_receipts_and_body_digest_substitution_never_authorize():
    request = EgressAuthorizationRequest(
        data_class_ref="class:1", provider_ref="provider:1", route_ref="route:1",
        consent_ref="consent:1", capability_ref="capability:1", policy_digest=HASH,
        receipt_intent_ref="receipt:1",
    )
    policy = EgressPolicyV1(
        "second-brain-security-foundation-v1", "policy:" + HASH, "1", "provider:1",
        ("class:" + HASH, "route:" + HASH), HASH,
    )
    consent = SourceConsentRetentionV1(
        "second-brain-security-foundation-v1", "source:" + HASH, "consent:" + HASH,
        "1", "2030-02-01T00:00:00Z", "map:" + HASH, HASH,
    )
    receipt = CapabilityReceiptV1(
        "second-brain-security-foundation-v1", "receipt:" + HASH, "request:" + HASH,
        "capability:" + HASH, ("class:" + HASH, "route:" + HASH), NOW,
        "2030-02-01T00:00:00Z", HASH,
    )
    gate = LocalFirstEgressPolicy(policy, consent, receipt)
    assert not gate.authorize(request, now=NOW).allowed
    assert not LocalFirstEgressPolicy(
        policy, consent, receipt, resolution=object(), aggregate=object(), trusted_keys=object(),
    ).authorize(request, now=NOW).allowed


def test_telemetry_rejects_unknown_free_text_raw_ids_and_limits_before_sink():
    sink = Sink()
    service, _ = telemetry(sink)
    assert emit(service, point(metric_name="raw.document.title")).error_code == "telemetry_metric_not_allowed"
    assert emit(service, point(value_bucket="raw-marker")).error_code == "telemetry_value_bucket_not_allowed"
    assert emit(service, point(status_code="free-text")).error_code == "telemetry_status_not_allowed"
    assert emit(service, point(time_bucket="2026-07-27T23:58:00Z")).error_code == "telemetry_retention_exceeded"
    with pytest.raises(Exception):
        point(workspace_ref_hash="raw-user-id")
    assert emit(service, point()).status == "delivered"
    assert emit(service, point(value_bucket="one")).error_code == "telemetry_cardinality_exceeded"
    assert sink.points == [point()]


def test_telemetry_sink_failure_uses_body_free_audit_fallback():
    sink = Sink(fails=True)
    service, audit = telemetry(sink)
    result = emit(service, point())
    assert result.status == "audit_only"
    encoded = audit.sink.records()[0].canonical_bytes().decode()
    assert "raw-workspace-id" not in encoded
    assert "raw-actor-id" not in encoded
