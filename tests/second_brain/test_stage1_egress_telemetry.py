from datetime import datetime, timezone

import pytest
from test_decision_contracts import TRUSTED, aggregate, expected, records, scope
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1, resolve_second_brain_contract

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
    EgressAuthorityStore,
    EgressAuthorizationRequest,
    LocalFirstEgressPolicy,
    mint_egress_authority_store,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    CapabilityReceiptV1,
    EgressPolicyV1,
    SourceConsentRetentionV1,
    mint_security_context_authority,
)

NOW = "2026-07-28T00:00:00Z"
HASH = "a" * 64


def ref(kind: str, digit: str) -> str:
    return f"{kind}:{digit * 64}"


def egress_authority():
    items = records()
    envelope = aggregate(items)
    resolution = resolve_second_brain_contract(
        items, ResolvedScopeV1.from_mapping(scope()), expected(), envelope, trusted_keys=TRUSTED,
    )
    return mint_security_context_authority(resolution, envelope, TRUSTED)


def stored_records():
    policy = EgressPolicyV1.from_mapping({
        "security_version": "second-brain-security-foundation-v1", "policy_ref": ref("policy", "1"),
        "policy_revision": "1", "destination_ref": ref("provider", "2"),
        "allowed_scope_refs": [ref("class", "3"), ref("route", "4")], "policy_digest": HASH,
    })
    consent = SourceConsentRetentionV1.from_mapping({
        "security_version": "second-brain-security-foundation-v1", "source_ref": ref("source", "5"),
        "consent_ref": ref("consent", "6"), "retention_revision": "1",
        "retention_until": "2030-02-01T00:00:00Z", "deletion_recovery_map_ref": ref("map", "7"),
        "policy_digest": HASH,
    })
    capability = CapabilityReceiptV1.from_mapping({
        "security_version": "second-brain-security-foundation-v1", "receipt_ref": ref("receipt", "8"),
        "request_ref": ref("request", "9"), "capability_ref": ref("capability", "b"),
        "authorized_scope_refs": [ref("class", "3"), ref("route", "4")],
        "issued_at": NOW, "expires_at": "2030-02-01T00:00:00Z", "receipt_digest": HASH,
    })
    return policy, consent, capability
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
    with pytest.raises(TypeError):
        LocalFirstEgressPolicy(policy, consent, receipt)
    assert not LocalFirstEgressPolicy().authorize(request, now=NOW).allowed


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
def test_egress_store_rejects_forged_store_receipt_body_and_revision():
    with pytest.raises(Exception):
        EgressAuthorityStore(object(), object())  # type: ignore[arg-type]

    store = mint_egress_authority_store(egress_authority())
    receipt_id = store.mint_receipt(*stored_records())
    request = EgressAuthorizationRequest("class:1", "provider:1", "route:1", "consent:1", "capability:1", HASH, "receipt:1")
    now = datetime(2026, 7, 28, tzinfo=timezone.utc)
    assert store._load_current("forged-receipt", request, now=now) is None

    record = store._EgressAuthorityStore__receipts[receipt_id]
    object.__setattr__(record, "policy_body", b"{}")
    assert store._load_current(receipt_id, request, now=now) is None

    receipt_id = store.mint_receipt(*stored_records())
    record = store._EgressAuthorityStore__receipts[receipt_id]
    store._EgressAuthorityStore__current_revisions[(record.policy_body and stored_records()[0].policy_ref, stored_records()[1].consent_ref)] = ("2", "1")
    assert store._load_current(receipt_id, request, now=now) is None
