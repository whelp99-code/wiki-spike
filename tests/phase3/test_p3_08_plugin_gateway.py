from __future__ import annotations

from dataclasses import replace
import json

import pytest

from wiki_spike.memory_core import (
    PLUGIN_MANIFEST_VERSION,
    PLUGIN_REQUEST_VERSION,
    PLUGIN_RESPONSE_VERSION,
    CapabilityToken,
    InMemoryPluginOutputValidator,
    InMemoryPluginQuotaStore,
    InvalidContractValue,
    PluginGateway,
    PluginManifest,
    PluginRequest,
    Sensitivity,
    UnknownContractField,
)


def manifest(**overrides):
    values = {
        "plugin_id": "summary",
        "plugin_version": "1.0.0",
        "runner_mode": "out_of_process",
        "allowed_operations": ("summarize",),
        "required_capabilities": ("memory.read",),
        "egress_class": "private",
        "max_request_bytes": "4096",
        "max_response_bytes": "4096",
        "timeout_ms": "1000",
        "max_calls_per_operation": "1",
        "output_schema_id": "summary-v1",
    }
    values.update(overrides)
    return PluginManifest.create(**values)


def request(**overrides):
    values = {
        "request_id": "req-1",
        "plugin_id": "summary",
        "plugin_version": "1.0.0",
        "workspace_id": "ws-1",
        "actor_id": "user-1",
        "operation_id": "op-1",
        "operation_type": "summarize",
        "capability_token_ref": "cap-1",
        "sensitivity": "private",
        "deadline_at": "2026-07-23T00:00:00Z",
        "correlation_id": "corr-1",
        "payload": {"text": "hello"},
    }
    values.update(overrides)
    return PluginRequest.create(**values)


def token(**overrides):
    values = {
        "token_id": "tok-1",
        "workspace_id": "ws-1",
        "actor_id": "user-1",
        "actions": frozenset({"plugin.invoke:summary", "memory.read"}),
        "max_sensitivity": Sensitivity.PRIVATE,
        "expires_at": "2026-07-23T00:00:00Z",
    }
    values.update(overrides)
    return CapabilityToken(**values)


def response_bytes(req, man, *, output=None, **overrides):
    values = {
        "plugin_response_version": PLUGIN_RESPONSE_VERSION,
        "request_id": req.request_id,
        "plugin_id": man.plugin_id,
        "plugin_version": man.plugin_version,
        "output_schema_id": man.output_schema_id,
        "output": output or {"summary": "ok"},
    }
    values.update(overrides)
    return json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class FakeRunner:
    def __init__(self, behavior="ok", payload=None):
        self.behavior = behavior
        self.payload = payload
        self.calls = []

    def invoke(self, man, request_bytes, timeout_ms):
        self.calls.append((man, request_bytes, timeout_ms))
        if self.behavior == "timeout":
            raise TimeoutError("late")
        if self.behavior == "crash":
            raise RuntimeError("crash")
        if self.behavior == "not-bytes":
            return "bad"
        if self.behavior == "raw":
            return self.payload
        decoded = json.loads(request_bytes)
        req = PluginRequest.from_mapping(decoded)
        return response_bytes(req, man, output=self.payload)


def gateway(runner, *, validators=None, now="2026-07-22T00:00:00Z", quota=None):
    return PluginGateway(
        runner,
        InMemoryPluginOutputValidator(validators or {"summary-v1": lambda value: "summary" in value}),
        quota or InMemoryPluginQuotaStore(),
        now=now,
    )


def test_manifest_id_is_deterministic_and_content_bound():
    first = manifest()
    second = manifest()
    assert first.manifest_id == second.manifest_id
    assert first.plugin_schema_version == PLUGIN_MANIFEST_VERSION
    assert PluginManifest.from_mapping(first.to_mapping()) == first
    with pytest.raises(InvalidContractValue):
        PluginManifest.from_mapping({**first.to_mapping(), "manifest_id": "0" * 64})


def test_manifest_rejects_in_process_mode_and_unsafe_limits():
    with pytest.raises(InvalidContractValue):
        manifest(runner_mode="in_process")
    with pytest.raises(InvalidContractValue):
        manifest(timeout_ms="120001")
    with pytest.raises(InvalidContractValue):
        manifest(max_request_bytes="01")


def test_manifest_strict_parser_rejects_unknown_and_string_sequences():
    mapping = manifest().to_mapping()
    with pytest.raises(UnknownContractField):
        PluginManifest.from_mapping({**mapping, "debug": True})
    with pytest.raises(InvalidContractValue):
        PluginManifest.from_mapping({**mapping, "allowed_operations": "summarize"})


def test_request_strict_parser_and_canonical_payload():
    value = request(payload={"title": "Cafe\u0301"})
    assert value.plugin_request_version == PLUGIN_REQUEST_VERSION
    assert value.payload["title"] == "Café"
    assert PluginRequest.from_mapping(value.to_mapping()) == value
    with pytest.raises(UnknownContractField):
        PluginRequest.from_mapping({**value.to_mapping(), "extra": "x"})
    with pytest.raises(InvalidContractValue):
        request(payload={"count": 1})
    with pytest.raises(InvalidContractValue):
        PluginRequest.from_mapping({**value.to_mapping(), "payload": ["bad"]})


def test_valid_invocation_returns_validated_canonical_output():
    runner = FakeRunner(payload={"summary": "Café"})
    result = gateway(runner).invoke(manifest(), request(), token())
    assert result.status == "ok"
    assert result.output == {"summary": "Café"}
    assert len(result.output_digest) == 64
    assert len(runner.calls) == 1
    assert runner.calls[0][2] == 1000
    assert json.loads(runner.calls[0][1])["plugin_request_version"] == PLUGIN_REQUEST_VERSION


def test_missing_invoke_capability_denies_before_runner():
    runner = FakeRunner()
    result = gateway(runner).invoke(
        manifest(),
        request(),
        token(actions=frozenset({"memory.read"})),
    )
    assert result.status == "rejected"
    assert result.error_code == "plugin_policy_capability_missing"
    assert runner.calls == []


def test_missing_manifest_required_capability_denies_before_runner():
    runner = FakeRunner()
    result = gateway(runner).invoke(
        manifest(required_capabilities=("memory.read", "memory.write")),
        request(),
        token(actions=frozenset({"plugin.invoke:summary", "memory.read"})),
    )
    assert result.error_code == "plugin_capability_missing"
    assert runner.calls == []


def test_workspace_and_sensitivity_policy_are_enforced():
    runner = FakeRunner()
    wrong_workspace = gateway(runner).invoke(manifest(), request(), token(workspace_id="ws-2"))
    assert wrong_workspace.error_code == "plugin_policy_workspace_mismatch"
    too_sensitive = gateway(runner).invoke(
        manifest(egress_class="secret"),
        request(sensitivity="secret"),
        token(max_sensitivity=Sensitivity.PRIVATE),
    )
    assert too_sensitive.error_code == "plugin_policy_sensitivity_exceeded"
    assert runner.calls == []


def test_egress_class_denies_private_or_restricted_payload():
    runner = FakeRunner()
    private_denied = gateway(runner).invoke(
        manifest(egress_class="internal"), request(sensitivity="private"), token()
    )
    assert private_denied.error_code == "plugin_egress_denied"
    no_egress = gateway(runner).invoke(
        manifest(egress_class="none"), request(sensitivity="public"), token()
    )
    assert no_egress.error_code == "plugin_egress_denied"
    assert runner.calls == []


def test_empty_payload_can_use_no_egress_runner():
    runner = FakeRunner()
    result = gateway(runner).invoke(
        manifest(egress_class="none"),
        request(sensitivity="public", payload={}),
        token(max_sensitivity=Sensitivity.PUBLIC),
    )
    assert result.status == "ok"
    assert len(runner.calls) == 1


def test_oversized_request_is_rejected_before_runner():
    runner = FakeRunner()
    result = gateway(runner).invoke(
        manifest(max_request_bytes="10"), request(), token()
    )
    assert result.error_code == "plugin_request_oversized"
    assert runner.calls == []


def test_operation_quota_is_workspace_operation_plugin_scoped():
    runner = FakeRunner()
    quota = InMemoryPluginQuotaStore()
    gate = gateway(runner, quota=quota)
    assert gate.invoke(manifest(), request(), token()).status == "ok"
    second = gate.invoke(manifest(), request(request_id="req-2"), token())
    assert second.error_code == "plugin_quota_exceeded"
    other_operation = gate.invoke(
        manifest(), request(request_id="req-3", operation_id="op-2"), token()
    )
    assert other_operation.status == "ok"
    assert len(runner.calls) == 2


@pytest.mark.parametrize(
    ("behavior", "error_code"),
    [("timeout", "plugin_timeout"), ("crash", "plugin_crashed")],
)
def test_runner_timeout_and_crash_are_isolated(behavior, error_code):
    runner = FakeRunner(behavior)
    result = gateway(runner).invoke(manifest(), request(), token())
    assert result.status == "retry_later"
    assert result.error_code == error_code


def test_non_bytes_and_oversized_response_are_rejected():
    non_bytes = gateway(FakeRunner("not-bytes")).invoke(manifest(), request(), token())
    assert non_bytes.error_code == "plugin_response_not_bytes"
    oversized_runner = FakeRunner("raw", b"x" * 200)
    oversized = gateway(oversized_runner).invoke(
        manifest(max_response_bytes="100"), request(), token()
    )
    assert oversized.error_code == "plugin_response_oversized"


@pytest.mark.parametrize(
    ("payload", "error_code"),
    [
        (b"not-json", "plugin_response_malformed"),
        (json.dumps([]).encode(), "plugin_response_malformed"),
        (json.dumps({"unexpected": "field"}).encode(), "plugin_response_fields_invalid"),
    ],
)
def test_malformed_response_is_fail_closed(payload, error_code):
    result = gateway(FakeRunner("raw", payload)).invoke(manifest(), request(), token())
    assert result.status == "rejected"
    assert result.error_code == error_code


def test_response_version_and_identity_binding_are_checked():
    man = manifest()
    req = request()
    bad_version = response_bytes(req, man, plugin_response_version="plugin-v999")
    assert gateway(FakeRunner("raw", bad_version)).invoke(man, req, token()).error_code == "plugin_response_version_unsupported"
    bad_request = response_bytes(req, man, request_id="other")
    assert gateway(FakeRunner("raw", bad_request)).invoke(man, req, token()).error_code == "plugin_response_binding_mismatch"


def test_output_canonicalization_and_schema_validation_are_enforced():
    man = manifest()
    req = request()
    raw_number = response_bytes(req, man, output={"summary": "ok", "score": 1})
    assert gateway(FakeRunner("raw", raw_number)).invoke(man, req, token()).error_code == "plugin_output_invalid"
    schema_failed = gateway(
        FakeRunner(payload={"wrong": "shape"}),
        validators={"summary-v1": lambda value: "summary" in value},
    ).invoke(man, req, token())
    assert schema_failed.error_code == "plugin_output_schema_failed"


def test_manifest_operation_deadline_and_identity_mismatch_are_rejected():
    runner = FakeRunner()
    assert gateway(runner).invoke(manifest(), request(operation_type="translate"), token()).error_code == "plugin_operation_denied"
    assert gateway(runner, now="2026-07-23T00:00:00Z").invoke(manifest(), request(), token()).error_code == "plugin_deadline_expired"
    assert gateway(runner).invoke(manifest(plugin_version="2.0.0"), request(), token()).error_code == "plugin_manifest_mismatch"
    assert runner.calls == []


def test_plugin_contract_schema_is_strict_and_versioned():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas/phase3/plugin-contracts.schema.json").read_text("utf-8"))
    assert schema["$defs"]["manifest"]["additionalProperties"] is False
    assert schema["$defs"]["request"]["additionalProperties"] is False
    assert schema["$defs"]["response"]["additionalProperties"] is False
    assert schema["$defs"]["manifest"]["properties"]["runner_mode"]["const"] == "out_of_process"


def test_adversarial_report_contains_exactly_20_rounds():
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    text = (root / "docs/adversarial/P3-08_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
    assert rounds == list(range(1, 21))
