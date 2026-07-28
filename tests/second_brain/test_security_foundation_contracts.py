from __future__ import annotations

import json
from pathlib import Path

import pytest

from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.second_brain_security_contracts import (
    CapabilityRequestV1,
    DeviceEnrollmentV1,
    EgressPolicyV1,
    invoke_with_resolved_security_context,
)

D = "a" * 64
R = f"fixture:{D}"


def capability_request() -> dict[str, object]:
    return {"security_version":"second-brain-security-foundation-v1","request_ref":R,"capability_ref":R,"subject_key_ref":R,"scope_refs":[R],"requested_at":"2026-07-28T00:00:00Z","request_digest":D}


def test_strict_wire_contract_rejects_unknown_raw_number_and_raw_identifier():
    raw = capability_request()
    assert CapabilityRequestV1.from_mapping(raw).scope_refs == (R,)
    raw["prompt"] = "activate this"  # raw prompt/body fields are never wire-safe
    with pytest.raises(UnknownContractField): CapabilityRequestV1.from_mapping(raw)
    raw = capability_request(); raw["request_ref"] = "human-readable-id"
    with pytest.raises(InvalidContractValue, match="keyed digest"): CapabilityRequestV1.from_mapping(raw)
    lease = {"security_version":"second-brain-security-foundation-v1","lease_request_ref":R,"credential_ref":R,"capability_receipt_ref":R,"lease_duration_seconds":60,"requested_at":"2026-07-28T00:00:00Z","request_digest":D}
    from wiki_spike.memory_core.second_brain_security_contracts import CredentialLeaseRequestV1
    with pytest.raises(InvalidContractValue): CredentialLeaseRequestV1.from_mapping(lease)


def test_expired_security_record_and_unordered_scope_list_fail_closed():
    raw = {"security_version":"second-brain-security-foundation-v1","enrollment_ref":R,"device_key_ref":R,"trust_root_ref":R,"enrolled_at":"2026-07-28T00:00:00Z","expires_at":"2026-07-28T00:00:01Z","enrollment_digest":D}
    with pytest.raises(InvalidContractValue, match="expired"): DeviceEnrollmentV1.from_mapping(raw, now=__import__("datetime").datetime(2026, 7, 29, tzinfo=__import__("datetime").timezone.utc))
    policy = {"security_version":"second-brain-security-foundation-v1","policy_ref":R,"policy_revision":"1","destination_ref":R,"allowed_scope_refs":[f"z:{D}", R],"policy_digest":D}
    with pytest.raises(InvalidContractValue, match="sorted"): EgressPolicyV1.from_mapping(policy)


def test_unresolved_context_denies_before_test_port_invocation():
    called = False
    def port() -> None:
        nonlocal called
        called = True
    with pytest.raises(InvalidContractValue, match="RESOLVED"):
        invoke_with_resolved_security_context(port, None, None, None)
    assert not called


def test_schema_is_closed_and_uses_only_wire_safe_refs_and_decimal_strings():
    schema = json.loads((Path(__file__).parents[2] / "schemas/second-brain/security-foundation-v1.schema.json").read_text())
    assert schema["$defs"]["ref"]["pattern"] == "^[a-z][a-z0-9_-]{0,63}:[0-9a-f]{64}$"
    assert schema["$defs"]["decimal"]["type"] == "string"
    assert schema["$defs"]["CapabilityRequestV1"]["additionalProperties"] is False
