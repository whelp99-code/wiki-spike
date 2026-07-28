from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from test_stage1_capabilities import authority, issued
from wiki_spike.infrastructure.capability_store import CapabilityStore
from wiki_spike.infrastructure.credential_broker import CredentialDenied, FixtureCredentialResolver, LocalCredentialBroker
from wiki_spike.memory_core.second_brain_capabilities import CapabilityDenied, ConsumptionReceipt

POLICY = json.loads((Path(__file__).parents[1] / "fixtures/second_brain/security/credential-policy-v1.json").read_text())
SECRET = b"fixture-only-secret-not-for-core"
NOW = lambda: datetime(2029, 1, 1, tzinfo=timezone.utc)


def receipt(*, store=None, action=None, credential_ref=None):
    issued_store, _, request, service, grant = issued()
    store = store or issued_store
    entry = POLICY["credentials"][0]
    return service.consume_for_credential(authority(), grant.capability_ref, request.request_digest, "nonce", credential_ref=credential_ref or entry["credential_ref"], action=action or entry["action"]), issued_store


def broker(store, consumer=None):
    return LocalCredentialBroker(POLICY, capability_store=store, resolver=FixtureCredentialResolver({POLICY["credentials"][0]["credential_ref"]: bytearray(SECRET)}), consumer=consumer or (lambda _lease, _secret: None), now=NOW)


def test_redeems_only_store_minted_exact_receipt_once():
    evidence, store = receipt()
    lease = broker(store).lease(evidence)
    assert lease.credential_ref == POLICY["credentials"][0]["credential_ref"]
    with pytest.raises(CredentialDenied, match="replay"):
        broker(store).lease(evidence)
    with pytest.raises(CredentialDenied):
        broker(store).lease({})  # type: ignore[arg-type]
    with pytest.raises(CapabilityDenied):
        ConsumptionReceipt(object(), "token")  # type: ignore[arg-type]
    with pytest.raises(AttributeError):
        evidence.credential_ref = "credential:forged"  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        evidence._redeemed = False  # type: ignore[attr-defined]


def test_rejects_cross_store_and_out_of_scope_bindings_before_consumer():
    evidence, source_store = receipt()
    calls = []
    with pytest.raises(CredentialDenied, match="cross-store"):
        broker(CapabilityStore(), lambda *_: calls.append(True)).lease(evidence)
    assert calls == []
    with pytest.raises(CapabilityDenied, match="out of scope"):
        receipt(action="source.write")
    with pytest.raises(CapabilityDenied, match="out of scope"):
        receipt(credential_ref="credential:" + "b" * 64)


def test_fixture_secret_is_mutable_and_zeroized_after_truthful_one_shot_lifetime():
    evidence, store = receipt()
    buffers, received = [], []
    def consumer(lease, secret):
        buffers.append(secret)
        received.append((lease, bytes(secret)))
    lease = broker(store, consumer).lease(evidence)
    assert received == [(lease, SECRET)]
    assert bytes(buffers[0]) == b"\0" * len(SECRET)


def test_unavailable_backend_and_disabled_policy_deny():
    evidence, store = receipt()
    with pytest.raises(CredentialDenied, match="backend is unavailable"):
        LocalCredentialBroker(POLICY, capability_store=store, now=NOW).lease(evidence)
    evidence, store = receipt()
    disabled = POLICY | {"disabled_credential_refs": [POLICY["credentials"][0]["credential_ref"]]}
    with pytest.raises(CredentialDenied, match="unresolved or disabled"):
        LocalCredentialBroker(disabled, capability_store=store, resolver=FixtureCredentialResolver({}), consumer=lambda *_: None, now=NOW).lease(evidence)
