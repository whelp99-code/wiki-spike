from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wiki_spike.infrastructure.credential_broker import (
    ConsumedCredentialCapability,
    CredentialDenied,
    FixtureCredentialResolver,
    LocalCredentialBroker,
)

POLICY = json.loads((Path(__file__).parents[1] / "fixtures/second_brain/security/credential-policy-v1.json").read_text())
SECRET = b"fixture-only-secret-not-for-core"
NOW = lambda: datetime(2029, 1, 1, tzinfo=timezone.utc)


def capability(**changes):
    entry = POLICY["credentials"][0]
    values = {
        "capability_ref": "capability:" + "e" * 64,
        "credential_ref": entry["credential_ref"],
        "source_ref": entry["source_ref"],
        "route_ref": entry["route_ref"],
        "credential_class": entry["credential_class"],
        "action": entry["action"],
        "device_key_ref": entry["device_key_ref"],
        "expires_at": entry["expires_at"],
    }
    values.update(changes)
    return ConsumedCredentialCapability(**values)


def broker(consumer=None):
    return LocalCredentialBroker(
        POLICY,
        resolver=FixtureCredentialResolver({POLICY["credentials"][0]["credential_ref"]: SECRET}),
        consumer=consumer or (lambda _lease, _secret: None),
        now=NOW,
    )


@pytest.mark.parametrize("change", [
    {"credential_ref": "credential:" + "f" * 64},
    {"source_ref": "source:" + "f" * 64},
    {"route_ref": "route:" + "f" * 64},
    {"credential_class": "other"},
    {"action": "source.write"},
    {"device_key_ref": "device:" + "f" * 64},
    {"expires_at": "2028-01-01T00:00:00Z"},
])
def test_denies_invalid_or_unresolved_bindings_before_consumer(change):
    calls = []
    with pytest.raises(CredentialDenied):
        broker(lambda *_: calls.append("called")).lease(capability(**change))
    assert calls == []
    disabled = POLICY | {"disabled_credential_refs": [POLICY["credentials"][0]["credential_ref"]]}
    with pytest.raises(CredentialDenied, match="unresolved or disabled"):
        LocalCredentialBroker(disabled, resolver=FixtureCredentialResolver({}), consumer=lambda *_: None, now=NOW).lease(capability())


def test_denies_replay_and_marks_capability_used_when_consumer_errors():
    calls = []
    service = broker(lambda *_: calls.append("called"))
    first = capability()
    service.lease(first)
    with pytest.raises(CredentialDenied, match="replay"):
        service.lease(first)
    failing = broker(lambda *_: (_ for _ in ()).throw(RuntimeError("consumer failure")))
    evidence = capability(capability_ref="capability:" + "9" * 64)
    with pytest.raises(RuntimeError, match="consumer failure"):
        failing.lease(evidence)
    with pytest.raises(CredentialDenied, match="replay"):
        failing.lease(evidence)
    assert calls == ["called"]


def test_secret_only_reaches_low_level_consumer_in_cleared_mutable_buffer():
    received = []
    buffer = []

    def consumer(lease, secret):
        received.append((lease, bytes(secret)))
        buffer.append(secret)

    lease = broker(consumer).lease(capability())
    assert received == [(lease, SECRET)]
    assert isinstance(lease.lease_id, str) and SECRET.decode() not in repr(lease)
    assert bytes(buffer[0]) == b"\0" * len(SECRET)


def test_denies_raw_secret_shaped_capability_fields_before_consumer():
    calls = []
    raw = capability().__dict__ | {"api_key": SECRET.decode()}
    with pytest.raises(CredentialDenied, match="raw credential"):
        broker(lambda *_: calls.append("called")).lease(raw)
    assert calls == []


def test_unavailable_backend_denies_without_source_or_network_fallback():
    with pytest.raises(CredentialDenied, match="backend is unavailable"):
        LocalCredentialBroker(POLICY, now=NOW).lease(capability())
