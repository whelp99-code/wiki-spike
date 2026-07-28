from __future__ import annotations

import base64
import json
import socket
import urllib.request
from pathlib import Path

import pytest

from wiki_spike.connectors.claude_memory_bank import ClaudeMemoryBankFixtureConnector
from wiki_spike.connectors.codex import CodexFixtureConnector
from wiki_spike.connectors.git import GitFixtureConnector
from wiki_spike.connectors.markdown import MarkdownFixtureConnector
from wiki_spike.memory_core.second_brain_capture_contracts import SourceScopeRefV1


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "second_brain" / "capture"
REF = lambda key: f"{key}:{'a' * 64}"
CONNECTORS = (
    ("codex.json", CodexFixtureConnector, "Codex", "codex"),
    ("claude_memory_bank.json", ClaudeMemoryBankFixtureConnector, "Claude/Memory Bank", "claude-memory-bank"),
    ("git.json", GitFixtureConnector, "Git", "git"),
    ("markdown.json", MarkdownFixtureConnector, "Markdown", "markdown"),
)
DISPOSITIONS = ["ACCEPTED", "DUPLICATE", "TOMBSTONE", "SKIPPED", "QUARANTINED"]


class FixtureClient:
    def __init__(self, payloads: dict[str, bytes]) -> None:
        self.payloads = payloads
        self.requests: list[str] = []

    def read_fixture_payload(self, request_ref: str) -> bytes:
        self.requests.append(request_ref)
        return self.payloads[request_ref]


class NativeMappingSealer:
    def __init__(self) -> None:
        self.sealed: list[tuple[str, str, bytes]] = []

    def seal_native_mapping(self, scope, capture_ref: str, native_mapping: bytes) -> str:
        self.sealed.append((scope.scope_ref, capture_ref, native_mapping))
        return REF("sealed-native-mapping")


def fixture(name: str) -> tuple[str, bytes, dict[str, object]]:
    value = json.loads((FIXTURES / name).read_text())
    return REF("fixture-request"), json.dumps(value, sort_keys=True).encode(), value


def scope(profile: str, domain: str) -> SourceScopeRefV1:
    return SourceScopeRefV1.from_mapping({
        "scope_version": "second-brain-source-scope-ref-v1",
        "source_profile": profile,
        "source_domain": domain,
        "source_ref": REF(f"{domain}-source"),
        "workspace_ref": REF("workspace"),
        "scope_ref": REF(f"{domain}-scope"),
        "scope_epoch": "1",
    })


@pytest.mark.parametrize(("fixture_name", "connector_type", "profile", "domain"), CONNECTORS)
def test_typed_fixture_connector_maps_exact_profile_deterministically(
    fixture_name, connector_type, profile, domain,
):
    request_ref, payload, value = fixture(fixture_name)
    source_scope = scope(profile, domain)
    client = FixtureClient({request_ref: payload})
    sealer = NativeMappingSealer()
    connector = connector_type(client, sealer, [request_ref])

    first = connector.read_fixture_ciphertexts(source_scope, "1")
    second = connector.read_fixture_ciphertexts(source_scope, "1")

    assert first == second
    assert first == (base64.b64decode(json.loads(payload)["ciphertext_b64"]),)
    assert client.requests == [request_ref, request_ref]
    assert [json.loads(native) for _, _, native in sealer.sealed] == [
        value["native_mapping"], value["native_mapping"],
    ]
    assert value["native_mapping"]["dispositions"] == DISPOSITIONS


@pytest.mark.parametrize(("fixture_name", "connector_type", "profile", "domain"), CONNECTORS)
def test_connector_rejects_malformed_wrong_source_and_bad_scope(
    fixture_name, connector_type, profile, domain,
):
    request_ref, payload, value = fixture(fixture_name)
    source_scope = scope(profile, domain)
    connector = connector_type(FixtureClient({request_ref: payload}), NativeMappingSealer(), [request_ref])

    malformed = dict(value)
    del malformed["capture_ref"]
    wrong_source = dict(value, source_domain="git" if domain != "git" else "markdown")
    for candidate in (malformed, wrong_source):
        bad = json.dumps(candidate).encode()
        connector = connector_type(FixtureClient({request_ref: bad}), NativeMappingSealer(), [request_ref])
        with pytest.raises(ValueError):
            connector.read_fixture_ciphertexts(source_scope, "1")
    with pytest.raises(ValueError):
        connector.read_fixture_ciphertexts(scope("Git", "git"), "1")


@pytest.mark.parametrize(("fixture_name", "connector_type", "profile", "domain"), CONNECTORS)
def test_connector_is_bounded_fixture_only_and_retains_no_raw_mapping(
    monkeypatch, fixture_name, connector_type, profile, domain,
):
    request_ref, payload, _ = fixture(fixture_name)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("fixture connector attempted live I/O")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    connector = connector_type(FixtureClient({request_ref: payload}), NativeMappingSealer(), [request_ref])
    ciphertexts = connector.read_fixture_ciphertexts(scope(profile, domain), "1")
    assert ciphertexts
    assert set(vars(connector)) == {"_fixture_client", "_native_mapping_sealer", "_fixture_request_refs"}

    refs = [f"fixture:{index:064x}" for index in range(1025)]
    with pytest.raises(ValueError):
        connector_type(FixtureClient({}), NativeMappingSealer(), refs)
