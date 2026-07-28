from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import socket
import urllib.request
from pathlib import Path

import pytest

from wiki_spike.connectors.claude_memory_bank import ClaudeMemoryBankFixtureConnector
from wiki_spike.connectors.codex import CodexFixtureConnector
from wiki_spike.connectors.git import GitFixtureConnector
from wiki_spike.connectors.markdown import MarkdownFixtureConnector
from wiki_spike.memory_core.second_brain_capture_contracts import (
    EncryptedContentRefV1,
    EncryptedNativeMappingRefV1,
    SourceScopeRefV1,
)


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


class ContentSealer:
    def __init__(self) -> None:
        self.sealed: list[tuple[str, str, bytes]] = []

    def seal_content(self, scope, capture_ref: str, ciphertext: bytes) -> EncryptedContentRefV1:
        self.sealed.append((scope.scope_ref, capture_ref, ciphertext))
        return EncryptedContentRefV1(
            capture_ref,
            f"encrypted-content:{sha256(ciphertext).hexdigest()}",
        )


class NativeMappingSealer:
    def __init__(self) -> None:
        self.sealed: list[tuple[str, str, bytes]] = []

    def seal_native_mapping(
        self, scope, capture_ref: str, native_mapping: bytes,
    ) -> EncryptedNativeMappingRefV1:
        self.sealed.append((scope.scope_ref, capture_ref, native_mapping))
        return EncryptedNativeMappingRefV1(
            capture_ref,
            f"encrypted-native-mapping:{sha256(capture_ref.encode()).hexdigest()}",
        )


def fixture(name: str, *, scope_epoch: str = "1") -> tuple[str, bytes, dict[str, object]]:
    value = json.loads((FIXTURES / name).read_text())
    value["scope_epoch"] = scope_epoch
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


def encrypted_native_mapping_ref(capture_ref: str) -> str:
    return f"encrypted-native-mapping:{sha256(capture_ref.encode()).hexdigest()}"




@pytest.mark.parametrize(("fixture_name", "connector_type", "profile", "domain"), CONNECTORS)
def test_typed_fixture_connector_maps_exact_profile_deterministically(
    fixture_name, connector_type, profile, domain,
):
    request_ref, payload, value = fixture(fixture_name)
    source_scope = scope(profile, domain)
    client = FixtureClient({request_ref: payload})
    sealer = NativeMappingSealer()
    connector = connector_type(client, ContentSealer(), sealer, [request_ref])

    first = connector.read_fixture_capture_items(source_scope, "1")
    second = connector.read_fixture_capture_items(source_scope, "1")

    expected_capture_ref = value["capture_ref"]
    expected_ciphertext = base64.b64decode(value["ciphertext_b64"])
    assert first == second
    assert tuple(
        (
            item.capture_ref,
            item.ciphertext,
            item.encrypted_content_ref,
            item.encrypted_native_mapping_ref,
        )
        for item in first
    ) == ((
        expected_capture_ref,
        expected_ciphertext,
        f"encrypted-content:{sha256(expected_ciphertext).hexdigest()}",
        encrypted_native_mapping_ref(expected_capture_ref),
    ),)
    with pytest.raises(FrozenInstanceError):
        first[0].ciphertext = b"swapped"
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
    connector = connector_type(FixtureClient({request_ref: payload}), ContentSealer(), NativeMappingSealer(), [request_ref])

    malformed_capture_ref = dict(value)
    del malformed_capture_ref["capture_ref"]
    forged_encrypted_content_ref = dict(value, encrypted_content_ref=REF("forged-content"))
    wrong_source = dict(value, source_domain="git" if domain != "git" else "markdown")
    for candidate in (
        malformed_capture_ref,
        forged_encrypted_content_ref,
        wrong_source,
    ):
        bad = json.dumps(candidate).encode()
        connector = connector_type(FixtureClient({request_ref: bad}), ContentSealer(), NativeMappingSealer(), [request_ref])
        with pytest.raises(ValueError):
            connector.read_fixture_capture_items(source_scope, "1")
    with pytest.raises(ValueError):
        connector.read_fixture_capture_items(scope("Git", "git"), "1")


@pytest.mark.parametrize(("fixture_name", "connector_type", "profile", "domain"), CONNECTORS)
def test_connector_is_bounded_fixture_only_and_retains_no_raw_mapping(
    monkeypatch, fixture_name, connector_type, profile, domain,
):
    request_ref, payload, _ = fixture(fixture_name)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("fixture connector attempted live I/O")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    connector = connector_type(FixtureClient({request_ref: payload}), ContentSealer(), NativeMappingSealer(), [request_ref])
    items = connector.read_fixture_capture_items(scope(profile, domain), "1")
    assert items
    assert set(vars(connector)) == {"_fixture_client", "_content_sealer", "_native_mapping_sealer", "_fixture_request_refs"}

    refs = [f"fixture:{index:064x}" for index in range(1025)]
    with pytest.raises(ValueError):
        connector_type(FixtureClient({}), ContentSealer(), NativeMappingSealer(), refs)

@pytest.mark.parametrize(("fixture_name", "connector_type", "profile", "domain"), CONNECTORS)
def test_connector_rejects_swapped_ciphertext_native_mapping_identity(
    fixture_name, connector_type, profile, domain,
):
    request_ref, payload, value = fixture(fixture_name)
    second_ref = REF("second-fixture-request")
    second_value = dict(value)
    second_value["capture_ref"] = f"capture:{'b' * 64}"
    second_value["ciphertext_b64"] = base64.b64encode(b"other-ciphertext").decode()
    second_value["native_mapping"] = {"native": "other"}
    second_payload = json.dumps(second_value, sort_keys=True).encode()

    class SwappedIdentitySealer(NativeMappingSealer):
        def seal_native_mapping(
            self, source_scope, capture_ref: str, native_mapping: bytes,
        ) -> EncryptedNativeMappingRefV1:
            super().seal_native_mapping(source_scope, capture_ref, native_mapping)
            other_capture_ref = (
                second_value["capture_ref"]
                if capture_ref == value["capture_ref"]
                else value["capture_ref"]
            )
            return EncryptedNativeMappingRefV1(
                other_capture_ref,
                encrypted_native_mapping_ref(other_capture_ref),
            )

    connector = connector_type(
        FixtureClient({request_ref: payload, second_ref: second_payload}),
        ContentSealer(),
        SwappedIdentitySealer(),
        [request_ref, second_ref],
    )

    with pytest.raises(ValueError, match="exact capture-bound"):
        connector.read_fixture_capture_items(scope(profile, domain), "1")

@pytest.mark.parametrize(("fixture_name", "connector_type", "profile", "domain"), CONNECTORS)
def test_connector_rejects_changed_scope_epoch_with_every_other_fixture_field_unchanged(
    fixture_name, connector_type, profile, domain,
):
    request_ref, payload, _ = fixture(fixture_name, scope_epoch="2")
    connector = connector_type(FixtureClient({request_ref: payload}), ContentSealer(), NativeMappingSealer(), [request_ref])

    with pytest.raises(ValueError, match="scope and epochs"):
        connector.read_fixture_capture_items(scope(profile, domain), "1")
