from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from wiki_spike.memory_core import (
    CONTRACT_VERSION,
    CommandEnvelope,
    InvalidContractValue,
    MemoryCommandPort,
    QueryEnvelope,
    UnknownContractField,
    UnsupportedContractVersion,
    canonical_bytes,
)


def command_mapping(**overrides):
    value = {
        "contract_version": CONTRACT_VERSION,
        "command_id": "cmd-001",
        "idempotency_key": "idem-001",
        "workspace_id": "ws-001",
        "actor_id": "user-001",
        "command_type": "memory.create",
        "expected_generation_id": None,
        "payload": {"title": "Café", "tags": ["회의", "AI"]},
    }
    value.update(overrides)
    return value


def test_command_golden_bytes_are_stable_and_utf8():
    command = CommandEnvelope.from_mapping(command_mapping())
    assert command.canonical_bytes() == (
        b'{"actor_id":"user-001","command_id":"cmd-001",'
        b'"command_type":"memory.create","contract_version":"phase3-core-v1",'
        b'"expected_generation_id":null,"idempotency_key":"idem-001",'
        b'"payload":{"tags":["\xed\x9a\x8c\xec\x9d\x98","AI"],"title":"Caf\xc3\xa9"},'
        b'"workspace_id":"ws-001"}'
    )


def test_nfd_and_nfc_produce_identical_bytes():
    nfc = command_mapping(payload={"title": "Café"})
    nfd = command_mapping(payload={"title": "Cafe\u0301"})
    assert CommandEnvelope.from_mapping(nfc).canonical_bytes() == CommandEnvelope.from_mapping(nfd).canonical_bytes()


def test_unknown_field_is_rejected_fail_closed():
    with pytest.raises(UnknownContractField):
        CommandEnvelope.from_mapping(command_mapping(debug=True))


def test_unknown_version_is_rejected_fail_closed():
    with pytest.raises(UnsupportedContractVersion):
        CommandEnvelope.from_mapping(command_mapping(contract_version="phase3-core-v999"))


@pytest.mark.parametrize("value", [1, 1.0, float("nan")])
def test_raw_numbers_are_rejected(value):
    with pytest.raises(InvalidContractValue):
        CommandEnvelope.from_mapping(command_mapping(payload={"count": value}))


def test_duplicate_key_after_unicode_normalization_is_rejected():
    with pytest.raises(InvalidContractValue):
        canonical_bytes({"é": "one", "e\u0301": "two"})


def test_query_requires_explicit_as_of_generation_and_consistency():
    query = QueryEnvelope.from_mapping({
        "contract_version": CONTRACT_VERSION,
        "query_id": "qry-1",
        "workspace_id": "ws-1",
        "actor_id": "user-1",
        "query_type": "memory.get",
        "as_of_generation_id": "gen-1",
        "consistency": "authoritative",
        "parameters": {"memory_id": "mem-1"},
    })
    assert query.as_of_generation_id == "gen-1"
    with pytest.raises(InvalidContractValue):
        QueryEnvelope.from_mapping({**query.to_mapping(), "consistency": "eventual"})


def test_contract_package_import_does_not_load_storage_modules():
    code = """
import sys
import wiki_spike.memory_core
forbidden = {'wiki_spike.cas','wiki_spike.controlplane','wiki_spike.generation','wiki_spike.publish','wiki_spike.workspace'}
loaded = forbidden.intersection(sys.modules)
assert not loaded, loaded
"""
    subprocess.run([sys.executable, "-c", code], check=True)


def test_protocol_is_runtime_checkable_without_adapter_dependency():
    class Handler:
        def execute(self, command):
            return None

    assert isinstance(Handler(), MemoryCommandPort)


def test_schema_is_strict_and_versioned():
    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas/phase3/core-contracts.schema.json").read_text("utf-8"))
    command = schema["$defs"]["commandEnvelope"]
    query = schema["$defs"]["queryEnvelope"]
    assert command["additionalProperties"] is False
    assert query["additionalProperties"] is False
    assert command["properties"]["contract_version"]["const"] == CONTRACT_VERSION
    assert query["properties"]["consistency"]["enum"] == ["authoritative", "projection_ok"]
