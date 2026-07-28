from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path

import jsonschema
import pytest

from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    BitemporalIntervalV2,
    LedgerCommandV2,
    RecallSnapshotRequestV2,
    canonical_ledger_digest,
)
from wiki_spike.memory_core.second_brain_ledger_ports import ValidatedRecallSnapshotAcquisitionV2


def ref(kind: str, n: str = "a") -> str: return f"{kind}:{n * 64}"

def command(kind: str = "CREATE_CANDIDATE") -> dict[str, object]:
    target = None if kind == "CREATE_CANDIDATE" else ref("candidate")
    related = []
    payload = {"candidate_ref": ref("candidate"), "prior_state": "ABSENT", "resulting_state": "PENDING", "content_digest": "c" * 64, "support_edges": [], "contradiction_edges": []}
    if kind in {"REVIEW_APPROVE", "REVIEW_REJECT", "REVOKE", "FORGET"}:
        payload.update(prior_state="PENDING" if kind.startswith("REVIEW") else "APPROVED", resulting_state={"REVIEW_APPROVE":"APPROVED","REVIEW_REJECT":"REJECTED","REVOKE":"REVOKED","FORGET":"FORGOTTEN"}[kind], content_digest=None)
    if kind in {"CORRECT", "SUPERSEDE", "DECLARE_CONTRADICTION"}:
        related = [ref("candidate", "b")]; payload.update(prior_state="APPROVED", resulting_state="APPROVED", content_digest="c" * 64 if kind != "DECLARE_CONTRADICTION" else None)
        edge = {"edge_kind":"SUPPORT" if kind != "DECLARE_CONTRADICTION" else "CONTRADICTION", "from_candidate_ref": ref("candidate", "b") if kind == "CORRECT" else target, "to_candidate_ref": target if kind == "CORRECT" else ref("candidate", "b"), "workspace_ref": ref("workspace"), "interval":{"valid_from":"2026-01-01T00:00:00Z","valid_to":None,"recorded_from":"2026-01-01T00:00:00Z","recorded_to":None}}
        payload["support_edges" if kind != "DECLARE_CONTRADICTION" else "contradiction_edges"] = [edge]
    body = {"command_version":"second-brain-ledger-command-v2","command_ref":ref("command"),"workspace_ref":ref("workspace"),"capability_ref":ref("capability"),"authority_epoch":"1","kind":kind,"target_candidate_ref":target,"related_candidate_refs":related,"interval":{"valid_from":"2026-01-01T00:00:00Z","valid_to":None,"recorded_from":"2026-01-01T00:00:00Z","recorded_to":None},"payload":payload}
    return body | {"command_digest":canonical_ledger_digest("command-v2", body)}

@pytest.mark.parametrize("kind", ["CREATE_CANDIDATE","REVIEW_APPROVE","REVIEW_REJECT","CORRECT","SUPERSEDE","REVOKE","FORGET","DECLARE_CONTRADICTION"])
def test_all_commands_parse(kind: str) -> None: assert LedgerCommandV2.from_mapping(command(kind)).kind == kind

@pytest.mark.parametrize("kind", ["CREATE_CANDIDATE","REVIEW_APPROVE","REVIEW_REJECT","CORRECT","SUPERSEDE","REVOKE","FORGET","DECLARE_CONTRADICTION"])
def test_all_commands_reject_digest_tamper(kind: str) -> None:
    raw = command(kind); raw["command_digest"] = "0" * 64
    with pytest.raises(InvalidContractValue): LedgerCommandV2.from_mapping(raw)

def test_command_is_closed_and_immutable() -> None:
    parsed = LedgerCommandV2.from_mapping(command())
    with pytest.raises(FrozenInstanceError): parsed.payload.candidate_ref = ref("other")  # type: ignore[misc]
    with pytest.raises(UnknownContractField): LedgerCommandV2.from_mapping(command() | {"unknown": True})

@pytest.mark.parametrize("when, expected", [("2026-01-01T00:00:00Z", True), ("2026-01-02T00:00:00Z", False), ("2026-01-01T00:00:00.000000Z", True)])
def test_intervals_compare_instants_not_strings(when: str, expected: bool) -> None:
    interval = BitemporalIntervalV2("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z", None)
    assert interval.contains(when, "2026-01-01T00:00:00Z") is expected

def test_request_rejects_raw_query() -> None:
    body = {"request_version":"second-brain-recall-snapshot-request-v2","workspace_ref":ref("workspace"),"capability_ref":ref("capability"),"authority_epoch":"2","query_digest":"a"*64,"valid_at":"2026-01-01T00:00:00Z","recorded_at":"2026-01-01T00:00:00Z","scope_digest":"b"*64,"continuation":None}
    request = body | {"request_digest":canonical_ledger_digest("request-v2", body)}
    RecallSnapshotRequestV2.from_mapping(request)
    with pytest.raises(UnknownContractField): RecallSnapshotRequestV2.from_mapping(request | {"raw_query":"secret"})
def test_validated_acquisition_has_no_assignable_private_fields() -> None:
    wrapper = object.__new__(ValidatedRecallSnapshotAcquisitionV2)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        wrapper._request = None  # type: ignore[assignment]
    with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
        wrapper.unknown = None  # type: ignore[attr-defined]
def test_command_schema_and_parser_parity_corpus() -> None:
    schema = json.loads((Path(__file__).parents[2] / "schemas/second-brain/ledger-recall-v2.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    for kind in ("CREATE_CANDIDATE", "REVIEW_APPROVE", "REVIEW_REJECT", "CORRECT", "SUPERSEDE", "REVOKE", "FORGET", "DECLARE_CONTRADICTION"):
        wire = command(kind)
        assert not list(validator.iter_errors(wire))
        assert LedgerCommandV2.from_mapping(wire).to_mapping() == wire


def test_command_schema_rejects_unknown_and_kind_branch_wires() -> None:
    schema = json.loads((Path(__file__).parents[2] / "schemas/second-brain/ledger-recall-v2.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)

    unknown = command() | {"unknown": True}
    assert list(validator.iter_errors(unknown))

    invalid_transition = command("REVIEW_APPROVE")
    invalid_transition["payload"]["resulting_state"] = "REJECTED"  # type: ignore[index]
    assert list(validator.iter_errors(invalid_transition))

    invalid_cardinality = command("CORRECT")
    invalid_cardinality["related_candidate_refs"] = []  # type: ignore[index]
    assert list(validator.iter_errors(invalid_cardinality))

    invalid_edge_branch = command("DECLARE_CONTRADICTION")
    invalid_edge_branch["payload"]["contradiction_edges"][0]["edge_kind"] = "SUPPORT"  # type: ignore[index]
    assert list(validator.iter_errors(invalid_edge_branch))


@pytest.mark.parametrize("kind", ["CORRECT", "SUPERSEDE", "DECLARE_CONTRADICTION"])
def test_reversed_directional_edge_is_rejected(kind: str) -> None:
    wire = command(kind)
    edge_key = "contradiction_edges" if kind == "DECLARE_CONTRADICTION" else "support_edges"
    edge = wire["payload"][edge_key][0]  # type: ignore[index]
    edge["from_candidate_ref"], edge["to_candidate_ref"] = edge["to_candidate_ref"], edge["from_candidate_ref"]
    body = {key: value for key, value in wire.items() if key != "command_digest"}
    wire["command_digest"] = canonical_ledger_digest("command-v2", body)
    with pytest.raises(InvalidContractValue, match="direction"):
        LedgerCommandV2.from_mapping(wire)
