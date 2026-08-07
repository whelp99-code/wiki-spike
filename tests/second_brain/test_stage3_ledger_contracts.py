from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path

import jsonschema
import pytest

from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    AuthorityProvenanceV2,
    BitemporalIntervalV2,
    CitationEvidenceV2,
    ConflictDecisionV2,
    GateStateV2,
    LedgerCommandV2,
    RecallSnapshotRequestV2,
    canonical_ledger_digest,
    make_recall_continuation_v2,
    make_recall_snapshot_v2,
    validate_recall_snapshot_acquisition,
    validate_ledger_recall_v2_semantics,
)
from wiki_spike.memory_core.second_brain_ledger_ports import ValidatedRecallSnapshotAcquisitionV2
from wiki_spike.applications.second_brain_recall_service import convert_validated_recall_snapshot


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
    body = {"command_version":"second-brain-ledger-command-v2","command_ref":ref("command"),"workspace_ref":ref("workspace"),"capability_ref":ref("capability"),"authority_epoch":"1","subject_ref":ref("subject"),"action":"WRITE","scope_digest":"e"*64,"kind":kind,"target_candidate_ref":target,"expected_active_revision_ref":None if kind == "CREATE_CANDIDATE" else ref("revision"),"related_candidate_refs":related,"interval":{"valid_from":"2026-01-01T00:00:00Z","valid_to":None,"recorded_from":"2026-01-01T00:00:00Z","recorded_to":None},"payload":payload,"command_payload_digest":canonical_ledger_digest("command-payload-v2", payload),"authority_provenance_ref":ref("provenance"),"authority_provenance_digest":"d"*64}
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
    body = {"request_version":"second-brain-recall-snapshot-request-v2","workspace_ref":ref("workspace"),"capability_ref":ref("capability"),"authority_epoch":"2","subject_ref":ref("subject"),"action":"RECALL","query_digest":"a"*64,"valid_at":"2026-01-01T00:00:00Z","recorded_at":"2026-01-01T00:00:00Z","scope_digest":"b"*64,"transaction_cut":"1","authority_provenance_ref":ref("provenance"),"authority_provenance_digest":"c"*64,"continuation":None}
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
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    for kind in ("CREATE_CANDIDATE", "REVIEW_APPROVE", "REVIEW_REJECT", "CORRECT", "SUPERSEDE", "REVOKE", "FORGET", "DECLARE_CONTRADICTION"):
        wire = command(kind)
        assert not list(validator.iter_errors(wire))
        assert LedgerCommandV2.from_mapping(wire).to_mapping() == wire
        assert validate_ledger_recall_v2_semantics(wire).to_mapping() == wire


def test_command_schema_rejects_unknown_and_kind_branch_wires() -> None:
    schema = json.loads((Path(__file__).parents[2] / "schemas/second-brain/ledger-recall-v2.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())

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
    wire["command_payload_digest"] = canonical_ledger_digest("command-payload-v2", wire["payload"])  # type: ignore[arg-type]
    body = {key: value for key, value in wire.items() if key != "command_digest"}
    wire["command_digest"] = canonical_ledger_digest("command-v2", body)
    with pytest.raises(InvalidContractValue, match="direction"):
        LedgerCommandV2.from_mapping(wire)
def test_command_requires_revision_and_digest_binds_it() -> None:
    wire = command("REVIEW_APPROVE")
    wire["expected_active_revision_ref"] = None
    wire["command_digest"] = canonical_ledger_digest("command-v2", {k: v for k, v in wire.items() if k != "command_digest"})
    with pytest.raises(InvalidContractValue, match="expected_active_revision_ref"):
        LedgerCommandV2.from_mapping(wire)

def provenance() -> dict[str, object]:
    body = {"provenance_version":"second-brain-authority-provenance-v2","provenance_ref":ref("provenance"),"signer_ref":ref("signer"),"signer_algorithm":"Ed25519","key_id":ref("key"),"component_labels":["authorization","global_floor","binding","recovery","route","cohort","deletion","consent"],"component_states":[{"state":"PASS","epoch":str(index + 1),"digest":f"{index + 1:064x}"} for index in range(8)],"transaction_cut":"1","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z","workspace_ref":ref("workspace"),"capability_ref":ref("capability"),"authority_epoch":"1","subject_ref":ref("subject"),"action":"WRITE","query_digest":None,"scope_digest":"e"*64,"request_digest":None,"command_payload_digest":"f"*64}
    return body | {"provenance_digest":canonical_ledger_digest("authority-provenance-v2", body),"signature":"store-issued-signature"}

def test_provenance_expiry_is_current_time_checked_and_digest_alone_is_not_authority() -> None:
    evidence = AuthorityProvenanceV2.from_mapping(provenance())
    evidence.validate_at("2026-01-01T12:00:00Z")
    with pytest.raises(InvalidContractValue, match="currently valid"):
        evidence.validate_at("2026-01-02T00:00:00Z")
def test_citation_evidence_and_conflict_decision_are_top_level_wires() -> None:
    schema = json.loads((Path(__file__).parents[2] / "schemas/second-brain/ledger-recall-v2.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    citation_body = {"evidence_version":"second-brain-citation-evidence-v2","locator_ref":ref("locator"),"locator_digest":"a"*64,"immutable_source_ref":ref("source"),"revision_ref":ref("revision")}
    citation = citation_body | {"evidence_digest":canonical_ledger_digest("citation-evidence-v2", citation_body)}
    decision_body = {"decision_version":"second-brain-conflict-decision-v2","left_candidate_ref":ref("candidate", "a"),"right_candidate_ref":ref("candidate", "b"),"state":"RESOLVED","winning_candidate_ref":ref("candidate", "a"),"expected_decision_revision_ref":ref("revision"),"authority_provenance_ref":ref("provenance"),"authority_provenance_digest":"b"*64,"winning_revision_citation":citation}
    decision = decision_body | {"decision_digest":canonical_ledger_digest("conflict-decision-v2", decision_body)}
    assert not list(validator.iter_errors(citation))
    assert not list(validator.iter_errors(decision))
    provenance_wire = provenance()
    assert not list(validator.iter_errors(provenance_wire))
    assert validate_ledger_recall_v2_semantics(provenance_wire).to_mapping() == provenance_wire
    assert CitationEvidenceV2.from_mapping(citation).to_mapping() == citation
    assert ConflictDecisionV2.from_mapping(decision).to_mapping() == decision
    assert validate_ledger_recall_v2_semantics(citation).to_mapping() == citation
    assert validate_ledger_recall_v2_semantics(decision).to_mapping() == decision
    forged_time = {"request_version":"second-brain-recall-snapshot-request-v2","workspace_ref":ref("workspace"),"capability_ref":ref("capability"),"authority_epoch":"2","subject_ref":ref("subject"),"action":"RECALL","query_digest":"a"*64,"valid_at":"2026-01-01T00:00:00","recorded_at":"2026-01-01T00:00:00Z","scope_digest":"b"*64,"transaction_cut":"1","authority_provenance_ref":ref("provenance"),"authority_provenance_digest":"c"*64,"continuation":None,"request_digest":"d"*64}
    assert list(validator.iter_errors(forged_time))
def test_acquisition_contract_requires_independent_verifier_and_trusted_time() -> None:
    import inspect
    from wiki_spike.memory_core.second_brain_ledger_contracts import validate_recall_snapshot_acquisition

    signature = inspect.signature(validate_recall_snapshot_acquisition)
    assert tuple(signature.parameters) == ("request", "result", "authority")
    assert all(parameter.default is inspect.Parameter.empty for parameter in signature.parameters.values())
def request_wire(continuation: dict[str, object] | None = None) -> dict[str, object]:
    body = {"request_version":"second-brain-recall-snapshot-request-v2","workspace_ref":ref("workspace"),"capability_ref":ref("capability"),"authority_epoch":"1","subject_ref":ref("subject"),"action":"RECALL","query_digest":"a"*64,"valid_at":"2026-01-01T00:00:00Z","recorded_at":"2026-01-01T00:00:00Z","scope_digest":"b"*64,"transaction_cut":"1","authority_provenance_ref":ref("provenance"),"authority_provenance_digest":"c"*64,"continuation":continuation}
    return body | {"request_digest":canonical_ledger_digest("request-v2", body)}

def snapshot_body() -> dict[str, object]:
    gate = {"state":"PASS","epoch":"1","digest":"d"*64}
    return {"snapshot_version":"second-brain-recall-serve-snapshot-v2","snapshot_attestation_version":"second-brain-recall-snapshot-attestation-v2","snapshot_signer_ref":ref("signer"),"snapshot_signer_algorithm":"Ed25519","snapshot_key_id":ref("key"),"snapshot_signature":"signed","provenance_component_labels":["authorization","global_floor","binding","recovery","route","cohort","deletion","consent"],"provenance_component_states":[gate] * 8,"has_more":False,"workspace_ref":ref("workspace"),"capability_ref":ref("capability"),"authority_epoch":"1","subject_ref":ref("subject"),"action":"RECALL","query_digest":"a"*64,"transaction_cut":"1","valid_at":"2026-01-01T00:00:00Z","recorded_at":"2026-01-01T00:00:00Z","scope_digest":"b"*64,"authority_provenance_ref":ref("provenance"),"authority_provenance_digest":"c"*64,"generation_ref":ref("generation"),"generation_digest":"e"*64,"checkpoint_ref":ref("checkpoint"),"checkpoint_digest":"f"*64,"freshness_digest":"0"*64,"authority_checkpoint_digest":"1"*64,"authorization":{"decision":"ALLOW","capability_ref":ref("capability"),"authority_epoch":"1","query_digest":"a"*64,"workspace_ref":ref("workspace"),"scope_digest":"b"*64},"global_floor":gate,"binding":gate,"recovery":gate,"route":gate,"cohort":gate,"deletion":gate,"consent":gate,"projection_digest":"2"*64,"contract_digest":"3"*64,"base_snapshot_digest":None,"cursor_state_digest":None,"incoming_cursor_digest":None,"incoming_continuation_ref":None,"candidates":[],"conflicts":[],"citations":[],"continuation":None}
def test_service_snapshot_preserves_bound_unverified_conflict_marker() -> None:
    candidate = ref("candidate")
    withheld = ref("candidate", "b")
    revision = ref("revision")
    evidence_body = {
        "evidence_version": "second-brain-citation-evidence-v2",
        "locator_ref": ref("locator"),
        "locator_digest": "1" * 64,
        "immutable_source_ref": ref("source"),
        "revision_ref": revision,
    }
    evidence = dict(evidence_body)
    evidence["evidence_digest"] = canonical_ledger_digest("citation-evidence-v2", evidence_body)
    citation_body = {
        "citation_version": "second-brain-recall-citation-v2",
        "candidate_ref": candidate,
        "evidence": evidence,
    }
    body = snapshot_body() | {
        "candidates": [{"candidate_ref": candidate, "revision_ref": revision, "state": "APPROVED", "content_digest": "4" * 64, "support_refs": []}],
        "citations": [{"citation_version": "second-brain-recall-citation-v2", "candidate_ref": candidate, "evidence": evidence, "citation_digest": canonical_ledger_digest("citation-v2", citation_body)}],
        "unverified_conflicts": [[candidate, withheld]],
    }
    result = make_recall_snapshot_v2(body)
    assert result.unverified_conflicts == ((candidate, withheld),)
    assert result.to_mapping()["unverified_conflicts"] == [[candidate, withheld]]
    acquisition = object.__new__(ValidatedRecallSnapshotAcquisitionV2)
    object.__setattr__(acquisition, "_request", RecallSnapshotRequestV2.from_mapping(request_wire()))
    object.__setattr__(acquisition, "_snapshot", result)
    converted, _ = convert_validated_recall_snapshot(acquisition)
    assert converted.unverified_conflicts == ((candidate, withheld),)

class Verifier:
    def __init__(self, snapshot_ok: bool = True, continuation_ok: bool = True) -> None:
        self.snapshot_ok = snapshot_ok
        self.continuation_ok = continuation_ok

    def trusted_now(self) -> str: return "2026-01-01T12:00:00Z"
    def verify_authority_provenance(self, provenance: object) -> bool: return self.snapshot_ok
    def verify_snapshot_authority(self, request: object, result: object) -> bool: return self.snapshot_ok
    def verify_continuation(self, continuation: object) -> bool: return self.continuation_ok

def test_acquisition_rejects_absent_or_forged_verifier_despite_allow_pass_snapshot() -> None:
    request = RecallSnapshotRequestV2.from_mapping(request_wire())
    result = make_recall_snapshot_v2(snapshot_body())
    with pytest.raises(InvalidContractValue, match="minted RecallTrustAuthorityV2"):
        validate_recall_snapshot_acquisition(request, result, None)  # type: ignore[arg-type]

def test_acquisition_rejects_first_page_chain_injection() -> None:
    request = RecallSnapshotRequestV2.from_mapping(request_wire())
    body = snapshot_body()
    body.update(base_snapshot_digest="4"*64, cursor_state_digest="6"*64, incoming_cursor_digest="5"*64, incoming_continuation_ref=ref("continuation"))
    with pytest.raises(InvalidContractValue, match="minted RecallTrustAuthorityV2"):
        validate_recall_snapshot_acquisition(request, make_recall_snapshot_v2(body), None)  # type: ignore[arg-type]

def test_acquisition_rejects_signed_continuation_when_verification_fails() -> None:
    continuation_body = {"continuation_version":"second-brain-recall-continuation-v2","continuation_ref":ref("continuation"),"workspace_ref":ref("workspace"),"capability_ref":ref("capability"),"authority_epoch":"1","subject_ref":ref("subject"),"action":"RECALL","query_digest":"a"*64,"scope_digest":"b"*64,"valid_at":"2026-01-01T00:00:00Z","recorded_at":"2026-01-01T00:00:00Z","transaction_cut":"1","authority_provenance_ref":ref("provenance"),"authority_provenance_digest":"c"*64,"signer_ref":ref("signer"),"signer_algorithm":"Ed25519","key_id":ref("key"),"signature":"signed","generation_ref":ref("generation"),"generation_digest":"e"*64,"checkpoint_ref":ref("checkpoint"),"checkpoint_digest":"f"*64,"freshness_digest":"0"*64,"authority_checkpoint_digest":"1"*64,"authority_commitment_digest":"2"*64,"base_snapshot_digest":"3"*64,"cursor_handle_ref":ref("cursor"),"cursor_state_digest":"4"*64,"issued_at":"2026-01-01T12:00:00Z","expires_at":"2026-01-01T12:04:00Z"}
    continuation = make_recall_continuation_v2(continuation_body)
    request = RecallSnapshotRequestV2.from_mapping(request_wire(continuation.to_mapping()))
    with pytest.raises(InvalidContractValue, match="minted RecallTrustAuthorityV2"):
        validate_recall_snapshot_acquisition(request, make_recall_snapshot_v2(snapshot_body()), None)  # type: ignore[arg-type]


def test_citation_wrapper_digest_binds_outer_body() -> None:
    evidence = {"evidence_version":"second-brain-citation-evidence-v2","locator_ref":ref("locator"),"locator_digest":"a"*64,"immutable_source_ref":ref("source"),"revision_ref":ref("revision")}
    evidence["evidence_digest"] = canonical_ledger_digest("citation-evidence-v2", evidence)
    citation = {"citation_version":"second-brain-recall-citation-v2","candidate_ref":ref("candidate"),"evidence":evidence}
    citation["citation_digest"] = canonical_ledger_digest("citation-v2", citation)
    assert validate_ledger_recall_v2_semantics(citation).citation_digest == citation["citation_digest"]
    citation["candidate_ref"] = ref("candidate", "b")
    with pytest.raises(InvalidContractValue): validate_ledger_recall_v2_semantics(citation)
