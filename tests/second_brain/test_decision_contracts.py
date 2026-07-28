from __future__ import annotations

from base64 import b64encode
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_SIGNING_DOMAIN, CONTRACT_SIGNATURE_VERSION, DECISION_SIGNING_DOMAIN,
    DECISION_SIGNATURE_VERSION, DecisionRecordV1, ExpectedScopeManifestV1,
    ResolvedScopeV1, SignedSecondBrainContractEnvelopeV1,
    TrustedAuthorityBindingsV1, TrustedDecisionKeyBindingsV1, detached_signing_bytes,
    resolve_second_brain_contract,
)

DIGEST, FUTURE = "a" * 64, "2030-01-01T00:00:00Z"
OWNER, APPROVER = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()

def _public(key: Ed25519PrivateKey) -> str:
    return b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

AUTHORITY = TrustedAuthorityBindingsV1("approver", _public(APPROVER), "owner", _public(OWNER))
TRUSTED = TrustedDecisionKeyBindingsV1({("DB-01", "global", None): AUTHORITY, ("DB-04", "global", None): AUTHORITY, ("DB-05", "global", None): AUTHORITY, ("DB-07", "global", None): AUTHORITY, ("DB-02", "source_profile", "Claude/Memory Bank"): AUTHORITY, ("DB-02", "source_profile", "Codex"): AUTHORITY, ("DB-02", "source_profile", "Git"): AUTHORITY, ("DB-02", "source_profile", "Markdown"): AUTHORITY, ("DB-03", "migration_source", "legacy Mem0/RAG"): AUTHORITY, ("DB-03", "migration_source", "me-wiki"): AUTHORITY, ("DB-03", "migration_source", "unified-db"): AUTHORITY, ("DB-06", "external_model_route", "model-a"): AUTHORITY, ("DB-08", "export_destination", "archive"): AUTHORITY}, AUTHORITY)

def decision(decision_id: str, scope_name: str | None = None, outcome: str = "GO") -> dict[str, object]:
    kind = {"DB-02":"source_profile", "DB-03":"migration_source", "DB-06":"external_model_route", "DB-08":"export_destination"}.get(decision_id, "global")
    raw: dict[str, object] = {"decision_version":"second-brain-decision-record-v1", "decision_id":decision_id, "outcome":outcome, "scope_kind":kind, "scope_name":scope_name if kind != "global" else None, "record_revision":"1", "decided_at":"2026-07-28T00:00:00Z", "supersedes":None, "post_interview_reconciliation":{"original_question":f"original question for {decision_id}","reconciliation":f"reconciled {decision_id}"}, "reason":f"reason-{decision_id}", "evidence_refs":[f"evidence-{decision_id}"], "evidence_digest":DIGEST, "expires_at":FUTURE}
    payload = detached_signing_bytes(DECISION_SIGNING_DOMAIN, raw)
    raw["signatures"] = [{"signature_version":DECISION_SIGNATURE_VERSION,"role":"approver","key_id":"approver","public_key_b64":_public(APPROVER),"signature_b64":b64encode(APPROVER.sign(payload)).decode()},{"signature_version":DECISION_SIGNATURE_VERSION,"role":"owner","key_id":"owner","public_key_b64":_public(OWNER),"signature_b64":b64encode(OWNER.sign(payload)).decode()}]
    return raw

def scope() -> dict[str, object]:
    return {"scope_version":"second-brain-resolved-scope-v1","enabled_source_profiles":["Claude/Memory Bank","Codex","Git","Markdown"],"disabled_source_profiles":{},"enabled_migration_sources":["legacy Mem0/RAG","me-wiki","unified-db"],"disabled_migration_sources":{},"feature_flags":["benchmark-governance","conflict-behavior","cutover-retention","identity-auth"],"egress_destinations":["archive"],"enabled_external_model_routes":["model-a"],"disabled_external_model_routes":{},"disabled_export_destinations":{},"capability_manifest_digest":DIGEST,"source_manifest_digest":DIGEST,"mandatory_release_constraints":["signed-release-baseline"]}

def expected() -> ExpectedScopeManifestV1:
    return ExpectedScopeManifestV1.from_tuples((("DB-02","source_profile","Claude/Memory Bank"),("DB-02","source_profile","Codex"),("DB-02","source_profile","Git"),("DB-02","source_profile","Markdown"),("DB-03","migration_source","legacy Mem0/RAG"),("DB-03","migration_source","me-wiki"),("DB-03","migration_source","unified-db"),("DB-06","external_model_route","model-a"),("DB-08","export_destination","archive")))

def records() -> list[DecisionRecordV1]:
    return [DecisionRecordV1.from_mapping(x) for x in [*(decision(x) for x in ("DB-01","DB-04","DB-05","DB-07")),*(decision("DB-02", name) for name in ("Claude/Memory Bank","Codex","Git","Markdown")),*(decision("DB-03", name) for name in ("legacy Mem0/RAG","me-wiki","unified-db")),decision("DB-06","model-a"),decision("DB-08","archive")]]

def aggregate(items: list[DecisionRecordV1], raw_scope: dict[str, object] | None = None) -> SignedSecondBrainContractEnvelopeV1:
    parsed_scope, manifest = ResolvedScopeV1.from_mapping(raw_scope or scope()), expected()
    from wiki_spike.memory_core.second_brain_contracts import SecondBrainContractDigestV1, Ed25519SignatureEnvelopeV1
    contract = SecondBrainContractDigestV1.create(items, parsed_scope, manifest)
    payload = {"contract_version":contract.contract_version,"contract_body":contract.body(),"contract_digest":contract.digest}
    return SignedSecondBrainContractEnvelopeV1(contract, tuple(Ed25519SignatureEnvelopeV1.from_mapping({"signature_version":CONTRACT_SIGNATURE_VERSION,"role":role,"key_id":name,"public_key_b64":_public(key),"signature_b64":b64encode(key.sign(detached_signing_bytes(CONTRACT_SIGNING_DOMAIN,payload))).decode()}, version=CONTRACT_SIGNATURE_VERSION) for role,name,key in (("approver","approver",APPROVER),("owner","owner",OWNER))))

def resolve(items: list[DecisionRecordV1], raw_scope: dict[str, object] | None = None, **kwargs: object):
    return resolve_second_brain_contract(items, ResolvedScopeV1.from_mapping(raw_scope or scope()), expected(), aggregate(items, raw_scope), trusted_keys=TRUSTED, **kwargs)

def test_resolution_requires_trusted_two_party_aggregate_and_manifest_binding():
    result = resolve(records())
    assert result.outcome == "RESOLVED" and result.contract is not None
    assert result.contract.expected_scope_manifest.digest == expected().digest

def test_extra_enabled_and_omitted_required_scope_fail_closed():
    raw = scope(); raw["enabled_source_profiles"] = ["Claude/Memory Bank","Codex","Git","Markdown","rogue"]
    with pytest.raises(InvalidContractValue, match="exactly match"): resolve(records(), raw)
    with pytest.raises(InvalidContractValue): resolve(records()[:-1])

def test_untrusted_signer_and_aggregate_tamper_fail_closed():
    items = records()
    bad = TrustedDecisionKeyBindingsV1(TRUSTED.decision_bindings, TrustedAuthorityBindingsV1("approver", _public(APPROVER), "owner", _public(Ed25519PrivateKey.generate())))
    with pytest.raises(InvalidContractValue, match="valid aggregate envelope"): resolve_second_brain_contract(items, ResolvedScopeV1.from_mapping(scope()), expected(), aggregate(items), trusted_keys=bad)
    envelope = aggregate(items); object.__setattr__(envelope.contract, "digest", "b" * 64)
    assert not envelope.verify(TRUSTED)


def test_direct_construction_cannot_bypass_dual_decision_signatures():
    for signatures in ((), records()[0].signatures[:1]):
        items = records()
        items[0] = replace(items[0], signatures=signatures)
        with pytest.raises(InvalidContractValue, match="signatures require"):
            resolve_second_brain_contract(
                items,
                ResolvedScopeV1.from_mapping(scope()),
                expected(),
                aggregate(items),
                trusted_keys=TRUSTED,
            )

def test_duplicate_key_name_role_and_schema_parity_fail():
    raw = decision("DB-01"); raw["signatures"][1]["key_id"] = "approver"  # type: ignore[index]
    with pytest.raises(InvalidContractValue, match="distinct"): DecisionRecordV1.from_mapping(raw)
    raw = decision("DB-01"); raw["signatures"][1]["role"] = "approver"  # type: ignore[index]
    with pytest.raises(InvalidContractValue, match="canonically ordered"): DecisionRecordV1.from_mapping(raw)
    schema = json.loads((Path(__file__).parents[2] / "schemas/second-brain/decision-record-v1.schema.json").read_text())
    assert schema["properties"]["signatures"]["prefixItems"][0]["allOf"][1]["properties"]["role"]["const"] == "approver"
    assert schema["properties"]["record_revision"] == {"type": "string", "pattern": "^[1-9][0-9]*$"}
    assert schema["properties"]["supersedes"]["properties"]["record_revision"] == {"type": "string", "pattern": "^[1-9][0-9]*$"}
    assert schema["allOf"][-1]["if"]["properties"]["record_revision"]["const"] == "1"
    disabled_schema = json.loads((Path(__file__).parents[2] / "schemas/second-brain/resolved-scope-v1.schema.json").read_text())
    assert disabled_schema["$defs"]["disabled"]["type"] == "object"
    aggregate_schema = json.loads((Path(__file__).parents[2] / "schemas/second-brain/contract-envelope-v1.schema.json").read_text())
    assert set(aggregate_schema["$defs"]["contract_body"]["required"]) == {"contract_version", "decision_digests", "resolved_scope", "expected_scope_manifest"}

def test_decision_authority_is_bound_to_exact_scope_and_evidence_is_required():
    items = records()
    bindings = dict(TRUSTED.decision_bindings)
    bindings[("DB-02", "source_profile", "Codex")] = TrustedAuthorityBindingsV1("approver", _public(APPROVER), "owner", _public(Ed25519PrivateKey.generate()))
    wrong_scope_authority = TrustedDecisionKeyBindingsV1(bindings, AUTHORITY)
    with pytest.raises(InvalidContractValue, match="untrusted"): resolve_second_brain_contract(items, ResolvedScopeV1.from_mapping(scope()), expected(), aggregate(items), trusted_keys=wrong_scope_authority)
    raw = decision("DB-01"); raw["evidence_refs"] = []
    with pytest.raises(InvalidContractValue, match="non-empty"): DecisionRecordV1.from_mapping(raw)

def test_aggregate_wire_parser_rejects_missing_malformed_and_tampered_body():
    wire = aggregate(records()).to_mapping()
    assert SignedSecondBrainContractEnvelopeV1.from_mapping(wire).verify(TRUSTED)
    for mutation in (
        lambda value: value.pop("contract_body"),
        lambda value: value.__setitem__("contract_body", {}),
        lambda value: value["contract_body"].pop("resolved_scope"),
        lambda value: value.__setitem__("contract_digest", "b" * 64),
    ):
        malformed = deepcopy(wire); mutation(malformed)
        with pytest.raises(InvalidContractValue):
            SignedSecondBrainContractEnvelopeV1.from_mapping(malformed)

def test_global_no_go_and_expiry_preserved():
    raw = [x.to_mapping() for x in records()]; raw[0] = decision("DB-01", outcome="NO_GO")
    result = resolve([DecisionRecordV1.from_mapping(x) for x in raw]); assert result.outcome == "BLOCKED" and result.contract is None
    with pytest.raises(InvalidContractValue, match="expired"): resolve(records(), now=datetime(2031, 1, 1, tzinfo=timezone.utc))
@pytest.mark.parametrize("field,value", [
    ("decision_version", "forged-v1"),
    ("outcome", "MAYBE"),
    ("evidence_refs", ()),
    ("scope_name", "forged-scope"),
])
def test_resolver_revalidates_directly_constructed_decisions(field: str, value: object):
    items = records()
    items[0] = replace(items[0], **{field: value})
    with pytest.raises(ValueError):
        resolve_second_brain_contract(items, ResolvedScopeV1.from_mapping(scope()), expected(), aggregate(items), trusted_keys=TRUSTED)

def test_lifecycle_fields_are_required_signed_and_strictly_linked():
    raw = decision("DB-01")
    for field in ("record_revision", "decided_at", "supersedes", "post_interview_reconciliation"):
        missing = deepcopy(raw); missing.pop(field)
        with pytest.raises(InvalidContractValue): DecisionRecordV1.from_mapping(missing)
    tampered = deepcopy(raw); tampered["post_interview_reconciliation"]["original_question"] = "changed"  # type: ignore[index]
    assert not DecisionRecordV1.from_mapping(tampered).signatures[0].verify(DECISION_SIGNING_DOMAIN, DecisionRecordV1.from_mapping(tampered).signing_payload())
    superseding = decision("DB-01"); superseding["record_revision"] = "2"
    superseding["supersedes"] = {"decision_id":"DB-01","scope_kind":"global","scope_name":None,"record_revision":"1","decision_digest":DIGEST}
    payload = detached_signing_bytes(DECISION_SIGNING_DOMAIN, {key:value for key,value in superseding.items() if key != "signatures"})
    superseding["signatures"] = [{"signature_version":DECISION_SIGNATURE_VERSION,"role":"approver","key_id":"approver","public_key_b64":_public(APPROVER),"signature_b64":b64encode(APPROVER.sign(payload)).decode()},{"signature_version":DECISION_SIGNATURE_VERSION,"role":"owner","key_id":"owner","public_key_b64":_public(OWNER),"signature_b64":b64encode(OWNER.sign(payload)).decode()}]
    assert DecisionRecordV1.from_mapping(superseding).record_revision == "2"
    superseding["supersedes"]["scope_name"] = "wrong"  # type: ignore[index]
    with pytest.raises(InvalidContractValue, match="same decision scope"): DecisionRecordV1.from_mapping(superseding)
    superseding["supersedes"]["scope_name"] = None  # type: ignore[index]
    superseding["supersedes"]["record_revision"] = "2"  # type: ignore[index]
    with pytest.raises(InvalidContractValue, match="immediately prior"): DecisionRecordV1.from_mapping(superseding)


@pytest.mark.parametrize("revision", [0, 1, "0", "-1", "+1", "01"])
def test_record_revision_requires_a_canonical_positive_decimal_string(revision: object):
    raw = decision("DB-01"); raw["record_revision"] = revision
    with pytest.raises(InvalidContractValue, match="record_revision"):
        DecisionRecordV1.from_mapping(raw)

def test_required_inventory_unknown_features_and_empty_release_baseline_fail_closed():
    missing_inventory = tuple(entry for entry in expected().expected_scopes if entry[2] != "Git")
    with pytest.raises(InvalidContractValue, match="required inventory"): ExpectedScopeManifestV1.from_tuples(missing_inventory)
    substituted = list(expected().expected_scopes); substituted[2] = ("DB-02", "source_profile", "Other")
    with pytest.raises(InvalidContractValue, match="expected scope|required inventory"):
        ExpectedScopeManifestV1.from_tuples(tuple(substituted))
    raw = scope(); raw["feature_flags"] = ["unbound-feature"]
    with pytest.raises(InvalidContractValue, match="unknown feature"): ResolvedScopeV1.from_mapping(raw)
    raw = scope(); raw["mandatory_release_constraints"] = []
    with pytest.raises(InvalidContractValue, match="non-empty"): ResolvedScopeV1.from_mapping(raw)

@pytest.mark.parametrize("decision_id,scope_name,field", [
    ("DB-02", "Codex", "disabled_source_profiles"),
    ("DB-03", "unified-db", "disabled_migration_sources"),
    ("DB-06", "model-a", "disabled_external_model_routes"),
    ("DB-08", "archive", "disabled_export_destinations"),
])
def test_every_scoped_no_go_class_resolves_as_disabled(decision_id: str, scope_name: str, field: str):
    raw_records = [record.to_mapping() for record in records()]
    index = next(index for index, record in enumerate(raw_records) if record["decision_id"] == decision_id and record["scope_name"] == scope_name)
    raw_records[index] = decision(decision_id, scope_name, "NO_GO")
    items = [DecisionRecordV1.from_mapping(record) for record in raw_records]
    raw_scope = scope()
    enabled_field = {"disabled_source_profiles":"enabled_source_profiles", "disabled_migration_sources":"enabled_migration_sources", "disabled_external_model_routes":"enabled_external_model_routes", "disabled_export_destinations":"egress_destinations"}[field]
    raw_scope[enabled_field] = [name for name in raw_scope[enabled_field] if name != scope_name]  # type: ignore[index]
    raw_scope[field] = {scope_name:"signed NO_GO"}
    assert resolve(items, raw_scope).outcome == "RESOLVED"

def test_resolver_revalidates_direct_scope_manifest_and_aggregate_objects():
    items = records()
    forged_scope = replace(ResolvedScopeV1.from_mapping(scope()), scope_version="forged-v1")
    with pytest.raises(ValueError):
        resolve_second_brain_contract(items, forged_scope, expected(), aggregate(items), trusted_keys=TRUSTED)
    with pytest.raises(InvalidContractValue):
        resolve_second_brain_contract(items, ResolvedScopeV1.from_mapping(scope()), ExpectedScopeManifestV1(()), aggregate(items), trusted_keys=TRUSTED)
    with pytest.raises(InvalidContractValue):
        resolve_second_brain_contract(items, ResolvedScopeV1.from_mapping(scope()), expected(), replace(aggregate(items), signatures=()), trusted_keys=TRUSTED)
