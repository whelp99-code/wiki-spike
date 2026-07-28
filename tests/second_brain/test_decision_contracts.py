from __future__ import annotations

from copy import deepcopy

import pytest

from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.second_brain_contracts import (
    DecisionRecordV1,
    ResolvedScopeV1,
    resolve_second_brain_contract,
)

DIGEST = "a" * 64
FUTURE = "2030-01-01T00:00:00Z"


def decision(decision_id: str, outcome: str = "GO") -> dict[str, object]:
    scoped = {"DB-02": ("source_profile", "notes"), "DB-03": ("migration_source", "legacy"), "DB-06": ("external_model_route", "model-a"), "DB-08": ("export_destination", "archive")}
    kind, name = scoped.get(decision_id, ("global", None))
    return {"decision_version": "second-brain-decision-record-v1", "decision_id": decision_id, "outcome": outcome, "scope_kind": kind, "scope_name": name, "reason": f"reason-{decision_id}", "evidence_refs": [f"evidence-{decision_id}"], "evidence_digest": DIGEST, "signed_by": "release-authority", "signature": "signature", "expires_at": FUTURE}


def scope() -> dict[str, object]:
    return {"scope_version": "second-brain-resolved-scope-v1", "enabled_source_profiles": ["notes"], "disabled_source_profiles": [], "enabled_migration_sources": ["legacy"], "disabled_migration_sources": [], "feature_flags": ["second-brain"], "egress_destinations": ["archive"], "disabled_external_model_routes": [], "disabled_export_destinations": [], "capability_manifest_digest": DIGEST, "source_manifest_digest": DIGEST, "mandatory_release_constraints": ["release-approval"]}


def resolved(records: list[DecisionRecordV1], raw_scope: dict[str, object] | None = None):
    return resolve_second_brain_contract(records, ResolvedScopeV1.from_mapping(raw_scope or scope()), verify_signature=lambda _: True)


def records() -> list[DecisionRecordV1]:
    return [DecisionRecordV1.from_mapping(decision(f"DB-{number:02d}")) for number in range(1, 9)]


def test_valid_aggregation_is_deterministic():
    first = resolved(records())
    second = resolved(list(reversed(records())))
    assert first.digest == second.digest
    assert [item[0] for item in first.decision_digests] == sorted(item[0] for item in first.decision_digests)


@pytest.mark.parametrize("decision_id", ["DB-01", "DB-04", "DB-05", "DB-07"])
def test_fatal_decisions_require_go(decision_id: str):
    with pytest.raises(InvalidContractValue, match="require GO"):
        DecisionRecordV1.from_mapping(decision(decision_id, "NO_GO"))


@pytest.mark.parametrize("decision_id,field", [("DB-02", "disabled_source_profiles"), ("DB-03", "disabled_migration_sources"), ("DB-06", "disabled_external_model_routes"), ("DB-08", "disabled_export_destinations")])
def test_scoped_no_go_disables_exactly_named_scope(decision_id: str, field: str):
    items = records()
    items[int(decision_id[-2:]) - 1] = DecisionRecordV1.from_mapping(decision(decision_id, "NO_GO"))
    raw_scope = scope()
    raw_scope[field] = [{"name": decision(decision_id)["scope_name"], "reason": f"reason-{decision_id}"}]
    if decision_id == "DB-02":
        raw_scope["enabled_source_profiles"] = ["other-profile"]
    elif decision_id == "DB-03":
        raw_scope["enabled_migration_sources"] = ["other-migration"]
    elif decision_id == "DB-08":
        raw_scope["egress_destinations"] = ["other-destination"]
    assert resolved(items, raw_scope).digest


def test_expired_unknown_and_bad_signature_fail_closed():
    expired = decision("DB-01")
    expired["expires_at"] = "2000-01-01T00:00:00Z"
    with pytest.raises(InvalidContractValue, match="expired"):
        DecisionRecordV1.from_mapping(expired)
    unknown = decision("DB-01")
    unknown["unexpected"] = "no"
    with pytest.raises(UnknownContractField):
        DecisionRecordV1.from_mapping(unknown)
    with pytest.raises(InvalidContractValue, match="invalid signature"):
        resolve_second_brain_contract(records(), ResolvedScopeV1.from_mapping(scope()), verify_signature=lambda _: False)


def test_scope_mismatch_fails_closed():
    items = records()
    items[1] = DecisionRecordV1.from_mapping(decision("DB-02", "NO_GO"))
    raw_scope = deepcopy(scope())
    raw_scope["disabled_source_profiles"] = [{"name": "other", "reason": "reason-DB-02"}]
    with pytest.raises(InvalidContractValue, match="exactly"):
        resolved(items, raw_scope)
