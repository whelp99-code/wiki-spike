"""Stage 6: cutover decision formula, cohort state machine, no unauthorized live switch."""
from __future__ import annotations

import pytest
from test_decision_contracts import scope
from test_stage3_ledger_persistence import digest, ref
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_cutover import (
    COHORT_MANIFEST_V1,
    CUTOVER_DECISION_V1,
    CutoverDecisionV1,
    MigrationCohortManifestV1,
    assert_cohort_subset_of_enabled_migration_sources,
    assert_cohort_transition,
    assert_cutover_decision_joins_scope_and_cohort,
    assert_destructive_decommission_authorized,
    assert_live_route_switch_authorized,
    assert_post_mutation_fail_closed,
    assert_pre_mutation_rollback_allowed,
    canonical_ledger_digest,
)
from wiki_spike.memory_core.second_brain_product_release import resolved_scope_digest


def _scope() -> ResolvedScopeV1:
    return ResolvedScopeV1.from_mapping(scope())


def _cohort(scope_obj: ResolvedScopeV1, *, state: str = "CUTOVER_READY", sources: tuple[str, ...] | None = None) -> MigrationCohortManifestV1:
    body = {
        "manifest_version": COHORT_MANIFEST_V1,
        "workspace_ref": ref("workspace", "cutover"),
        "cohort_state": state,
        "source_names": list(sources or ("unified-db", "legacy Mem0/RAG", "me-wiki")),
        "resolved_scope_digest": resolved_scope_digest(scope_obj),
        "source_manifest_digest": scope_obj.source_manifest_digest,
    }
    body["manifest_digest"] = canonical_ledger_digest("migration-cohort-manifest-v1", body)
    return MigrationCohortManifestV1.from_mapping(body)


def _decision(
    scope_obj: ResolvedScopeV1,
    cohort: MigrationCohortManifestV1,
    *,
    observation_days: int = 14,
    parity_cases: int = 200,
    e2e: int = 500,
    safety: int = 0,
    parity_lower: int = 9000,
    citation_lower: int = 9000,
    completeness_lower: int = 9000,
    availability_lower: int = 9900,
    holdout_changed: bool = False,
    formula_pass: bool | None = None,
    contract_digest: str | None = None,
) -> CutoverDecisionV1:
    mins = dict(parity_min_bps=9000, citation_min_bps=9000, completeness_min_bps=9000, availability_min_bps=9900)
    computed = (
        safety == 0 and observation_days >= 14 and parity_cases >= 200 and e2e >= 500
        and parity_lower >= mins["parity_min_bps"] and citation_lower >= mins["citation_min_bps"]
        and completeness_lower >= mins["completeness_min_bps"] and availability_lower >= mins["availability_min_bps"]
        and holdout_changed is False
    )
    body = {
        "decision_version": CUTOVER_DECISION_V1,
        "decision_id": "cutover-2026-07-29",
        "workspace_ref": ref("workspace", "cutover"),
        "cohort_manifest_digest": cohort.manifest_digest,
        "resolved_scope_digest": resolved_scope_digest(scope_obj),
        "contract_digest": contract_digest or digest("contract"),
        "source_manifest_digest": scope_obj.source_manifest_digest,
        "capability_manifest_digest": scope_obj.capability_manifest_digest,
        "benchmark_manifest_digest": digest("benchmark"),
        "holdout_manifest_digest": digest("holdout"),
        "generation_digest": digest("generation"),
        "checkpoint_digest": digest("checkpoint"),
        "route_version": "route-v1",
        "observation_days": observation_days,
        "parity_cases_per_source": parity_cases,
        "cohort_e2e_queries": e2e,
        "safety_violations": safety,
        "parity_bps_lower": parity_lower,
        "citation_bps_lower": citation_lower,
        "completeness_bps_lower": completeness_lower,
        "availability_bps_lower": availability_lower,
        **mins,
        "holdout_changed": holdout_changed,
        "approver_roles": sorted(["migration", "quality", "security", "product"]),
        "formula_pass": computed if formula_pass is None else formula_pass,
    }
    body["decision_digest"] = canonical_ledger_digest("cutover-decision-v1", body)
    return CutoverDecisionV1.from_mapping(body)


def test_cohort_must_be_subset_of_enabled_migration_sources() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    assert_cohort_subset_of_enabled_migration_sources(cohort, scope_obj)
    with pytest.raises(InvalidContractValue, match="not enabled"):
        assert_cohort_subset_of_enabled_migration_sources(
            _cohort(scope_obj, sources=("unified-db", "unknown-source")), scope_obj
        )


def test_cohort_state_machine_transitions_and_rollback_boundaries() -> None:
    assert_cohort_transition("DISCOVERED", "IMPORTING")
    assert_cohort_transition("READY_NON_SERVING", "CUTOVER_READY")
    assert_cohort_transition("CUTOVER_READY", "ROUTE_SWITCHED_NO_MUTATION")
    assert_cohort_transition("ROUTE_SWITCHED_NO_MUTATION", "CANONICAL_MUTATED")
    assert_cohort_transition("ROUTE_SWITCHED_NO_MUTATION", "ROLLED_BACK_RECONCILE")
    with pytest.raises(InvalidContractValue, match="illegal cohort transition"):
        assert_cohort_transition("CUTOVER_READY", "CANONICAL_MUTATED")
    assert_pre_mutation_rollback_allowed("ROUTE_SWITCHED_NO_MUTATION")
    with pytest.raises(InvalidContractValue, match="pre-mutation rollback"):
        assert_pre_mutation_rollback_allowed("CANONICAL_MUTATED")
    assert_post_mutation_fail_closed("ROUTE_SWITCHED_NO_MUTATION", action="external_rollback")
    with pytest.raises(InvalidContractValue, match="external rollback is closed"):
        assert_post_mutation_fail_closed("CANONICAL_MUTATED", action="external_rollback")


def test_cutover_formula_pass_requires_plan_minima() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    ok = _decision(scope_obj, cohort)
    assert ok.formula_pass is True
    with pytest.raises(InvalidContractValue, match="formula_pass does not match"):
        _decision(scope_obj, cohort, observation_days=13, formula_pass=True)
    with pytest.raises(InvalidContractValue, match="formula_pass does not match"):
        _decision(scope_obj, cohort, safety=1, formula_pass=True)
    with pytest.raises(InvalidContractValue, match="formula_pass does not match"):
        _decision(scope_obj, cohort, holdout_changed=True, formula_pass=True)
    with pytest.raises(InvalidContractValue, match="approver_roles"):
        body = ok.to_mapping()
        body["approver_roles"] = ["migration", "quality", "security"]
        body["decision_digest"] = canonical_ledger_digest("cutover-decision-v1", {k: v for k, v in body.items() if k != "decision_digest"})
        CutoverDecisionV1.from_mapping(body)


def test_cutover_decision_joins_scope_and_cohort() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj, state="CUTOVER_READY")
    decision = _decision(scope_obj, cohort)
    assert_cutover_decision_joins_scope_and_cohort(decision, scope_obj, cohort, contract_digest=digest("contract"))
    early = _cohort(scope_obj, state="READY_NON_SERVING")
    early_decision = _decision(scope_obj, early)
    with pytest.raises(InvalidContractValue, match="CUTOVER_READY"):
        assert_cutover_decision_joins_scope_and_cohort(
            early_decision, scope_obj, early, contract_digest=digest("contract")
        )


def test_live_route_switch_and_decommission_require_human_approvals() -> None:
    scope_obj = _scope()
    decision = _decision(scope_obj, _cohort(scope_obj))
    with pytest.raises(InvalidContractValue, match="human-controlled external approvals"):
        assert_live_route_switch_authorized(decision, human_external_approvals_present=False)
    assert_live_route_switch_authorized(decision, human_external_approvals_present=True)
    with pytest.raises(InvalidContractValue, match="90-day"):
        assert_destructive_decommission_authorized(
            "ROLLBACK_CLOSED", retention_days_elapsed=89, evidence_backed=True, human_external_approvals_present=True
        )
    with pytest.raises(InvalidContractValue, match="human-controlled external approvals"):
        assert_destructive_decommission_authorized(
            "ROLLBACK_CLOSED", retention_days_elapsed=90, evidence_backed=True, human_external_approvals_present=False
        )
    assert_destructive_decommission_authorized(
        "ROLLBACK_CLOSED", retention_days_elapsed=90, evidence_backed=True, human_external_approvals_present=True
    )
