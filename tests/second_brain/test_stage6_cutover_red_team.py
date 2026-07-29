"""Adversarial / red-team suite for G018: Stage-6 cutover decision + cohort SM.

Surface: api-package-algorithm. Prove fail-closed behavior across formula
underflows claiming PASS, missing approver roles, disabled sources in cohort,
illegal state transitions, unauthorized live switch, early decommission,
post-mutation external rollback, scope/cohort digest mismatches, and digest
tamper. No src edits.
"""
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

_COHORT_STATES = (
    "DISCOVERED",
    "IMPORTING",
    "QUARANTINED_ITEM",
    "RECONCILING",
    "READY_NON_SERVING",
    "CUTOVER_READY",
    "ROUTE_SWITCHED_NO_MUTATION",
    "CANONICAL_MUTATED",
    "ROLLBACK_CLOSED",
    "ROLLED_BACK_RECONCILE",
    "DECOMMISSIONED",
)

_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "DISCOVERED": frozenset({"IMPORTING"}),
    "IMPORTING": frozenset({"QUARANTINED_ITEM", "RECONCILING", "READY_NON_SERVING"}),
    "QUARANTINED_ITEM": frozenset({"IMPORTING", "RECONCILING"}),
    "RECONCILING": frozenset({"IMPORTING", "READY_NON_SERVING"}),
    "READY_NON_SERVING": frozenset({"CUTOVER_READY"}),
    "CUTOVER_READY": frozenset({"ROUTE_SWITCHED_NO_MUTATION"}),
    "ROUTE_SWITCHED_NO_MUTATION": frozenset({"CANONICAL_MUTATED", "ROLLED_BACK_RECONCILE"}),
    "CANONICAL_MUTATED": frozenset({"ROLLBACK_CLOSED"}),
    "ROLLBACK_CLOSED": frozenset({"DECOMMISSIONED"}),
    "ROLLED_BACK_RECONCILE": frozenset({"IMPORTING"}),
    "DECOMMISSIONED": frozenset(),
}

_REQUIRED_APPROVER_ROLES = ("migration", "quality", "security", "product")

_POST_MUTATION_STATES = ("CANONICAL_MUTATED", "ROLLBACK_CLOSED", "DECOMMISSIONED")


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _scope(**overrides: object) -> ResolvedScopeV1:
    raw = scope()
    raw.update(overrides)
    # Keep list fields sorted/unique when callers override them.
    for key in (
        "enabled_migration_sources",
        "enabled_source_profiles",
        "feature_flags",
        "egress_destinations",
        "enabled_external_model_routes",
        "mandatory_release_constraints",
    ):
        if key in overrides:
            names = list(overrides[key])  # type: ignore[arg-type]
            raw[key] = sorted(set(names))
    return ResolvedScopeV1.from_mapping(raw)


def _cohort(
    scope_obj: ResolvedScopeV1,
    *,
    state: str = "CUTOVER_READY",
    sources: tuple[str, ...] | None = None,
    resolved_scope_digest_value: str | None = None,
    source_manifest_digest: str | None = None,
    workspace_ref: str | None = None,
) -> MigrationCohortManifestV1:
    body = {
        "manifest_version": COHORT_MANIFEST_V1,
        "workspace_ref": workspace_ref or ref("workspace", "cutover-rt"),
        "cohort_state": state,
        "source_names": list(sources or ("unified-db",)),
        "resolved_scope_digest": resolved_scope_digest_value or resolved_scope_digest(scope_obj),
        "source_manifest_digest": source_manifest_digest or scope_obj.source_manifest_digest,
    }
    body["manifest_digest"] = canonical_ledger_digest("migration-cohort-manifest-v1", body)
    return MigrationCohortManifestV1.from_mapping(body)


def _decision_body(
    scope_obj: ResolvedScopeV1,
    cohort: MigrationCohortManifestV1,
    *,
    observation_days: int = 3,
    parity_cases: int = 200,
    e2e: int = 500,
    safety: int = 0,
    parity_lower: int = 9000,
    citation_lower: int = 9000,
    completeness_lower: int = 9000,
    availability_lower: int = 9900,
    parity_min_bps: int = 9000,
    citation_min_bps: int = 9000,
    completeness_min_bps: int = 9000,
    availability_min_bps: int = 9900,
    holdout_changed: bool = False,
    formula_pass: bool | None = None,
    contract_digest: str | None = None,
    approver_roles: list[str] | None = None,
    resolved_scope_digest_value: str | None = None,
    source_manifest_digest: str | None = None,
    capability_manifest_digest: str | None = None,
    cohort_manifest_digest: str | None = None,
    decision_id: str = "cutover-rt-2026-07-29",
) -> dict:
    mins = dict(
        parity_min_bps=parity_min_bps,
        citation_min_bps=citation_min_bps,
        completeness_min_bps=completeness_min_bps,
        availability_min_bps=availability_min_bps,
    )
    computed = (
        safety == 0
        and observation_days >= 3
        and parity_cases >= 200
        and e2e >= 500
        and parity_lower >= mins["parity_min_bps"]
        and citation_lower >= mins["citation_min_bps"]
        and completeness_lower >= mins["completeness_min_bps"]
        and availability_lower >= mins["availability_min_bps"]
        and holdout_changed is False
    )
    body = {
        "decision_version": CUTOVER_DECISION_V1,
        "decision_id": decision_id,
        "workspace_ref": ref("workspace", "cutover-rt"),
        "cohort_manifest_digest": cohort_manifest_digest or cohort.manifest_digest,
        "resolved_scope_digest": resolved_scope_digest_value or resolved_scope_digest(scope_obj),
        "contract_digest": contract_digest or digest("contract"),
        "source_manifest_digest": source_manifest_digest or scope_obj.source_manifest_digest,
        "capability_manifest_digest": capability_manifest_digest or scope_obj.capability_manifest_digest,
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
        "approver_roles": sorted(
            r.lower()
            for r in (list(_REQUIRED_APPROVER_ROLES) if approver_roles is None else approver_roles)
        ),
        "formula_pass": computed if formula_pass is None else formula_pass,
    }
    body["decision_digest"] = canonical_ledger_digest("cutover-decision-v1", body)
    return body


def _decision(
    scope_obj: ResolvedScopeV1,
    cohort: MigrationCohortManifestV1,
    **kwargs: object,
) -> CutoverDecisionV1:
    return CutoverDecisionV1.from_mapping(_decision_body(scope_obj, cohort, **kwargs))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# A1 -- formula underflows claiming PASS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("observation_days", 2),
        ("observation_days", 0),
        ("parity_cases", 199),
        ("parity_cases", 0),
        ("e2e", 499),
        ("e2e", 1),
        ("safety", 1),
        ("safety", 99),
        ("parity_lower", 8999),
        ("citation_lower", 8999),
        ("completeness_lower", 8999),
        ("availability_lower", 9899),
        ("holdout_changed", True),
    ],
    ids=lambda v: f"{v}" if not isinstance(v, bool) else ("holdout_true" if v else "holdout_false"),
)
def test_g018_a1_formula_underflow_claiming_pass_refuses(field: str, value: object) -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    kwargs = {field: value, "formula_pass": True}
    with pytest.raises(InvalidContractValue, match="formula_pass does not match"):
        _decision(scope_obj, cohort, **kwargs)  # type: ignore[arg-type]


def test_g018_a1_formula_pass_false_when_metrics_satisfy_is_also_refused() -> None:
    """Lying the other way: metrics pass but formula_pass=False must refuse bind."""
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    with pytest.raises(InvalidContractValue, match="formula_pass does not match"):
        _decision(scope_obj, cohort, formula_pass=False)


def test_g018_a1_lowered_minima_with_matching_lower_still_requires_formula_bind() -> None:
    """Attacker lowers min_bps so weak lower-bound still 'passes' relative to min.

    Construction is allowed when formula_pass matches the weakened thresholds,
    but live join still requires formula_pass True and plan-quality evidence is
    attacker-controlled only via the signed body. Pin that exact-plan mins with
    weak lower still refuse when claiming PASS against plan mins.
    """
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    # parity_lower 8000 < parity_min 9000 → computed False; claiming True refuses.
    with pytest.raises(InvalidContractValue, match="formula_pass does not match"):
        _decision(scope_obj, cohort, parity_lower=8000, formula_pass=True)
    # Weak min + weak lower with honest formula_pass=True constructs (relative PASS).
    weak = _decision(
        scope_obj,
        cohort,
        parity_lower=8000,
        parity_min_bps=8000,
        formula_pass=True,
    )
    assert weak.formula_pass is True
    assert weak.parity_min_bps == 8000


def test_g018_a1_compound_underflow_still_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    with pytest.raises(InvalidContractValue, match="formula_pass does not match"):
        _decision(
            scope_obj,
            cohort,
            observation_days=1,
            parity_cases=1,
            e2e=1,
            safety=5,
            holdout_changed=True,
            formula_pass=True,
        )


def test_g018_a1_exact_plan_minima_constructs_with_formula_pass() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    ok = _decision(scope_obj, cohort)
    assert ok.formula_pass is True
    assert ok.observation_days == 3
    assert ok.parity_cases_per_source == 200
    assert ok.cohort_e2e_queries == 500
    assert ok.safety_violations == 0


# ---------------------------------------------------------------------------
# A2 -- missing / wrong approver roles
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing", list(_REQUIRED_APPROVER_ROLES))
def test_g018_a2_missing_single_required_approver_refuses(missing: str) -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    roles = [r for r in _REQUIRED_APPROVER_ROLES if r != missing]
    with pytest.raises(InvalidContractValue, match="approver_roles"):
        _decision(scope_obj, cohort, approver_roles=roles)


def test_g018_a2_empty_approver_roles_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    with pytest.raises(InvalidContractValue, match="approver_roles"):
        _decision(scope_obj, cohort, approver_roles=[])


def test_g018_a2_extra_approver_role_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    with pytest.raises(InvalidContractValue, match="approver_roles"):
        _decision(
            scope_obj,
            cohort,
            approver_roles=list(_REQUIRED_APPROVER_ROLES) + ["executive"],
        )


def test_g018_a2_duplicate_approver_role_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    # set equality would pass if len not checked; duplicates shrink uniqueness.
    with pytest.raises(InvalidContractValue, match="approver_roles"):
        _decision(
            scope_obj,
            cohort,
            approver_roles=["migration", "quality", "security", "migration"],
        )


def test_g018_a2_case_normalized_roles_still_require_exact_set() -> None:
    """Roles are lowercased then sorted; uppercase of the four is accepted.

    Digest must bind the normalized lowercase role list that from_mapping writes.
    """
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    body = _decision_body(
        scope_obj,
        cohort,
        approver_roles=["Migration", "QUALITY", "Security", "PRODUCT"],
    )
    # Rebuild digest against the normalized body that from_mapping will hash.
    roles = sorted(r.lower() for r in body["approver_roles"])
    body["approver_roles"] = roles
    body["decision_digest"] = canonical_ledger_digest(
        "cutover-decision-v1", {k: v for k, v in body.items() if k != "decision_digest"}
    )
    # Present mixed-case input; construction normalizes then rebinds.
    body["approver_roles"] = ["Migration", "QUALITY", "Security", "PRODUCT"]
    # Digest was computed for lowercase sorted roles; from_mapping lowercases then
    # re-hashes against lowercase list — so recompute after setting mixed case by
    # matching from_mapping's body construction order.
    normalized = dict(body)
    normalized["approver_roles"] = sorted(r.lower() for r in body["approver_roles"])
    body["decision_digest"] = canonical_ledger_digest(
        "cutover-decision-v1", {k: v for k, v in normalized.items() if k != "decision_digest"}
    )
    ok = CutoverDecisionV1.from_mapping(body)
    assert ok.approver_roles == tuple(sorted(_REQUIRED_APPROVER_ROLES))


def test_g018_a2_lookalike_role_name_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    with pytest.raises(InvalidContractValue, match="approver_roles"):
        _decision(
            scope_obj,
            cohort,
            approver_roles=["migration", "quality", "security", "products"],
        )


# ---------------------------------------------------------------------------
# A3 -- disabled / unknown source in cohort
# ---------------------------------------------------------------------------


def test_g018_a3_unknown_source_not_in_enabled_refuses() -> None:
    scope_obj = _scope()
    with pytest.raises(InvalidContractValue, match="exactly one migration source"):
        _cohort(scope_obj, sources=("unified-db", "shadow-exfil-source"))
    cohort = _cohort(scope_obj, sources=("shadow-exfil-source",))
    with pytest.raises(InvalidContractValue, match="not enabled"):
        assert_cohort_subset_of_enabled_migration_sources(cohort, scope_obj)


def test_g018_a3_disabled_migration_source_cannot_join_cohort() -> None:
    """Source listed in disabled_migration_sources must refuse even if also enabled.

    ResolvedScopeV1 forbids the same name in both lists, so craft a scope with
    the target only in disabled, and a cohort still naming it.
    """
    scope_obj = _scope(
        enabled_migration_sources=["me-wiki", "unified-db"],
        disabled_migration_sources={"legacy Mem0/RAG": "retired-for-cutover"},
    )
    # Cohort tries to sneak the disabled source back in.
    cohort = _cohort(scope_obj, sources=("legacy Mem0/RAG",))  # single disabled source
    with pytest.raises(InvalidContractValue, match="not enabled|disabled migration source"):
        assert_cohort_subset_of_enabled_migration_sources(cohort, scope_obj)


def test_g018_a3_disabled_only_roster_refuses() -> None:
    scope_obj = _scope(
        enabled_migration_sources=["me-wiki", "unified-db"],
        disabled_migration_sources={"legacy Mem0/RAG": "retired-for-cutover"},
    )
    cohort = _cohort(scope_obj, sources=("legacy Mem0/RAG",))
    with pytest.raises(InvalidContractValue, match="not enabled|disabled migration source"):
        assert_cohort_subset_of_enabled_migration_sources(cohort, scope_obj)


def test_g018_a3_honest_subset_of_enabled_accepted() -> None:
    scope_obj = _scope()
    # multi-source refused at construction under DB-07 one-source-at-a-time
    with pytest.raises(InvalidContractValue, match="exactly one migration source"):
        _cohort(scope_obj, sources=("me-wiki", "unified-db"))
    cohort = _cohort(scope_obj, sources=("me-wiki",))
    assert_cohort_subset_of_enabled_migration_sources(cohort, scope_obj)


def test_g018_a3_full_enabled_roster_accepted() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    assert_cohort_subset_of_enabled_migration_sources(cohort, scope_obj)


def test_g018_a3_duplicate_source_names_refuse_construction() -> None:
    scope_obj = _scope()
    body = {
        "manifest_version": COHORT_MANIFEST_V1,
        "workspace_ref": ref("workspace", "cutover-rt"),
        "cohort_state": "CUTOVER_READY",
        "source_names": ["unified-db", "unified-db"],
        "resolved_scope_digest": resolved_scope_digest(scope_obj),
        "source_manifest_digest": scope_obj.source_manifest_digest,
    }
    body["manifest_digest"] = canonical_ledger_digest("migration-cohort-manifest-v1", body)
    with pytest.raises(InvalidContractValue, match="unique"):
        MigrationCohortManifestV1.from_mapping(body)


def test_g018_a3_empty_source_names_refuse_construction() -> None:
    scope_obj = _scope()
    body = {
        "manifest_version": COHORT_MANIFEST_V1,
        "workspace_ref": ref("workspace", "cutover-rt"),
        "cohort_state": "CUTOVER_READY",
        "source_names": [],
        "resolved_scope_digest": resolved_scope_digest(scope_obj),
        "source_manifest_digest": scope_obj.source_manifest_digest,
    }
    body["manifest_digest"] = canonical_ledger_digest("migration-cohort-manifest-v1", body)
    with pytest.raises(InvalidContractValue, match="non-empty"):
        MigrationCohortManifestV1.from_mapping(body)


# ---------------------------------------------------------------------------
# A4 -- illegal cohort transitions
# ---------------------------------------------------------------------------


def _illegal_pairs() -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for cur in _COHORT_STATES:
        allowed = _ALLOWED_TRANSITIONS[cur]
        for nxt in _COHORT_STATES:
            if nxt == cur:
                continue
            if nxt not in allowed:
                pairs.append((cur, nxt))
    return pairs


_HIGH_VALUE_ILLEGAL = [
    ("CUTOVER_READY", "CANONICAL_MUTATED"),
    ("CUTOVER_READY", "DECOMMISSIONED"),
    ("CUTOVER_READY", "ROLLBACK_CLOSED"),
    ("READY_NON_SERVING", "ROUTE_SWITCHED_NO_MUTATION"),
    ("READY_NON_SERVING", "CANONICAL_MUTATED"),
    ("DISCOVERED", "CUTOVER_READY"),
    ("DISCOVERED", "ROUTE_SWITCHED_NO_MUTATION"),
    ("IMPORTING", "CUTOVER_READY"),
    ("ROUTE_SWITCHED_NO_MUTATION", "DECOMMISSIONED"),
    ("ROUTE_SWITCHED_NO_MUTATION", "ROLLBACK_CLOSED"),
    ("CANONICAL_MUTATED", "ROLLED_BACK_RECONCILE"),
    ("CANONICAL_MUTATED", "DECOMMISSIONED"),
    ("CANONICAL_MUTATED", "ROUTE_SWITCHED_NO_MUTATION"),
    ("ROLLBACK_CLOSED", "ROLLED_BACK_RECONCILE"),
    ("ROLLBACK_CLOSED", "CANONICAL_MUTATED"),
    ("DECOMMISSIONED", "DISCOVERED"),
    ("DECOMMISSIONED", "IMPORTING"),
    ("ROLLED_BACK_RECONCILE", "CUTOVER_READY"),
    ("ROLLED_BACK_RECONCILE", "ROUTE_SWITCHED_NO_MUTATION"),
]


@pytest.mark.parametrize("current,nxt", _HIGH_VALUE_ILLEGAL, ids=lambda p: f"{p[0]}__{p[1]}" if isinstance(p, tuple) else str(p))
def test_g018_a4_illegal_cohort_transition_refuses(current: str, nxt: str) -> None:
    with pytest.raises(InvalidContractValue, match="illegal cohort transition"):
        assert_cohort_transition(current, nxt)


@pytest.mark.parametrize(
    "current,nxt",
    [
        ("DISCOVERED", "IMPORTING"),
        ("IMPORTING", "QUARANTINED_ITEM"),
        ("IMPORTING", "RECONCILING"),
        ("IMPORTING", "READY_NON_SERVING"),
        ("QUARANTINED_ITEM", "IMPORTING"),
        ("QUARANTINED_ITEM", "RECONCILING"),
        ("RECONCILING", "IMPORTING"),
        ("RECONCILING", "READY_NON_SERVING"),
        ("READY_NON_SERVING", "CUTOVER_READY"),
        ("CUTOVER_READY", "ROUTE_SWITCHED_NO_MUTATION"),
        ("ROUTE_SWITCHED_NO_MUTATION", "CANONICAL_MUTATED"),
        ("ROUTE_SWITCHED_NO_MUTATION", "ROLLED_BACK_RECONCILE"),
        ("CANONICAL_MUTATED", "ROLLBACK_CLOSED"),
        ("ROLLBACK_CLOSED", "DECOMMISSIONED"),
        ("ROLLED_BACK_RECONCILE", "IMPORTING"),
    ],
    ids=lambda p: f"{p[0]}->{p[1]}" if isinstance(p, tuple) else str(p),
)
def test_g018_a4_legal_cohort_transition_accepted(current: str, nxt: str) -> None:
    assert_cohort_transition(current, nxt)


def test_g018_a4_self_transition_refuses() -> None:
    for state in _COHORT_STATES:
        with pytest.raises(InvalidContractValue, match="illegal cohort transition"):
            assert_cohort_transition(state, state)


def test_g018_a4_unknown_state_refuses() -> None:
    with pytest.raises(InvalidContractValue, match="unknown cohort state"):
        assert_cohort_transition("CUTOVER_READY", "LIVE_PRODUCTION")
    with pytest.raises(InvalidContractValue, match="unknown cohort state"):
        assert_cohort_transition("PHANTOM", "IMPORTING")


def test_g018_a4_skip_ahead_cutover_ready_to_canonical_is_illegal() -> None:
    """Cannot skip ROUTE_SWITCHED_NO_MUTATION."""
    with pytest.raises(InvalidContractValue, match="illegal cohort transition"):
        assert_cohort_transition("CUTOVER_READY", "CANONICAL_MUTATED")


def test_g018_a4_decommissioned_is_terminal() -> None:
    for nxt in _COHORT_STATES:
        with pytest.raises(InvalidContractValue, match="illegal cohort transition"):
            assert_cohort_transition("DECOMMISSIONED", nxt)


# ---------------------------------------------------------------------------
# A5 -- live route switch without human approvals / with formula fail
# ---------------------------------------------------------------------------


def test_g018_a5_live_switch_without_human_approvals_refuses() -> None:
    scope_obj = _scope()
    decision = _decision(scope_obj, _cohort(scope_obj))
    with pytest.raises(InvalidContractValue, match="human-controlled external approvals"):
        assert_live_route_switch_authorized(decision, human_external_approvals_present=False)


def test_g018_a5_live_switch_with_formula_fail_refuses_even_with_approvals() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    failed = _decision(scope_obj, cohort, observation_days=2, formula_pass=False)
    assert failed.formula_pass is False
    with pytest.raises(InvalidContractValue, match="formula_pass is false"):
        assert_live_route_switch_authorized(failed, human_external_approvals_present=True)
    with pytest.raises(InvalidContractValue, match="formula_pass is false"):
        assert_live_route_switch_authorized(failed, human_external_approvals_present=False)


def test_g018_a5_live_switch_honest_path_accepted() -> None:
    scope_obj = _scope()
    decision = _decision(scope_obj, _cohort(scope_obj))
    assert_live_route_switch_authorized(decision, human_external_approvals_present=True)


def test_g018_a5_join_requires_cutover_ready_or_route_switched() -> None:
    scope_obj = _scope()
    for bad_state in (
        "DISCOVERED",
        "IMPORTING",
        "READY_NON_SERVING",
        "CANONICAL_MUTATED",
        "ROLLBACK_CLOSED",
        "DECOMMISSIONED",
        "ROLLED_BACK_RECONCILE",
    ):
        cohort = _cohort(scope_obj, state=bad_state)
        decision = _decision(scope_obj, cohort)
        with pytest.raises(InvalidContractValue, match="CUTOVER_READY"):
            assert_cutover_decision_joins_scope_and_cohort(
                decision, scope_obj, cohort, contract_digest=digest("contract")
            )


def test_g018_a5_join_refuses_when_formula_pass_false() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj, state="CUTOVER_READY")
    decision = _decision(scope_obj, cohort, safety=1, formula_pass=False)
    with pytest.raises(InvalidContractValue, match="formula_pass is false"):
        assert_cutover_decision_joins_scope_and_cohort(
            decision, scope_obj, cohort, contract_digest=digest("contract")
        )


def test_g018_a5_join_accepts_route_switched_no_mutation() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj, state="ROUTE_SWITCHED_NO_MUTATION")
    decision = _decision(scope_obj, cohort)
    assert_cutover_decision_joins_scope_and_cohort(
        decision, scope_obj, cohort, contract_digest=digest("contract")
    )


# ---------------------------------------------------------------------------
# A6 -- decommission before 90d / wrong state / missing evidence or approvals
# ---------------------------------------------------------------------------


def test_g018_a6_decommission_before_90_days_refuses() -> None:
    for days in (0, 1, 30, 89):
        with pytest.raises(InvalidContractValue, match="90-day"):
            assert_destructive_decommission_authorized(
                "ROLLBACK_CLOSED",
                retention_days_elapsed=days,
                evidence_backed=True,
                human_external_approvals_present=True,
            )


def test_g018_a6_decommission_at_exact_90_with_approvals_accepted() -> None:
    assert_destructive_decommission_authorized(
        "ROLLBACK_CLOSED",
        retention_days_elapsed=90,
        evidence_backed=True,
        human_external_approvals_present=True,
    )


def test_g018_a6_decommission_without_human_approvals_refuses() -> None:
    with pytest.raises(InvalidContractValue, match="human-controlled external approvals"):
        assert_destructive_decommission_authorized(
            "ROLLBACK_CLOSED",
            retention_days_elapsed=90,
            evidence_backed=True,
            human_external_approvals_present=False,
        )


def test_g018_a6_decommission_without_evidence_refuses() -> None:
    with pytest.raises(InvalidContractValue, match="evidence-backed"):
        assert_destructive_decommission_authorized(
            "ROLLBACK_CLOSED",
            retention_days_elapsed=90,
            evidence_backed=False,
            human_external_approvals_present=True,
        )


@pytest.mark.parametrize(
    "state",
    [
        "DISCOVERED",
        "IMPORTING",
        "READY_NON_SERVING",
        "CUTOVER_READY",
        "ROUTE_SWITCHED_NO_MUTATION",
        "CANONICAL_MUTATED",
        "ROLLED_BACK_RECONCILE",
        "DECOMMISSIONED",
    ],
)
def test_g018_a6_decommission_from_wrong_state_refuses(state: str) -> None:
    with pytest.raises(InvalidContractValue, match="ROLLBACK_CLOSED"):
        assert_destructive_decommission_authorized(
            state,
            retention_days_elapsed=90,
            evidence_backed=True,
            human_external_approvals_present=True,
        )


def test_g018_a6_decommission_compound_failure_prefers_state_gate() -> None:
    """Wrong state is checked before retention; still fail-closed."""
    with pytest.raises(InvalidContractValue, match="ROLLBACK_CLOSED"):
        assert_destructive_decommission_authorized(
            "CANONICAL_MUTATED",
            retention_days_elapsed=0,
            evidence_backed=False,
            human_external_approvals_present=False,
        )


# ---------------------------------------------------------------------------
# A7 -- post-mutation external rollback / pre-mutation boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", list(_POST_MUTATION_STATES))
def test_g018_a7_post_mutation_external_rollback_refuses(state: str) -> None:
    with pytest.raises(InvalidContractValue, match="external rollback is closed"):
        assert_post_mutation_fail_closed(state, action="external_rollback")


@pytest.mark.parametrize(
    "state",
    [
        "DISCOVERED",
        "IMPORTING",
        "READY_NON_SERVING",
        "CUTOVER_READY",
        "ROUTE_SWITCHED_NO_MUTATION",
        "ROLLED_BACK_RECONCILE",
    ],
)
def test_g018_a7_pre_mutation_states_allow_external_rollback_action_check(state: str) -> None:
    """assert_post_mutation_fail_closed only closes after mutation; earlier is a no-op."""
    assert_post_mutation_fail_closed(state, action="external_rollback")


def test_g018_a7_pre_mutation_rollback_only_from_route_switched() -> None:
    assert_pre_mutation_rollback_allowed("ROUTE_SWITCHED_NO_MUTATION")
    for state in _COHORT_STATES:
        if state == "ROUTE_SWITCHED_NO_MUTATION":
            continue
        with pytest.raises(InvalidContractValue, match="pre-mutation rollback"):
            assert_pre_mutation_rollback_allowed(state)


def test_g018_a7_post_mutation_non_rollback_action_is_not_closed_by_this_gate() -> None:
    """Gate is action-specific; non-rollback actions do not trip the close."""
    for state in _POST_MUTATION_STATES:
        assert_post_mutation_fail_closed(state, action="reconcile")
        assert_post_mutation_fail_closed(state, action="inspect")


def test_g018_a7_cannot_transition_canonical_mutated_to_rolled_back() -> None:
    with pytest.raises(InvalidContractValue, match="illegal cohort transition"):
        assert_cohort_transition("CANONICAL_MUTATED", "ROLLED_BACK_RECONCILE")


# ---------------------------------------------------------------------------
# A8 -- scope / cohort / contract digest mismatches
# ---------------------------------------------------------------------------


def test_g018_a8_cohort_resolved_scope_digest_mismatch_refuses() -> None:
    scope_obj = _scope()
    # Different capability digest → different resolved_scope_digest (allowed field).
    other = _scope(capability_manifest_digest=digest("other-capability-for-scope"))
    cohort = _cohort(scope_obj, resolved_scope_digest_value=resolved_scope_digest(other))
    with pytest.raises(InvalidContractValue, match="cohort resolved_scope_digest mismatch"):
        assert_cohort_subset_of_enabled_migration_sources(cohort, scope_obj)


def test_g018_a8_cohort_source_manifest_digest_mismatch_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj, source_manifest_digest=digest("other-source-manifest"))
    with pytest.raises(InvalidContractValue, match="cohort source_manifest_digest mismatch"):
        assert_cohort_subset_of_enabled_migration_sources(cohort, scope_obj)


def test_g018_a8_decision_resolved_scope_digest_mismatch_on_join_refuses() -> None:
    scope_obj = _scope()
    other = _scope(capability_manifest_digest=digest("other-capability-for-scope"))
    cohort = _cohort(scope_obj)
    # Bind decision to other scope digest while presenting original scope.
    decision = _decision(
        scope_obj,
        cohort,
        resolved_scope_digest_value=resolved_scope_digest(other),
    )
    with pytest.raises(InvalidContractValue, match="resolved_scope_digest mismatch"):
        assert_cutover_decision_joins_scope_and_cohort(
            decision, scope_obj, cohort, contract_digest=digest("contract")
        )


def test_g018_a8_decision_contract_digest_mismatch_on_join_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    decision = _decision(scope_obj, cohort, contract_digest=digest("contract-a"))
    with pytest.raises(InvalidContractValue, match="contract_digest mismatch"):
        assert_cutover_decision_joins_scope_and_cohort(
            decision, scope_obj, cohort, contract_digest=digest("contract-b")
        )


def test_g018_a8_decision_cohort_manifest_digest_mismatch_on_join_refuses() -> None:
    scope_obj = _scope()
    cohort_a = _cohort(scope_obj, sources=("unified-db",))
    cohort_b = _cohort(scope_obj, sources=("me-wiki",))
    decision = _decision(scope_obj, cohort_a)
    with pytest.raises(InvalidContractValue, match="cohort_manifest_digest mismatch"):
        assert_cutover_decision_joins_scope_and_cohort(
            decision, scope_obj, cohort_b, contract_digest=digest("contract")
        )


def test_g018_a8_decision_source_manifest_digest_mismatch_on_join_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    decision = _decision(
        scope_obj,
        cohort,
        source_manifest_digest=digest("foreign-source"),
    )
    with pytest.raises(InvalidContractValue, match="source_manifest_digest mismatch"):
        assert_cutover_decision_joins_scope_and_cohort(
            decision, scope_obj, cohort, contract_digest=digest("contract")
        )


def test_g018_a8_decision_capability_manifest_digest_mismatch_on_join_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    decision = _decision(
        scope_obj,
        cohort,
        capability_manifest_digest=digest("foreign-capability"),
    )
    with pytest.raises(InvalidContractValue, match="capability_manifest_digest mismatch"):
        assert_cutover_decision_joins_scope_and_cohort(
            decision, scope_obj, cohort, contract_digest=digest("contract")
        )


def test_g018_a8_honest_join_accepted() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj, state="CUTOVER_READY")
    decision = _decision(scope_obj, cohort)
    assert_cutover_decision_joins_scope_and_cohort(
        decision, scope_obj, cohort, contract_digest=digest("contract")
    )
    assert_cohort_subset_of_enabled_migration_sources(cohort, scope_obj)


# ---------------------------------------------------------------------------
# A9 -- digest tamper
# ---------------------------------------------------------------------------


def test_g018_a9_decision_digest_tamper_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    body = _decision_body(scope_obj, cohort)
    body["decision_digest"] = digest("tampered-decision")
    with pytest.raises(InvalidContractValue, match="decision_digest does not bind"):
        CutoverDecisionV1.from_mapping(body)


def test_g018_a9_decision_body_field_swap_without_redigest_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    body = _decision_body(scope_obj, cohort)
    body["observation_days"] = 30  # leave decision_digest stale
    with pytest.raises(InvalidContractValue, match="decision_digest does not bind"):
        CutoverDecisionV1.from_mapping(body)


def test_g018_a9_decision_formula_pass_flip_without_redigest_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    body = _decision_body(scope_obj, cohort)
    assert body["formula_pass"] is True
    body["formula_pass"] = False  # stale digest + formula mismatch either way
    with pytest.raises(InvalidContractValue, match="formula_pass does not match|decision_digest does not bind"):
        CutoverDecisionV1.from_mapping(body)


def test_g018_a9_decision_approver_swap_without_redigest_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    body = _decision_body(scope_obj, cohort)
    # Swap roles order is fine after sort, so change content via case only then
    # force a role set that survives lowercase sort to the same set — instead
    # drop a role in body while keeping stale digest.
    body["approver_roles"] = ["migration", "quality", "security"]
    with pytest.raises(InvalidContractValue, match="approver_roles|decision_digest"):
        CutoverDecisionV1.from_mapping(body)


def test_g018_a9_cohort_manifest_digest_tamper_refuses() -> None:
    scope_obj = _scope()
    body = {
        "manifest_version": COHORT_MANIFEST_V1,
        "workspace_ref": ref("workspace", "cutover-rt"),
        "cohort_state": "CUTOVER_READY",
        "source_names": ["unified-db"],
        "resolved_scope_digest": resolved_scope_digest(scope_obj),
        "source_manifest_digest": scope_obj.source_manifest_digest,
    }
    body["manifest_digest"] = digest("tampered-cohort")
    with pytest.raises(InvalidContractValue, match="manifest_digest does not bind"):
        MigrationCohortManifestV1.from_mapping(body)


def test_g018_a9_cohort_body_field_swap_without_redigest_refuses() -> None:
    scope_obj = _scope()
    body = {
        "manifest_version": COHORT_MANIFEST_V1,
        "workspace_ref": ref("workspace", "cutover-rt"),
        "cohort_state": "CUTOVER_READY",
        "source_names": ["unified-db"],
        "resolved_scope_digest": resolved_scope_digest(scope_obj),
        "source_manifest_digest": scope_obj.source_manifest_digest,
    }
    body["manifest_digest"] = canonical_ledger_digest("migration-cohort-manifest-v1", body)
    body["cohort_state"] = "ROUTE_SWITCHED_NO_MUTATION"  # stale digest
    with pytest.raises(InvalidContractValue, match="manifest_digest does not bind"):
        MigrationCohortManifestV1.from_mapping(body)


def test_g018_a9_decision_digest_not_sha256_hex_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    body = _decision_body(scope_obj, cohort)
    body["decision_digest"] = "not-a-digest"
    with pytest.raises(InvalidContractValue, match="sha256"):
        CutoverDecisionV1.from_mapping(body)


def test_g018_a9_decision_digest_uppercase_hex_refuses() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    body = _decision_body(scope_obj, cohort)
    body["decision_digest"] = body["decision_digest"].upper()
    with pytest.raises(InvalidContractValue, match="sha256"):
        CutoverDecisionV1.from_mapping(body)


def test_g018_a9_round_trip_honest_decision_and_cohort_bind() -> None:
    scope_obj = _scope()
    cohort = _cohort(scope_obj)
    decision = _decision(scope_obj, cohort)
    again = CutoverDecisionV1.from_mapping(decision.to_mapping())
    assert again.decision_digest == decision.decision_digest
    again_cohort = MigrationCohortManifestV1.from_mapping(cohort.to_mapping())
    assert again_cohort.manifest_digest == cohort.manifest_digest
    assert_cutover_decision_joins_scope_and_cohort(
        again, scope_obj, again_cohort, contract_digest=digest("contract")
    )
    assert_live_route_switch_authorized(again, human_external_approvals_present=True)


def test_g018_a3_multi_source_cohort_refuses_construction() -> None:
    scope_obj = _scope()
    with pytest.raises(InvalidContractValue, match="exactly one migration source"):
        _cohort(scope_obj, sources=("unified-db", "me-wiki"))
