"""Adversarial / red-team suite for G016: Stage-4 evaluation governance isolation.

Surface: API / package / algorithm. Prove isolation fail-closed across the nine
frozen attack classes (benchmark bleed, shared keys/capabilities, corpus overlap,
SLO minima, external reflection, export gates, support withdrawal, governance
digest integrity, live LifecycleLedgerAuthority isolation proof).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from test_decision_contracts import scope
from test_stage3_ledger_persistence import (
    KEY_ID,
    NOW,
    SIGNER_REF,
    blob,
    create_and_approve,
    digest,
    ref,
    request,
    signed_snapshot_signer,
    store,
    trust_for_request,
)
from wiki_spike.applications.second_brain_evaluation_service import (
    EvaluationGovernanceError,
    SecondBrainEvaluationService,
)
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_evaluation_contracts import (
    BENCHMARK_MANIFEST_V1,
    EVALUATION_GOVERNANCE_V1,
    HOLDOUT_MANIFEST_V1,
    MANAGED_PROJECTION_V1,
    RECALL_SLO_V1,
    REFLECTION_PROPOSAL_V1,
    BenchmarkManifestV1,
    EvaluationGovernanceV1,
    HoldoutManifestV1,
    ManagedProjectionV1,
    RecallSloV1,
    ReflectionProposalV1,
    assert_evaluation_isolated_from_serving,
    assert_projection_export_allowed,
    assert_reflection_allowed,
    canonical_ledger_digest,
    invalidate_reflection_support,
)


# ---------------------------------------------------------------------------
# Fixtures / builders (mirror Stage-4 governance helpers; adversarial variants)
# ---------------------------------------------------------------------------


def _workspace() -> str:
    return ref("workspace", "eval-rt")


def _benchmark(
    *,
    items: tuple[str, ...] = (digest("rt-bench-1"), digest("rt-bench-2")),
    key: str = "rt-bench",
    capability: str | None = None,
    workspace: str | None = None,
) -> BenchmarkManifestV1:
    body = {
        "manifest_version": BENCHMARK_MANIFEST_V1,
        "workspace_ref": workspace or _workspace(),
        "corpus_key_ref": ref("key", key),
        "capability_ref": ref("capability", capability or key),
        "item_digests": list(items),
        "label_review_digest": digest("rt-labels"),
        "consent_digest": digest("rt-consent"),
    }
    body["manifest_digest"] = canonical_ledger_digest("benchmark-manifest-v1", body)
    return BenchmarkManifestV1.from_mapping(body)


def _holdout(
    *,
    items: tuple[str, ...] = (digest("rt-hold-1"),),
    key: str = "rt-hold",
    capability: str | None = None,
    workspace: str | None = None,
) -> HoldoutManifestV1:
    body = {
        "manifest_version": HOLDOUT_MANIFEST_V1,
        "workspace_ref": workspace or _workspace(),
        "holdout_key_ref": ref("key", key),
        "capability_ref": ref("capability", capability or key),
        "item_digests": list(items),
        "separation_digest": digest("rt-separation"),
    }
    body["manifest_digest"] = canonical_ledger_digest("holdout-manifest-v1", body)
    return HoldoutManifestV1.from_mapping(body)


def _slo(**overrides: object) -> RecallSloV1:
    body: dict[str, object] = {
        "slo_version": RECALL_SLO_V1,
        "parity_min_bps": 9000,
        "citation_min_bps": 9000,
        "completeness_min_bps": 9000,
        "availability_min_bps": 9900,
        "max_safety_violations": 0,
        "min_shadow_days": 3,
        "min_parity_cases_per_source": 200,
        "min_cohort_e2e_queries": 500,
        "confidence_method": "one-sided-wilson-95",
        "include_invalid_in_denominator": True,
        "include_abstained_in_denominator": True,
        "include_source_unavailable_in_denominator": True,
    }
    body.update(overrides)
    digest_body = {k: v for k, v in body.items() if k != "slo_digest"}
    body["slo_digest"] = canonical_ledger_digest("recall-slo-v1", digest_body)
    return RecallSloV1.from_mapping(body)


def _governance(
    benchmark: BenchmarkManifestV1,
    holdout: HoldoutManifestV1,
    slo: RecallSloV1,
    *,
    workspace: str | None = None,
    serving_corpus_digest: str | None = None,
) -> EvaluationGovernanceV1:
    body = {
        "governance_version": EVALUATION_GOVERNANCE_V1,
        "workspace_ref": workspace or benchmark.workspace_ref,
        "benchmark_manifest_digest": benchmark.manifest_digest,
        "holdout_manifest_digest": holdout.manifest_digest,
        "slo_digest": slo.slo_digest,
        "consent_digest": benchmark.consent_digest,
        "encryption_isolation_digest": digest("rt-enc-isolation"),
        "serving_corpus_digest": serving_corpus_digest or digest("rt-serving-corpus"),
    }
    body["governance_digest"] = canonical_ledger_digest("evaluation-governance-v1", body)
    return EvaluationGovernanceV1.from_mapping(body)


def _scope(**overrides: object) -> ResolvedScopeV1:
    raw = scope()
    raw.update(overrides)
    return ResolvedScopeV1.from_mapping(raw)


def _proposal(
    *,
    proposal: str = "p1",
    supports: tuple[str, ...] = (ref("candidate", "s1"),),
    local: bool = True,
    route: str | None = None,
    workspace: str | None = None,
) -> ReflectionProposalV1:
    body = {
        "proposal_version": REFLECTION_PROPOSAL_V1,
        "workspace_ref": workspace or _workspace(),
        "proposal_ref": ref("proposal", proposal),
        "support_candidate_refs": list(supports),
        "rationale_digest": digest(f"rt-rationale-{proposal}"),
        "local_only": local,
        "external_route": route,
    }
    body["proposal_digest"] = canonical_ledger_digest("reflection-proposal-v1", body)
    return ReflectionProposalV1.from_mapping(body)


def _projection(
    *,
    projection: str = "m1",
    withheld: bool = False,
    destination: str | None = None,
    workspace: str | None = None,
) -> ManagedProjectionV1:
    body = {
        "projection_version": MANAGED_PROJECTION_V1,
        "workspace_ref": workspace or _workspace(),
        "projection_ref": ref("projection", projection),
        "schema_version": "managed-identity-v1",
        "source_generation_digest": digest("rt-gen"),
        "artifact_digest": digest(f"rt-artifact-{projection}"),
        "withheld": withheld,
        "export_destination": destination,
    }
    body["projection_digest"] = canonical_ledger_digest("managed-projection-v1", body)
    return ManagedProjectionV1.from_mapping(body)


def _stack(
    *,
    benchmark: BenchmarkManifestV1 | None = None,
    holdout: HoldoutManifestV1 | None = None,
    slo: RecallSloV1 | None = None,
    scope_obj: ResolvedScopeV1 | None = None,
    recall=None,
):
    benchmark = benchmark or _benchmark()
    holdout = holdout or _holdout()
    slo = slo or _slo()
    governance = _governance(benchmark, holdout, slo)
    service = SecondBrainEvaluationService(
        scope=scope_obj or _scope(),
        governance=governance,
        benchmark=benchmark,
        holdout=holdout,
        slo=slo,
        recall=recall,
    )
    return governance, benchmark, holdout, slo, service


# ---------------------------------------------------------------------------
# A1 -- benchmark item digest injected as serving content_digest
# ---------------------------------------------------------------------------


def test_g016_a1_benchmark_item_injected_as_serving_content_digest_refuses() -> None:
    benchmark, holdout, slo = _benchmark(), _holdout(), _slo()
    governance = _governance(benchmark, holdout, slo)
    injected = benchmark.item_digests[0]
    with pytest.raises(InvalidContractValue, match="serving corpus"):
        assert_evaluation_isolated_from_serving(
            governance,
            benchmark,
            holdout,
            serving_candidate_content_digests=(injected, digest("unrelated-served")),
        )


def test_g016_a1_holdout_item_injected_as_serving_content_digest_refuses() -> None:
    benchmark, holdout, slo = _benchmark(), _holdout(), _slo()
    governance = _governance(benchmark, holdout, slo)
    with pytest.raises(InvalidContractValue, match="serving corpus"):
        assert_evaluation_isolated_from_serving(
            governance,
            benchmark,
            holdout,
            serving_candidate_content_digests=(holdout.item_digests[0],),
        )


def test_g016_a1_service_live_proof_wraps_injected_eval_item_as_governance_error(
    tmp_path: Path,
) -> None:
    """When a live snapshot would surface an evaluation item digest, the service
    fail-closes via EvaluationGovernanceError (not a silent pass)."""
    database, cas, ledger, workspace = store(tmp_path)
    # Craft a benchmark whose item_digests deliberately include a future serving
    # content digest by first materializing the serving blob, then binding it.
    serving_digest = blob(cas, "would-be-eval-bleed")
    candidate = ref("candidate", "bleed")
    create_and_approve(ledger, cas, candidate, "would-be-eval-bleed", workspace=workspace)

    benchmark = _benchmark(items=(serving_digest, digest("rt-bench-other")), workspace=workspace)
    holdout = _holdout(workspace=workspace)
    slo = _slo()
    governance = _governance(benchmark, holdout, slo, workspace=workspace)
    req = request(workspace, recorded_at=NOW)
    authority = LifecycleLedgerAuthority(
        database,
        cas,
        trust_for_request(req),
        signed_snapshot_signer,
        signer_ref=SIGNER_REF,
        key_id=KEY_ID,
    )
    service = SecondBrainEvaluationService(
        scope=_scope(),
        governance=governance,
        benchmark=benchmark,
        holdout=holdout,
        slo=slo,
        recall=authority,
    )
    with pytest.raises(EvaluationGovernanceError, match="serving corpus"):
        service.prove_isolation_against_serving(req)
    database.close()


# ---------------------------------------------------------------------------
# A2 -- shared key or capability between benchmark / holdout / serving
# ---------------------------------------------------------------------------


def test_g016_a2_shared_benchmark_holdout_key_refuses() -> None:
    shared_key = "shared-key"
    with pytest.raises(InvalidContractValue, match="keys must be distinct"):
        assert_evaluation_isolated_from_serving(
            _governance(_benchmark(key=shared_key), _holdout(key=shared_key), _slo()),
            _benchmark(key=shared_key),
            _holdout(key=shared_key),
        )


def test_g016_a2_shared_benchmark_holdout_capability_refuses() -> None:
    # Distinct keys but identical capability refs.
    benchmark = _benchmark(key="bk", capability="shared-cap")
    holdout = _holdout(key="hk", capability="shared-cap")
    governance = _governance(benchmark, holdout, _slo())
    with pytest.raises(InvalidContractValue, match="capabilities must be distinct"):
        assert_evaluation_isolated_from_serving(governance, benchmark, holdout)


def test_g016_a2_evaluation_key_appearing_as_serving_key_refuses() -> None:
    benchmark, holdout, slo = _benchmark(), _holdout(), _slo()
    governance = _governance(benchmark, holdout, slo)
    with pytest.raises(InvalidContractValue, match="serving keys"):
        assert_evaluation_isolated_from_serving(
            governance,
            benchmark,
            holdout,
            serving_key_refs=(benchmark.corpus_key_ref, ref("key", "honest-serving")),
        )
    with pytest.raises(InvalidContractValue, match="serving keys"):
        assert_evaluation_isolated_from_serving(
            governance,
            benchmark,
            holdout,
            serving_key_refs=(holdout.holdout_key_ref,),
        )


def test_g016_a2_evaluation_capability_appearing_as_serving_capability_refuses() -> None:
    benchmark, holdout, slo = _benchmark(), _holdout(), _slo()
    governance = _governance(benchmark, holdout, slo)
    with pytest.raises(InvalidContractValue, match="serving capabilities"):
        assert_evaluation_isolated_from_serving(
            governance,
            benchmark,
            holdout,
            serving_capability_refs=(benchmark.capability_ref,),
        )
    with pytest.raises(InvalidContractValue, match="serving capabilities"):
        assert_evaluation_isolated_from_serving(
            governance,
            benchmark,
            holdout,
            serving_capability_refs=(holdout.capability_ref,),
        )


def test_g016_a2_service_constructor_refuses_shared_bench_holdout_identity() -> None:
    shared = "cap-collision"
    benchmark = _benchmark(key="bk2", capability=shared)
    holdout = _holdout(key="hk2", capability=shared)
    slo = _slo()
    governance = _governance(benchmark, holdout, slo)
    with pytest.raises(InvalidContractValue, match="capabilities must be distinct"):
        SecondBrainEvaluationService(
            scope=_scope(),
            governance=governance,
            benchmark=benchmark,
            holdout=holdout,
            slo=slo,
        )


# ---------------------------------------------------------------------------
# A3 -- overlapping benchmark / holdout item sets
# ---------------------------------------------------------------------------


def test_g016_a3_overlapping_benchmark_holdout_item_sets_refuse() -> None:
    shared_item = digest("overlap-item")
    benchmark = _benchmark(items=(shared_item, digest("bench-only")))
    holdout = _holdout(items=(shared_item, digest("hold-only")))
    governance = _governance(benchmark, holdout, _slo())
    with pytest.raises(InvalidContractValue, match="disjoint"):
        assert_evaluation_isolated_from_serving(governance, benchmark, holdout)


def test_g016_a3_holdout_is_exact_subset_of_benchmark_still_refuses() -> None:
    items = (digest("a"), digest("b"), digest("c"))
    benchmark = _benchmark(items=items)
    holdout = _holdout(items=(items[1],))
    governance = _governance(benchmark, holdout, _slo())
    with pytest.raises(InvalidContractValue, match="disjoint"):
        assert_evaluation_isolated_from_serving(governance, benchmark, holdout)


# ---------------------------------------------------------------------------
# A4 -- SLO below plan minima
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("min_shadow_days", 2, "out of required range"),
        ("min_parity_cases_per_source", 199, "out of required range"),
        ("min_cohort_e2e_queries", 499, "out of required range"),
        ("max_safety_violations", 1, "out of required range"),
        ("include_invalid_in_denominator", False, "must be true"),
        ("include_abstained_in_denominator", False, "must be true"),
        ("include_source_unavailable_in_denominator", False, "must be true"),
    ],
)
def test_g016_a4_slo_below_plan_minima_refuses_construction(
    field: str, value: object, match: str
) -> None:
    with pytest.raises(InvalidContractValue, match=match):
        _slo(**{field: value})


def test_g016_a4_slo_at_exact_plan_minima_constructs() -> None:
    slo = _slo(
        min_shadow_days=3,
        min_parity_cases_per_source=200,
        min_cohort_e2e_queries=500,
        max_safety_violations=0,
    )
    assert slo.min_shadow_days == 3
    assert slo.min_parity_cases_per_source == 200
    assert slo.min_cohort_e2e_queries == 500
    assert slo.max_safety_violations == 0
    assert slo.include_invalid_in_denominator is True


# ---------------------------------------------------------------------------
# A5 -- external reflection when route disabled; local still ok
# ---------------------------------------------------------------------------


def test_g016_a5_external_reflection_disabled_route_refuses_local_ok() -> None:
    enabled = _scope(
        enabled_external_model_routes=["model-a"],
        disabled_external_model_routes={},
    )
    disabled = _scope(
        enabled_external_model_routes=[],
        disabled_external_model_routes={"model-a": "owner-off", "model-b": "owner-off"},
    )
    local = _proposal(local=True)
    external_a = _proposal(local=False, route="model-a")
    external_unknown = _proposal(proposal="p-unknown", local=False, route="model-z")

    assert_reflection_allowed(enabled, local)
    assert_reflection_allowed(disabled, local)
    assert_reflection_allowed(enabled, external_a)

    with pytest.raises(InvalidContractValue, match="disabled by resolved scope"):
        assert_reflection_allowed(disabled, external_a)
    with pytest.raises(InvalidContractValue, match="disabled by resolved scope"):
        assert_reflection_allowed(enabled, external_unknown)


def test_g016_a5_service_submit_reflection_fail_closed_on_disabled_route() -> None:
    _, _, _, _, ok_service = _stack(
        scope_obj=_scope(
            enabled_external_model_routes=["model-a"],
            disabled_external_model_routes={},
        )
    )
    assert ok_service.submit_reflection(_proposal(local=True)).local_only is True
    assert ok_service.submit_reflection(
        _proposal(proposal="ext", local=False, route="model-a")
    ).external_route == "model-a"

    _, _, _, _, blocked = _stack(
        scope_obj=_scope(
            enabled_external_model_routes=[],
            disabled_external_model_routes={"model-a": "no"},
        )
    )
    with pytest.raises(EvaluationGovernanceError, match="disabled by resolved scope"):
        blocked.submit_reflection(_proposal(proposal="blocked", local=False, route="model-a"))
    # Local path remains open on the same blocked-external scope.
    assert blocked.submit_reflection(
        _proposal(proposal="still-local", local=True)
    ).local_only is True


# ---------------------------------------------------------------------------
# A6 -- export to disabled/unknown destination; withhold then export
# ---------------------------------------------------------------------------


def test_g016_a6_export_to_disabled_or_unknown_destination_refuses() -> None:
    allowed = _scope(egress_destinations=["archive"], disabled_export_destinations={})
    disabled = _scope(
        egress_destinations=[],
        disabled_export_destinations={"archive": "owner-off"},
    )
    unknown = _projection(destination="s3-exfil")
    known = _projection(destination="archive")

    assert_projection_export_allowed(allowed, _projection())  # internal ok
    assert_projection_export_allowed(allowed, known)

    with pytest.raises(InvalidContractValue, match="disabled by resolved scope"):
        assert_projection_export_allowed(allowed, unknown)
    with pytest.raises(InvalidContractValue, match="disabled by resolved scope"):
        assert_projection_export_allowed(disabled, known)


def test_g016_a6_withheld_projection_cannot_name_or_export_destination() -> None:
    scope_obj = _scope(egress_destinations=["archive"], disabled_export_destinations={})
    # Construction refuse: withheld + destination.
    with pytest.raises(InvalidContractValue, match="withheld"):
        _projection(withheld=True, destination="archive")
    # from_mapping itself must refuse an illegal withheld+destination pair even if
    # an attacker rebinds the digest after flipping both fields.
    body = _projection(withheld=False, destination="archive").to_mapping()
    body["withheld"] = True
    body["projection_digest"] = canonical_ledger_digest(
        "managed-projection-v1",
        {k: v for k, v in body.items() if k != "projection_digest"},
    )
    with pytest.raises(InvalidContractValue, match="withheld"):
        ManagedProjectionV1.from_mapping(body)

    # Service path: publish then withhold clears destination; internal rebuild ok.
    governance, benchmark, holdout, slo, service = _stack(scope_obj=scope_obj)
    published = service.publish_projection(_projection(destination="archive"))
    withheld = service.withhold_projection(published.projection_ref)
    assert withheld.withheld is True
    assert withheld.export_destination is None
    # Withheld internal projection (no destination) is still allowed through the gate.
    assert_projection_export_allowed(scope_obj, withheld)
    # Export after withhold: a fresh exportable to an unknown destination is refused.
    with pytest.raises(EvaluationGovernanceError, match="disabled by resolved scope"):
        service.publish_projection(
            _projection(projection="m-unknown", destination="not-a-real-dest")
        )
    # Export after withhold: disabled known destination is refused.
    blocked = SecondBrainEvaluationService(
        scope=_scope(
            egress_destinations=[],
            disabled_export_destinations={"archive": "no"},
        ),
        governance=governance,
        benchmark=benchmark,
        holdout=holdout,
        slo=slo,
    )
    with pytest.raises(EvaluationGovernanceError, match="disabled by resolved scope"):
        blocked.publish_projection(
            _projection(projection="m-disabled-after-withhold", destination="archive")
        )


def test_g016_a6_service_publish_refuses_disabled_destination() -> None:
    _, _, _, _, service = _stack(
        scope_obj=_scope(
            egress_destinations=[],
            disabled_export_destinations={"archive": "no"},
        )
    )
    with pytest.raises(EvaluationGovernanceError, match="disabled by resolved scope"):
        service.publish_projection(_projection(destination="archive"))
    # Internal managed projection still allowed.
    assert service.publish_projection(_projection(projection="internal-ok")).export_destination is None


# ---------------------------------------------------------------------------
# A7 -- support withdrawal removes only dependent proposals
# ---------------------------------------------------------------------------


def test_g016_a7_support_withdrawal_removes_only_dependent_proposals() -> None:
    root = ref("candidate", "root")
    dep = ref("candidate", "dep")
    other = ref("candidate", "other")
    kept = _proposal(proposal="kept", supports=(other,))
    doomed_direct = _proposal(proposal="doomed-direct", supports=(root,))
    doomed_multi = _proposal(proposal="doomed-multi", supports=(dep, root, other))
    also_kept = _proposal(proposal="also-kept", supports=(dep,))  # dep not withdrawn

    remaining = invalidate_reflection_support(
        (kept, doomed_direct, doomed_multi, also_kept),
        (root,),
    )
    assert remaining == (kept, also_kept)

    # Withdraw dep as well; also_kept must drop, kept remains.
    remaining2 = invalidate_reflection_support(remaining, (dep,))
    assert remaining2 == (kept,)


def test_g016_a7_service_withdraw_support_preserves_unrelated_proposals() -> None:
    _, _, _, _, service = _stack()
    alive = ref("candidate", "alive")
    gone = ref("candidate", "gone")
    unrelated = ref("candidate", "unrelated")
    p_alive = service.submit_reflection(_proposal(proposal="p-alive", supports=(alive,)))
    p_gone = service.submit_reflection(_proposal(proposal="p-gone", supports=(gone,)))
    p_both = service.submit_reflection(
        _proposal(proposal="p-both", supports=(alive, gone))
    )
    p_unrelated = service.submit_reflection(
        _proposal(proposal="p-unrelated", supports=(unrelated,))
    )
    remaining = service.withdraw_support((gone,))
    assert {p.proposal_ref for p in remaining} == {
        p_alive.proposal_ref,
        p_unrelated.proposal_ref,
    }
    assert p_gone.proposal_ref not in {p.proposal_ref for p in remaining}
    assert p_both.proposal_ref not in {p.proposal_ref for p in remaining}


# ---------------------------------------------------------------------------
# A8 -- governance digest tamper / mismatched slo_digest
# ---------------------------------------------------------------------------


def test_g016_a8_governance_digest_tamper_refuses_construction() -> None:
    benchmark, holdout, slo = _benchmark(), _holdout(), _slo()
    governance = _governance(benchmark, holdout, slo)
    body = governance.to_mapping()
    body["governance_digest"] = digest("tampered-governance-digest")
    with pytest.raises(InvalidContractValue, match="governance_digest does not bind"):
        EvaluationGovernanceV1.from_mapping(body)


def test_g016_a8_governance_body_field_swap_without_redigest_refuses() -> None:
    benchmark, holdout, slo = _benchmark(), _holdout(), _slo()
    governance = _governance(benchmark, holdout, slo)
    body = governance.to_mapping()
    # Swap serving_corpus_digest while leaving governance_digest stale.
    body["serving_corpus_digest"] = digest("attacker-serving-corpus")
    with pytest.raises(InvalidContractValue, match="governance_digest does not bind"):
        EvaluationGovernanceV1.from_mapping(body)


def test_g016_a8_mismatched_slo_digest_refuses_service_construction() -> None:
    benchmark, holdout = _benchmark(), _holdout()
    slo_a = _slo(parity_min_bps=9000)
    slo_b = _slo(parity_min_bps=9500)
    assert slo_a.slo_digest != slo_b.slo_digest
    governance = _governance(benchmark, holdout, slo_a)
    with pytest.raises(EvaluationGovernanceError, match="does not bind the provided SLO"):
        SecondBrainEvaluationService(
            scope=_scope(),
            governance=governance,
            benchmark=benchmark,
            holdout=holdout,
            slo=slo_b,
        )


def test_g016_a8_slo_digest_tamper_refuses_construction() -> None:
    body = _slo().to_mapping()
    body["slo_digest"] = digest("tampered-slo")
    with pytest.raises(InvalidContractValue, match="slo_digest does not bind"):
        RecallSloV1.from_mapping(body)


def test_g016_a8_benchmark_manifest_digest_tamper_refuses() -> None:
    body = _benchmark().to_mapping()
    body["manifest_digest"] = digest("tampered-bench-manifest")
    with pytest.raises(InvalidContractValue, match="manifest_digest does not bind"):
        BenchmarkManifestV1.from_mapping(body)


def test_g016_a8_governance_unbound_benchmark_manifest_refuses_isolation() -> None:
    benchmark = _benchmark()
    other_benchmark = _benchmark(items=(digest("other-1"),), key="other-bench")
    holdout = _holdout()
    slo = _slo()
    governance = _governance(benchmark, holdout, slo)
    with pytest.raises(InvalidContractValue, match="does not bind the benchmark"):
        assert_evaluation_isolated_from_serving(governance, other_benchmark, holdout)


# ---------------------------------------------------------------------------
# A9 -- live isolation proof against real LifecycleLedgerAuthority snapshot
# ---------------------------------------------------------------------------


def test_g016_a9_live_isolation_proof_passes_when_corpora_disjoint(tmp_path: Path) -> None:
    database, cas, ledger, workspace = store(tmp_path)
    # Two serving candidates whose content digests are NOT evaluation items.
    create_and_approve(
        ledger, cas, ref("candidate", "served-a"), "served-a-body", workspace=workspace
    )
    create_and_approve(
        ledger, cas, ref("candidate", "served-b"), "served-b-body", workspace=workspace
    )

    benchmark = _benchmark(
        items=(digest("rt-bench-live-1"), digest("rt-bench-live-2")),
        workspace=workspace,
    )
    holdout = _holdout(items=(digest("rt-hold-live-1"),), workspace=workspace)
    slo = _slo()
    governance = _governance(benchmark, holdout, slo, workspace=workspace)
    req = request(workspace, recorded_at=NOW)
    authority = LifecycleLedgerAuthority(
        database,
        cas,
        trust_for_request(req),
        signed_snapshot_signer,
        signer_ref=SIGNER_REF,
        key_id=KEY_ID,
    )
    service = SecondBrainEvaluationService(
        scope=_scope(),
        governance=governance,
        benchmark=benchmark,
        holdout=holdout,
        slo=slo,
        recall=authority,
    )
    report = service.prove_isolation_against_serving(req)
    assert report.isolated is True
    assert report.serving_candidate_count == 2
    assert report.benchmark_item_count == 2
    assert report.holdout_item_count == 1
    assert report.governance_digest == governance.governance_digest

    # Positive control: disjoint serving keys/capabilities also pass.
    report2 = service.prove_isolation_against_serving(
        req,
        serving_key_refs=(ref("key", "serving-only"),),
        serving_capability_refs=(ref("capability", "serving-only"),),
    )
    assert report2.isolated is True

    # Negative control on the same live stack: evaluation key as serving key.
    with pytest.raises(EvaluationGovernanceError, match="serving keys"):
        service.prove_isolation_against_serving(
            req,
            serving_key_refs=(benchmark.corpus_key_ref,),
        )
    database.close()


def test_g016_a9_live_isolation_workspace_mismatch_refuses(tmp_path: Path) -> None:
    database, cas, ledger, workspace = store(tmp_path)
    create_and_approve(
        ledger, cas, ref("candidate", "w"), "w-body", workspace=workspace
    )
    # Governance bound to a different workspace than the live request.
    benchmark = _benchmark(workspace=_workspace())
    holdout = _holdout(workspace=_workspace())
    slo = _slo()
    governance = _governance(benchmark, holdout, slo, workspace=_workspace())
    req = request(workspace, recorded_at=NOW)
    authority = LifecycleLedgerAuthority(
        database,
        cas,
        trust_for_request(req),
        signed_snapshot_signer,
        signer_ref=SIGNER_REF,
        key_id=KEY_ID,
    )
    service = SecondBrainEvaluationService(
        scope=_scope(),
        governance=governance,
        benchmark=benchmark,
        holdout=holdout,
        slo=slo,
        recall=authority,
    )
    with pytest.raises(EvaluationGovernanceError, match="workspace mismatch"):
        service.prove_isolation_against_serving(req)
    database.close()
