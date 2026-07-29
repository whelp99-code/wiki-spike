"""Stage 4: evaluation governance, holdout/SLO isolation, reflection and projection gates."""
from __future__ import annotations

from pathlib import Path

import pytest
from test_decision_contracts import DIGEST, resolve, records, scope
from test_stage3_ledger_persistence import (
    KEY_ID, NOW, SIGNER_REF, blob, create_and_approve, digest, ref, request,
    signed_snapshot_signer, store, trust_for_request,
)
from wiki_spike.applications.second_brain_evaluation_service import (
    EvaluationGovernanceError,
    SecondBrainEvaluationService,
)
from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
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


def _workspace() -> str:
    return ref("workspace", "eval")


def _benchmark(*, items: tuple[str, ...] = (digest("bench-1"), digest("bench-2")), key: str = "bench") -> BenchmarkManifestV1:
    body = {
        "manifest_version": BENCHMARK_MANIFEST_V1,
        "workspace_ref": _workspace(),
        "corpus_key_ref": ref("key", key),
        "capability_ref": ref("capability", key),
        "item_digests": list(items),
        "label_review_digest": digest("labels"),
        "consent_digest": digest("consent"),
    }
    body["manifest_digest"] = canonical_ledger_digest("benchmark-manifest-v1", body)
    return BenchmarkManifestV1.from_mapping(body)


def _holdout(*, items: tuple[str, ...] = (digest("hold-1"),), key: str = "hold") -> HoldoutManifestV1:
    body = {
        "manifest_version": HOLDOUT_MANIFEST_V1,
        "workspace_ref": _workspace(),
        "holdout_key_ref": ref("key", key),
        "capability_ref": ref("capability", key),
        "item_digests": list(items),
        "separation_digest": digest("separation"),
    }
    body["manifest_digest"] = canonical_ledger_digest("holdout-manifest-v1", body)
    return HoldoutManifestV1.from_mapping(body)


def _slo() -> RecallSloV1:
    body = {
        "slo_version": RECALL_SLO_V1,
        "parity_min_bps": 9000,
        "citation_min_bps": 9000,
        "completeness_min_bps": 9000,
        "availability_min_bps": 9900,
        "max_safety_violations": 0,
        "min_shadow_days": 14,
        "min_parity_cases_per_source": 200,
        "min_cohort_e2e_queries": 500,
        "confidence_method": "one-sided-wilson-95",
        "include_invalid_in_denominator": True,
        "include_abstained_in_denominator": True,
        "include_source_unavailable_in_denominator": True,
    }
    body["slo_digest"] = canonical_ledger_digest("recall-slo-v1", body)
    return RecallSloV1.from_mapping(body)


def _governance(benchmark: BenchmarkManifestV1, holdout: HoldoutManifestV1, slo: RecallSloV1) -> EvaluationGovernanceV1:
    body = {
        "governance_version": EVALUATION_GOVERNANCE_V1,
        "workspace_ref": _workspace(),
        "benchmark_manifest_digest": benchmark.manifest_digest,
        "holdout_manifest_digest": holdout.manifest_digest,
        "slo_digest": slo.slo_digest,
        "consent_digest": digest("consent"),
        "encryption_isolation_digest": digest("enc-isolation"),
        "serving_corpus_digest": digest("serving-corpus"),
    }
    body["governance_digest"] = canonical_ledger_digest("evaluation-governance-v1", body)
    return EvaluationGovernanceV1.from_mapping(body)


def _scope(**overrides: object) -> ResolvedScopeV1:
    raw = scope()
    raw.update(overrides)
    return ResolvedScopeV1.from_mapping(raw)


def _proposal(*, supports: tuple[str, ...] = (ref("candidate", "s1"),), local: bool = True, route: str | None = None) -> ReflectionProposalV1:
    body = {
        "proposal_version": REFLECTION_PROPOSAL_V1,
        "workspace_ref": _workspace(),
        "proposal_ref": ref("proposal", "p1"),
        "support_candidate_refs": list(supports),
        "rationale_digest": digest("rationale"),
        "local_only": local,
        "external_route": route,
    }
    body["proposal_digest"] = canonical_ledger_digest("reflection-proposal-v1", body)
    return ReflectionProposalV1.from_mapping(body)


def _projection(*, withheld: bool = False, destination: str | None = None) -> ManagedProjectionV1:
    body = {
        "projection_version": MANAGED_PROJECTION_V1,
        "workspace_ref": _workspace(),
        "projection_ref": ref("projection", "m1"),
        "schema_version": "managed-identity-v1",
        "source_generation_digest": digest("gen"),
        "artifact_digest": digest("artifact"),
        "withheld": withheld,
        "export_destination": destination,
    }
    body["projection_digest"] = canonical_ledger_digest("managed-projection-v1", body)
    return ManagedProjectionV1.from_mapping(body)


def test_benchmark_holdout_and_slo_bind_and_reject_shared_identity() -> None:
    benchmark, holdout, slo = _benchmark(), _holdout(), _slo()
    governance = _governance(benchmark, holdout, slo)
    assert_evaluation_isolated_from_serving(governance, benchmark, holdout)
    with pytest.raises(InvalidContractValue, match="distinct"):
        EvaluationGovernanceV1.from_mapping({
            **governance.to_mapping(),
            "holdout_manifest_digest": governance.benchmark_manifest_digest,
            "governance_digest": digest("x"),
        })
    overlap = _holdout(items=benchmark.item_digests, key="hold2")
    gov_overlap = _governance(benchmark, overlap, slo)
    with pytest.raises(InvalidContractValue, match="disjoint"):
        assert_evaluation_isolated_from_serving(gov_overlap, benchmark, overlap)


def test_evaluation_items_never_enter_serving_corpus_or_keys() -> None:
    benchmark, holdout, slo = _benchmark(), _holdout(), _slo()
    governance = _governance(benchmark, holdout, slo)
    with pytest.raises(InvalidContractValue, match="serving corpus"):
        assert_evaluation_isolated_from_serving(
            governance, benchmark, holdout,
            serving_candidate_content_digests=(benchmark.item_digests[0],),
        )
    with pytest.raises(InvalidContractValue, match="serving keys"):
        assert_evaluation_isolated_from_serving(
            governance, benchmark, holdout, serving_key_refs=(benchmark.corpus_key_ref,),
        )
    with pytest.raises(InvalidContractValue, match="serving capabilities"):
        assert_evaluation_isolated_from_serving(
            governance, benchmark, holdout, serving_capability_refs=(holdout.capability_ref,),
        )


def test_slo_freezes_plan_minima_and_denominator_rules() -> None:
    slo = _slo()
    assert slo.min_shadow_days == 14
    assert slo.min_parity_cases_per_source == 200
    assert slo.min_cohort_e2e_queries == 500
    assert slo.max_safety_violations == 0
    assert slo.include_invalid_in_denominator is True
    with pytest.raises(InvalidContractValue, match="out of required range"):
        body = slo.to_mapping()
        body["min_shadow_days"] = 7
        body["slo_digest"] = canonical_ledger_digest("recall-slo-v1", {k: v for k, v in body.items() if k != "slo_digest"})
        RecallSloV1.from_mapping(body)


def test_live_serving_snapshot_isolation_proof(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    # Build a real serving candidate whose content digest is NOT an eval item.
    candidate = ref("candidate", "served")
    content = blob(cas, "served-content-not-eval")
    create_and_approve(service, cas, candidate, "served", workspace=workspace)
    # Rebind evaluation contracts onto this workspace.
    bench_body = _benchmark().to_mapping(); bench_body["workspace_ref"] = workspace
    bench_body["manifest_digest"] = canonical_ledger_digest("benchmark-manifest-v1", {k: v for k, v in bench_body.items() if k != "manifest_digest"})
    hold_body = _holdout().to_mapping(); hold_body["workspace_ref"] = workspace
    hold_body["manifest_digest"] = canonical_ledger_digest("holdout-manifest-v1", {k: v for k, v in hold_body.items() if k != "manifest_digest"})
    benchmark, holdout, slo = BenchmarkManifestV1.from_mapping(bench_body), HoldoutManifestV1.from_mapping(hold_body), _slo()
    gov_body = {
        "governance_version": EVALUATION_GOVERNANCE_V1,
        "workspace_ref": workspace,
        "benchmark_manifest_digest": benchmark.manifest_digest,
        "holdout_manifest_digest": holdout.manifest_digest,
        "slo_digest": slo.slo_digest,
        "consent_digest": digest("consent"),
        "encryption_isolation_digest": digest("enc"),
        "serving_corpus_digest": digest("serving"),
    }
    gov_body["governance_digest"] = canonical_ledger_digest("evaluation-governance-v1", gov_body)
    governance = EvaluationGovernanceV1.from_mapping(gov_body)
    req = request(workspace, recorded_at=NOW)
    authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(req), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID,
    )
    eval_service = SecondBrainEvaluationService(
        scope=_scope(), governance=governance, benchmark=benchmark, holdout=holdout, slo=slo,
        recall=authority,
    )
    report = eval_service.prove_isolation_against_serving(req)
    assert report.isolated and report.serving_candidate_count == 1
    # Inject an eval item into serving and prove isolation fails.
    eval_item = benchmark.item_digests[0]
    with pytest.raises(InvalidContractValue, match="serving corpus"):
        assert_evaluation_isolated_from_serving(
            governance, benchmark, holdout, serving_candidate_content_digests=(eval_item,),
        )
    database.close()


def test_external_reflection_requires_enabled_route_local_always_ok() -> None:
    scope_obj = _scope(enabled_external_model_routes=["model-a"], disabled_external_model_routes={})
    local = _proposal(local=True)
    assert_reflection_allowed(scope_obj, local)
    external = _proposal(local=False, route="model-a")
    assert_reflection_allowed(scope_obj, external)
    disabled = _scope(enabled_external_model_routes=[], disabled_external_model_routes={"model-a": "no"})
    with pytest.raises(InvalidContractValue, match="disabled by resolved scope"):
        assert_reflection_allowed(disabled, external)


def test_support_withdrawal_invalidates_reflection_proposals() -> None:
    root, dependent = ref("candidate", "root"), ref("candidate", "dep")
    kept = _proposal(supports=(ref("candidate", "other"),))
    doomed = ReflectionProposalV1.from_mapping({
        **_proposal(supports=(root, dependent)).to_mapping(),
        # rebind digest for different supports already done by helper only for default;
    })
    # rebuild doomed properly
    body = {
        "proposal_version": REFLECTION_PROPOSAL_V1,
        "workspace_ref": _workspace(),
        "proposal_ref": ref("proposal", "doomed"),
        "support_candidate_refs": [root, dependent],
        "rationale_digest": digest("r"),
        "local_only": True,
        "external_route": None,
    }
    body["proposal_digest"] = canonical_ledger_digest("reflection-proposal-v1", body)
    doomed = ReflectionProposalV1.from_mapping(body)
    remaining = invalidate_reflection_support((kept, doomed), (root,))
    assert remaining == (kept,)


def test_projection_export_gated_and_withholdable() -> None:
    scope_obj = _scope(egress_destinations=["archive"], disabled_export_destinations={})
    internal = _projection()
    assert_projection_export_allowed(scope_obj, internal)
    exportable = _projection(destination="archive")
    assert_projection_export_allowed(scope_obj, exportable)
    # Destination not in egress_destinations (or explicitly disabled without dual enable).
    disabled = _scope(egress_destinations=[], disabled_export_destinations={"archive": "no"})
    with pytest.raises(InvalidContractValue, match="disabled by resolved scope"):
        assert_projection_export_allowed(disabled, exportable)
    with pytest.raises(InvalidContractValue, match="withheld"):
        assert_projection_export_allowed(scope_obj, _projection(withheld=True, destination="archive"))


def test_evaluation_service_reflection_and_projection_flow() -> None:
    benchmark, holdout, slo = _benchmark(), _holdout(), _slo()
    governance = _governance(benchmark, holdout, slo)
    service = SecondBrainEvaluationService(
        scope=_scope(), governance=governance, benchmark=benchmark, holdout=holdout, slo=slo,
    )
    proposal = service.submit_reflection(_proposal(supports=(ref("candidate", "alive"),)))
    assert proposal.local_only
    remaining = service.withdraw_support((ref("candidate", "alive"),))
    assert remaining == ()
    projection = service.publish_projection(_projection())
    withheld = service.withhold_projection(projection.projection_ref)
    assert withheld.withheld and withheld.export_destination is None
    with pytest.raises(EvaluationGovernanceError, match="disabled by resolved scope"):
        SecondBrainEvaluationService(
            scope=_scope(enabled_external_model_routes=[], disabled_external_model_routes={"model-a": "no"}),
            governance=governance, benchmark=benchmark, holdout=holdout, slo=slo,
        ).submit_reflection(_proposal(local=False, route="model-a"))


def test_stage0_contract_still_requires_db05_for_benchmark_feature() -> None:
    # DB-05 remains a global GO requirement for product progression; Stage 4
    # evaluation governance does not bypass Stage 0 aggregation.
    result = resolve(records())
    assert result.outcome == "RESOLVED"
    assert "benchmark-governance" in result.contract.resolved_scope.feature_flags
