"""Stage-4 evaluation governance application boundary.

Keeps benchmark/holdout material out of the serving recall path and enforces
resolved-scope gates for external reflection and export.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_evaluation_contracts import (
    BenchmarkManifestV1,
    EvaluationGovernanceV1,
    HoldoutManifestV1,
    ManagedProjectionV1,
    RecallSloV1,
    ReflectionProposalV1,
    assert_evaluation_isolated_from_serving,
    assert_projection_export_allowed,
    assert_rationale_egress_allowed,
    assert_reflection_allowed,
    invalidate_reflection_support_transitive,
)
from wiki_spike.memory_core.second_brain_ledger_ports import AtomicRecallSnapshotPort
from wiki_spike.memory_core.second_brain_ledger_contracts import RecallSnapshotRequestV2


class EvaluationGovernanceError(RuntimeError):
    """Evaluation governance refused an unsafe operation."""


@dataclass(frozen=True)
class EvaluationIsolationReport:
    governance_digest: str
    benchmark_item_count: int
    holdout_item_count: int
    serving_candidate_count: int
    isolated: bool


class SecondBrainEvaluationService:
    """Application boundary for Stage-4 evaluation, reflection and projection gates."""

    def __init__(
        self,
        *,
        scope: ResolvedScopeV1,
        governance: EvaluationGovernanceV1,
        benchmark: BenchmarkManifestV1,
        holdout: HoldoutManifestV1,
        slo: RecallSloV1,
        recall: AtomicRecallSnapshotPort | None = None,
    ) -> None:
        if governance.slo_digest != slo.slo_digest:
            raise EvaluationGovernanceError("governance does not bind the provided SLO")
        assert_evaluation_isolated_from_serving(governance, benchmark, holdout)
        self._scope = scope
        self._governance = governance
        self._benchmark = benchmark
        self._holdout = holdout
        self._slo = slo
        self._recall = recall
        self._proposals: list[ReflectionProposalV1] = []
        self._projections: list[ManagedProjectionV1] = []
        self._support_edges: list[tuple[str, str]] = []
        self._forbidden_serving_digests = set(benchmark.item_digests) | set(holdout.item_digests)
        self._forbidden_serving_keys = {benchmark.corpus_key_ref, holdout.holdout_key_ref}
        self._forbidden_serving_capabilities = {benchmark.capability_ref, holdout.capability_ref}

    @property
    def slo(self) -> RecallSloV1:
        return self._slo

    def prove_isolation_against_serving(
        self,
        request: RecallSnapshotRequestV2,
        *,
        serving_key_refs: Sequence[str] = (),
        serving_capability_refs: Sequence[str] = (),
    ) -> EvaluationIsolationReport:
        """Acquire a live serving snapshot and prove no evaluation item is served."""
        if self._recall is None:
            raise EvaluationGovernanceError("serving recall port is required for isolation proof")
        if request.workspace_ref != self._governance.workspace_ref:
            raise EvaluationGovernanceError("isolation proof workspace mismatch")
        acquisition = self._recall.acquire_recall_snapshot(request)
        served = tuple(item.content_digest for item in acquisition.snapshot.candidates)
        try:
            assert_evaluation_isolated_from_serving(
                self._governance,
                self._benchmark,
                self._holdout,
                serving_candidate_content_digests=served,
                serving_key_refs=serving_key_refs,
                serving_capability_refs=serving_capability_refs,
            )
            self.assert_serving_content_allowed(served)
        except InvalidContractValue as exc:
            raise EvaluationGovernanceError(str(exc)) from exc
        return EvaluationIsolationReport(
            governance_digest=self._governance.governance_digest,
            benchmark_item_count=len(self._benchmark.item_digests),
            holdout_item_count=len(self._holdout.item_digests),
            serving_candidate_count=len(served),
            isolated=True,
        )

    def register_support_edge(self, supporter_ref: str, dependent_ref: str) -> None:
        """Record a directed support edge for transitive reflection invalidation."""
        if not isinstance(supporter_ref, str) or not isinstance(dependent_ref, str):
            raise EvaluationGovernanceError("support edge refs must be strings")
        self._support_edges.append((supporter_ref, dependent_ref))

    def submit_reflection(
        self,
        proposal: ReflectionProposalV1,
        *,
        rationale_text: str = "",
        allowed_classes: Sequence[str] = (),
        proposal_class: str | None = None,
    ) -> ReflectionProposalV1:
        try:
            assert_rationale_egress_allowed(
                self._scope,
                proposal,
                rationale_text=rationale_text,
                allowed_classes=allowed_classes,
                proposal_class=proposal_class,
            )
        except InvalidContractValue as exc:
            raise EvaluationGovernanceError(str(exc)) from exc
        if proposal.workspace_ref != self._governance.workspace_ref:
            raise EvaluationGovernanceError("reflection workspace mismatch")
        self._proposals.append(proposal)
        return proposal

    def withdraw_support(self, candidate_refs: Sequence[str]) -> tuple[ReflectionProposalV1, ...]:
        remaining = invalidate_reflection_support_transitive(
            self._proposals, candidate_refs, self._support_edges,
        )
        self._proposals = list(remaining)
        return remaining

    def assert_serving_content_allowed(self, content_digests: Sequence[str]) -> None:
        """Hard serving-path gate: refuse any content digest from evaluation corpora."""
        overlap = self._forbidden_serving_digests.intersection(content_digests)
        if overlap:
            raise EvaluationGovernanceError("serving path refused evaluation corpus content")

    def forbidden_serving_material(self) -> dict[str, tuple[str, ...]]:
        """Expose the evaluation material the serving path must never accept."""
        return {
            "content_digests": tuple(sorted(self._forbidden_serving_digests)),
            "key_refs": tuple(sorted(self._forbidden_serving_keys)),
            "capability_refs": tuple(sorted(self._forbidden_serving_capabilities)),
        }

    def publish_projection(self, projection: ManagedProjectionV1) -> ManagedProjectionV1:
        try:
            assert_projection_export_allowed(self._scope, projection)
        except InvalidContractValue as exc:
            raise EvaluationGovernanceError(str(exc)) from exc
        if projection.workspace_ref != self._governance.workspace_ref:
            raise EvaluationGovernanceError("projection workspace mismatch")
        self._projections.append(projection)
        return projection

    def withhold_projection(self, projection_ref: str) -> ManagedProjectionV1:
        for index, projection in enumerate(self._projections):
            if projection.projection_ref == projection_ref:
                if projection.withheld:
                    return projection
                body = projection.to_mapping()
                body["withheld"] = True
                body["export_destination"] = None
                # re-bind digest
                from wiki_spike.memory_core.second_brain_evaluation_contracts import (
                    MANAGED_PROJECTION_V1,
                    canonical_ledger_digest,
                )
                digest_body = {k: v for k, v in body.items() if k != "projection_digest"}
                body["projection_digest"] = canonical_ledger_digest("managed-projection-v1", digest_body)
                withheld = ManagedProjectionV1.from_mapping(body)
                self._projections[index] = withheld
                return withheld
        raise EvaluationGovernanceError("projection not found")
