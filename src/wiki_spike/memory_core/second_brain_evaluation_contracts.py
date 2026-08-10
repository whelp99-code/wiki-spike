"""Stage-4 evaluation governance, holdout, SLO, reflection and projection gates.

Evaluation governance is deliberately not serving-memory authority. Benchmark
and holdout material must never become recall candidates, generation input, or
serving projections. Reflection and external export are feature-gated by the
resolved scope (DB-06 / DB-08) and fail closed when disabled.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping, Sequence

from .errors import InvalidContractValue
from .second_brain_contracts import ResolvedScopeV1
from .second_brain_ledger_contracts import canonical_ledger_bytes, canonical_ledger_digest

EVALUATION_GOVERNANCE_V1 = "second-brain-evaluation-governance-v1"
BENCHMARK_MANIFEST_V1 = "second-brain-benchmark-manifest-v1"
HOLDOUT_MANIFEST_V1 = "second-brain-holdout-manifest-v1"
RECALL_SLO_V1 = "second-brain-recall-slo-v1"
REFLECTION_PROPOSAL_V1 = "second-brain-reflection-proposal-v1"
MANAGED_PROJECTION_V1 = "second-brain-managed-projection-v1"
_HEX64 = frozenset("0123456789abcdef")


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in _HEX64 for ch in value):
        raise InvalidContractValue(f"{field} must be a lowercase sha256 hex digest")
    return value


def _ref(value: Any, field: str, prefix: str | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise InvalidContractValue(f"{field} must be a non-empty bounded ref")
    if prefix is not None and not value.startswith(prefix + ":"):
        raise InvalidContractValue(f"{field} must start with {prefix}:")
    return value


def _strict(data: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(data, Mapping) or any(not isinstance(k, str) for k in data):
        raise InvalidContractValue("contract must be an object with string keys")
    unknown, missing = set(data) - fields, fields - set(data)
    if unknown or missing:
        raise InvalidContractValue(f"contract fields invalid unknown={sorted(unknown)} missing={sorted(missing)}")
    return {key: data[key] for key in fields}


def _nonempty_tuple(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value or any(not isinstance(item, str) or not item for item in value):
        raise InvalidContractValue(f"{field} must be a non-empty string list")
    items = tuple(value)
    if len(set(items)) != len(items):
        raise InvalidContractValue(f"{field} must be unique")
    return items


@dataclass(frozen=True, slots=True)
class BenchmarkManifestV1:
    """Owner-reviewed local personal benchmark corpus. Never serving authority."""

    FIELDS = {
        "manifest_version", "workspace_ref", "corpus_key_ref", "capability_ref",
        "item_digests", "label_review_digest", "consent_digest", "manifest_digest",
    }
    manifest_version: str
    workspace_ref: str
    corpus_key_ref: str
    capability_ref: str
    item_digests: tuple[str, ...]
    label_review_digest: str
    consent_digest: str
    manifest_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "BenchmarkManifestV1":
        values = _strict(data, cls.FIELDS)
        if values["manifest_version"] != BENCHMARK_MANIFEST_V1:
            raise InvalidContractValue("unsupported benchmark manifest version")
        items = tuple(_digest(item, "item_digests") for item in _nonempty_tuple(values["item_digests"], "item_digests"))
        body = {
            "manifest_version": BENCHMARK_MANIFEST_V1,
            "workspace_ref": _ref(values["workspace_ref"], "workspace_ref", "workspace"),
            "corpus_key_ref": _ref(values["corpus_key_ref"], "corpus_key_ref", "key"),
            "capability_ref": _ref(values["capability_ref"], "capability_ref", "capability"),
            "item_digests": list(items),
            "label_review_digest": _digest(values["label_review_digest"], "label_review_digest"),
            "consent_digest": _digest(values["consent_digest"], "consent_digest"),
        }
        digest = _digest(values["manifest_digest"], "manifest_digest")
        if digest != canonical_ledger_digest("benchmark-manifest-v1", body):
            raise InvalidContractValue("benchmark manifest_digest does not bind its body")
        return cls(
            BENCHMARK_MANIFEST_V1, body["workspace_ref"], body["corpus_key_ref"], body["capability_ref"],
            items, body["label_review_digest"], body["consent_digest"], digest,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "workspace_ref": self.workspace_ref,
            "corpus_key_ref": self.corpus_key_ref,
            "capability_ref": self.capability_ref,
            "item_digests": list(self.item_digests),
            "label_review_digest": self.label_review_digest,
            "consent_digest": self.consent_digest,
            "manifest_digest": self.manifest_digest,
        }


@dataclass(frozen=True, slots=True)
class HoldoutManifestV1:
    """Private holdout with separate keys/capabilities from serving and development."""

    FIELDS = {
        "manifest_version", "workspace_ref", "holdout_key_ref", "capability_ref",
        "item_digests", "separation_digest", "manifest_digest",
    }
    manifest_version: str
    workspace_ref: str
    holdout_key_ref: str
    capability_ref: str
    item_digests: tuple[str, ...]
    separation_digest: str
    manifest_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "HoldoutManifestV1":
        values = _strict(data, cls.FIELDS)
        if values["manifest_version"] != HOLDOUT_MANIFEST_V1:
            raise InvalidContractValue("unsupported holdout manifest version")
        items = tuple(_digest(item, "item_digests") for item in _nonempty_tuple(values["item_digests"], "item_digests"))
        body = {
            "manifest_version": HOLDOUT_MANIFEST_V1,
            "workspace_ref": _ref(values["workspace_ref"], "workspace_ref", "workspace"),
            "holdout_key_ref": _ref(values["holdout_key_ref"], "holdout_key_ref", "key"),
            "capability_ref": _ref(values["capability_ref"], "capability_ref", "capability"),
            "item_digests": list(items),
            "separation_digest": _digest(values["separation_digest"], "separation_digest"),
        }
        digest = _digest(values["manifest_digest"], "manifest_digest")
        if digest != canonical_ledger_digest("holdout-manifest-v1", body):
            raise InvalidContractValue("holdout manifest_digest does not bind its body")
        return cls(
            HOLDOUT_MANIFEST_V1, body["workspace_ref"], body["holdout_key_ref"], body["capability_ref"],
            items, body["separation_digest"], digest,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "workspace_ref": self.workspace_ref,
            "holdout_key_ref": self.holdout_key_ref,
            "capability_ref": self.capability_ref,
            "item_digests": list(self.item_digests),
            "separation_digest": self.separation_digest,
            "manifest_digest": self.manifest_digest,
        }


@dataclass(frozen=True, slots=True)
class RecallSloV1:
    """Frozen numerical Recall SLOs and denominator rules for evaluation claims."""

    FIELDS = {
        "slo_version", "parity_min_bps", "citation_min_bps", "completeness_min_bps",
        "availability_min_bps", "max_safety_violations", "min_shadow_days",
        "min_parity_cases_per_source", "min_cohort_e2e_queries", "confidence_method",
        "include_invalid_in_denominator", "include_abstained_in_denominator",
        "include_source_unavailable_in_denominator", "slo_digest",
    }
    slo_version: str
    parity_min_bps: int
    citation_min_bps: int
    completeness_min_bps: int
    availability_min_bps: int
    max_safety_violations: int
    min_shadow_days: int
    min_parity_cases_per_source: int
    min_cohort_e2e_queries: int
    confidence_method: str
    include_invalid_in_denominator: bool
    include_abstained_in_denominator: bool
    include_source_unavailable_in_denominator: bool
    slo_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RecallSloV1":
        values = _strict(data, cls.FIELDS)
        if values["slo_version"] != RECALL_SLO_V1:
            raise InvalidContractValue("unsupported recall slo version")
        if values["confidence_method"] != "one-sided-wilson-95":
            raise InvalidContractValue("confidence_method must be one-sided-wilson-95")
        ints = {}
        for field, minimum, maximum in (
            ("parity_min_bps", 0, 10000),
            ("citation_min_bps", 0, 10000),
            ("completeness_min_bps", 0, 10000),
            ("availability_min_bps", 0, 10000),
            ("max_safety_violations", 0, 0),
            ("min_shadow_days", 3, 3650),
            ("min_parity_cases_per_source", 200, 1000000),
            ("min_cohort_e2e_queries", 500, 10000000),
        ):
            value = values[field]
            if type(value) is not int or isinstance(value, bool) or not minimum <= value <= maximum:
                raise InvalidContractValue(f"{field} out of required range")
            ints[field] = value
        for field in (
            "include_invalid_in_denominator",
            "include_abstained_in_denominator",
            "include_source_unavailable_in_denominator",
        ):
            if values[field] is not True:
                raise InvalidContractValue(f"{field} must be true")
        body = {
            "slo_version": RECALL_SLO_V1,
            **{field: ints[field] for field in (
                "parity_min_bps", "citation_min_bps", "completeness_min_bps", "availability_min_bps",
                "max_safety_violations", "min_shadow_days", "min_parity_cases_per_source",
                "min_cohort_e2e_queries",
            )},
            "confidence_method": "one-sided-wilson-95",
            "include_invalid_in_denominator": True,
            "include_abstained_in_denominator": True,
            "include_source_unavailable_in_denominator": True,
        }
        digest = _digest(values["slo_digest"], "slo_digest")
        if digest != canonical_ledger_digest("recall-slo-v1", body):
            raise InvalidContractValue("slo_digest does not bind its body")
        return cls(RECALL_SLO_V1, **ints, confidence_method="one-sided-wilson-95",
                   include_invalid_in_denominator=True, include_abstained_in_denominator=True,
                   include_source_unavailable_in_denominator=True, slo_digest=digest)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "slo_version": self.slo_version,
            "parity_min_bps": self.parity_min_bps,
            "citation_min_bps": self.citation_min_bps,
            "completeness_min_bps": self.completeness_min_bps,
            "availability_min_bps": self.availability_min_bps,
            "max_safety_violations": self.max_safety_violations,
            "min_shadow_days": self.min_shadow_days,
            "min_parity_cases_per_source": self.min_parity_cases_per_source,
            "min_cohort_e2e_queries": self.min_cohort_e2e_queries,
            "confidence_method": self.confidence_method,
            "include_invalid_in_denominator": self.include_invalid_in_denominator,
            "include_abstained_in_denominator": self.include_abstained_in_denominator,
            "include_source_unavailable_in_denominator": self.include_source_unavailable_in_denominator,
            "slo_digest": self.slo_digest,
        }


@dataclass(frozen=True, slots=True)
class EvaluationGovernanceV1:
    """Binds benchmark, holdout, SLO and encryption isolation away from serving."""

    FIELDS = {
        "governance_version", "workspace_ref", "benchmark_manifest_digest",
        "holdout_manifest_digest", "slo_digest", "consent_digest",
        "encryption_isolation_digest", "serving_corpus_digest", "governance_digest",
    }
    governance_version: str
    workspace_ref: str
    benchmark_manifest_digest: str
    holdout_manifest_digest: str
    slo_digest: str
    consent_digest: str
    encryption_isolation_digest: str
    serving_corpus_digest: str
    governance_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "EvaluationGovernanceV1":
        values = _strict(data, cls.FIELDS)
        if values["governance_version"] != EVALUATION_GOVERNANCE_V1:
            raise InvalidContractValue("unsupported evaluation governance version")
        body = {
            "governance_version": EVALUATION_GOVERNANCE_V1,
            "workspace_ref": _ref(values["workspace_ref"], "workspace_ref", "workspace"),
            "benchmark_manifest_digest": _digest(values["benchmark_manifest_digest"], "benchmark_manifest_digest"),
            "holdout_manifest_digest": _digest(values["holdout_manifest_digest"], "holdout_manifest_digest"),
            "slo_digest": _digest(values["slo_digest"], "slo_digest"),
            "consent_digest": _digest(values["consent_digest"], "consent_digest"),
            "encryption_isolation_digest": _digest(values["encryption_isolation_digest"], "encryption_isolation_digest"),
            "serving_corpus_digest": _digest(values["serving_corpus_digest"], "serving_corpus_digest"),
        }
        if body["benchmark_manifest_digest"] == body["holdout_manifest_digest"]:
            raise InvalidContractValue("benchmark and holdout manifests must be distinct")
        if body["benchmark_manifest_digest"] == body["serving_corpus_digest"] or body["holdout_manifest_digest"] == body["serving_corpus_digest"]:
            raise InvalidContractValue("evaluation corpora must not share the serving corpus digest")
        digest = _digest(values["governance_digest"], "governance_digest")
        if digest != canonical_ledger_digest("evaluation-governance-v1", body):
            raise InvalidContractValue("governance_digest does not bind its body")
        return cls(EVALUATION_GOVERNANCE_V1, **{k: body[k] for k in body if k != "governance_version"}, governance_digest=digest)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "governance_version": self.governance_version,
            "workspace_ref": self.workspace_ref,
            "benchmark_manifest_digest": self.benchmark_manifest_digest,
            "holdout_manifest_digest": self.holdout_manifest_digest,
            "slo_digest": self.slo_digest,
            "consent_digest": self.consent_digest,
            "encryption_isolation_digest": self.encryption_isolation_digest,
            "serving_corpus_digest": self.serving_corpus_digest,
            "governance_digest": self.governance_digest,
        }


@dataclass(frozen=True, slots=True)
class ReflectionProposalV1:
    """Local-first reflection proposal. External egress is scope-gated separately."""

    FIELDS = {
        "proposal_version", "workspace_ref", "proposal_ref", "support_candidate_refs",
        "rationale_digest", "local_only", "external_route", "proposal_digest",
    }
    proposal_version: str
    workspace_ref: str
    proposal_ref: str
    support_candidate_refs: tuple[str, ...]
    rationale_digest: str
    local_only: bool
    external_route: str | None
    proposal_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ReflectionProposalV1":
        values = _strict(data, cls.FIELDS)
        if values["proposal_version"] != REFLECTION_PROPOSAL_V1:
            raise InvalidContractValue("unsupported reflection proposal version")
        supports = tuple(_ref(item, "support_candidate_refs", "candidate") for item in _nonempty_tuple(values["support_candidate_refs"], "support_candidate_refs"))
        local_only = values["local_only"]
        if local_only is not True and local_only is not False:
            raise InvalidContractValue("local_only must be a boolean")
        route = values["external_route"]
        if local_only:
            if route is not None:
                raise InvalidContractValue("local_only reflection cannot name an external route")
        else:
            if not isinstance(route, str) or not route:
                raise InvalidContractValue("external reflection requires an external_route")
        body = {
            "proposal_version": REFLECTION_PROPOSAL_V1,
            "workspace_ref": _ref(values["workspace_ref"], "workspace_ref", "workspace"),
            "proposal_ref": _ref(values["proposal_ref"], "proposal_ref", "proposal"),
            "support_candidate_refs": list(supports),
            "rationale_digest": _digest(values["rationale_digest"], "rationale_digest"),
            "local_only": local_only,
            "external_route": route,
        }
        digest = _digest(values["proposal_digest"], "proposal_digest")
        if digest != canonical_ledger_digest("reflection-proposal-v1", body):
            raise InvalidContractValue("proposal_digest does not bind its body")
        return cls(
            REFLECTION_PROPOSAL_V1, body["workspace_ref"], body["proposal_ref"], supports,
            body["rationale_digest"], local_only, route, digest,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "proposal_version": self.proposal_version,
            "workspace_ref": self.workspace_ref,
            "proposal_ref": self.proposal_ref,
            "support_candidate_refs": list(self.support_candidate_refs),
            "rationale_digest": self.rationale_digest,
            "local_only": self.local_only,
            "external_route": self.external_route,
            "proposal_digest": self.proposal_digest,
        }


@dataclass(frozen=True, slots=True)
class ManagedProjectionV1:
    """Internal managed projection. External export is destination-scoped separately."""

    FIELDS = {
        "projection_version", "workspace_ref", "projection_ref", "schema_version",
        "source_generation_digest", "artifact_digest", "withheld", "export_destination",
        "projection_digest",
    }
    projection_version: str
    workspace_ref: str
    projection_ref: str
    schema_version: str
    source_generation_digest: str
    artifact_digest: str
    withheld: bool
    export_destination: str | None
    projection_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ManagedProjectionV1":
        values = _strict(data, cls.FIELDS)
        if values["projection_version"] != MANAGED_PROJECTION_V1:
            raise InvalidContractValue("unsupported managed projection version")
        withheld = values["withheld"]
        if withheld is not True and withheld is not False:
            raise InvalidContractValue("withheld must be a boolean")
        destination = values["export_destination"]
        if destination is not None and (not isinstance(destination, str) or not destination):
            raise InvalidContractValue("export_destination must be null or a non-empty string")
        if withheld and destination is not None:
            raise InvalidContractValue("withheld projection cannot name an export destination")
        if not isinstance(values["schema_version"], str) or not values["schema_version"]:
            raise InvalidContractValue("schema_version required")
        body = {
            "projection_version": MANAGED_PROJECTION_V1,
            "workspace_ref": _ref(values["workspace_ref"], "workspace_ref", "workspace"),
            "projection_ref": _ref(values["projection_ref"], "projection_ref", "projection"),
            "schema_version": values["schema_version"],
            "source_generation_digest": _digest(values["source_generation_digest"], "source_generation_digest"),
            "artifact_digest": _digest(values["artifact_digest"], "artifact_digest"),
            "withheld": withheld,
            "export_destination": destination,
        }
        digest = _digest(values["projection_digest"], "projection_digest")
        if digest != canonical_ledger_digest("managed-projection-v1", body):
            raise InvalidContractValue("projection_digest does not bind its body")
        return cls(
            MANAGED_PROJECTION_V1, body["workspace_ref"], body["projection_ref"], body["schema_version"],
            body["source_generation_digest"], body["artifact_digest"], withheld, destination, digest,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "projection_version": self.projection_version,
            "workspace_ref": self.workspace_ref,
            "projection_ref": self.projection_ref,
            "schema_version": self.schema_version,
            "source_generation_digest": self.source_generation_digest,
            "artifact_digest": self.artifact_digest,
            "withheld": self.withheld,
            "export_destination": self.export_destination,
            "projection_digest": self.projection_digest,
        }


def assert_evaluation_isolated_from_serving(
    governance: EvaluationGovernanceV1,
    benchmark: BenchmarkManifestV1,
    holdout: HoldoutManifestV1,
    *,
    serving_candidate_content_digests: Sequence[str] = (),
    serving_key_refs: Sequence[str] = (),
    serving_capability_refs: Sequence[str] = (),
) -> None:
    """Fail closed if evaluation material can bleed into the serving path."""
    if benchmark.workspace_ref != governance.workspace_ref or holdout.workspace_ref != governance.workspace_ref:
        raise InvalidContractValue("evaluation manifests must bind the governance workspace")
    if benchmark.manifest_digest != governance.benchmark_manifest_digest:
        raise InvalidContractValue("governance does not bind the benchmark manifest")
    if holdout.manifest_digest != governance.holdout_manifest_digest:
        raise InvalidContractValue("governance does not bind the holdout manifest")
    if benchmark.consent_digest != governance.consent_digest:
        raise InvalidContractValue("governance consent_digest must equal the benchmark consent_digest")
    if benchmark.corpus_key_ref == holdout.holdout_key_ref:
        raise InvalidContractValue("benchmark and holdout keys must be distinct")
    if benchmark.capability_ref == holdout.capability_ref:
        raise InvalidContractValue("benchmark and holdout capabilities must be distinct")
    shared_items = set(benchmark.item_digests) & set(holdout.item_digests)
    if shared_items:
        raise InvalidContractValue("benchmark and holdout item sets must be disjoint")
    serving_items = set(serving_candidate_content_digests)
    if serving_items & set(benchmark.item_digests) or serving_items & set(holdout.item_digests):
        raise InvalidContractValue("evaluation items must never appear in the serving corpus")
    if benchmark.corpus_key_ref in serving_key_refs or holdout.holdout_key_ref in serving_key_refs:
        raise InvalidContractValue("evaluation keys must never be serving keys")
    if benchmark.capability_ref in serving_capability_refs or holdout.capability_ref in serving_capability_refs:
        raise InvalidContractValue("evaluation capabilities must never be serving capabilities")


def assert_reflection_allowed(scope: ResolvedScopeV1, proposal: ReflectionProposalV1) -> None:
    """Local reflection is always in-product; external reflection requires DB-06 enablement."""
    if proposal.local_only:
        return
    enabled = set(scope.enabled_external_model_routes)
    if proposal.external_route not in enabled:
        raise InvalidContractValue("external reflection route is disabled by resolved scope")


def assert_projection_export_allowed(scope: ResolvedScopeV1, projection: ManagedProjectionV1) -> None:
    """Internal managed projections may rebuild/withhold; external export is DB-08 gated."""
    if projection.export_destination is None:
        return
    if projection.withheld:
        raise InvalidContractValue("withheld projection cannot export")
    disabled = dict(scope.disabled_export_destinations)
    if projection.export_destination in disabled or projection.export_destination not in set(scope.egress_destinations):
        raise InvalidContractValue("export destination is disabled by resolved scope")


def invalidate_reflection_support(
    proposals: Sequence[ReflectionProposalV1],
    withdrawn_candidate_refs: Sequence[str],
) -> tuple[ReflectionProposalV1, ...]:
    """Drop any reflection proposal whose support set intersects a withdrawn candidate.

    Support withdrawal is transitive at the product layer: a proposal that still
    names a withdrawn supporter is no longer promotable.
    """
    withdrawn = set(withdrawn_candidate_refs)
    return tuple(
        proposal for proposal in proposals
        if withdrawn.isdisjoint(proposal.support_candidate_refs)
    )


_FORBIDDEN_RATIONALE_MARKERS = (
    "exfiltrate", "upload_raw", "remote_train", "provider_log_prompt", "unredacted_pii",
)


def assert_rationale_egress_allowed(
    scope: ResolvedScopeV1,
    proposal: ReflectionProposalV1,
    *,
    rationale_text: str = "",
    allowed_classes: Sequence[str] = (),
    proposal_class: str | None = None,
) -> None:
    """Fail closed on external reflection that is out of scope or carries forbidden rationale markers.

    Local-only proposals skip route/class checks but still reject explicit exfil markers
    in any supplied rationale text so a local path cannot launder egress intent.
    """
    text = rationale_text if isinstance(rationale_text, str) else ""
    lowered = text.lower()
    for marker in _FORBIDDEN_RATIONALE_MARKERS:
        if marker in lowered:
            raise InvalidContractValue(f"rationale carries forbidden egress marker: {marker}")
    assert_reflection_allowed(scope, proposal)
    if proposal.local_only:
        return
    if allowed_classes:
        if not isinstance(proposal_class, str) or not proposal_class or proposal_class not in set(allowed_classes):
            raise InvalidContractValue("external reflection class is not in the allowed class manifest")


def transitive_support_closure(
    direct_edges: Sequence[tuple[str, str]],
    roots: Sequence[str],
) -> frozenset[str]:
    """Compute the set of candidates reachable from roots over directed support edges.

    ``direct_edges`` are (from_supporter, to_dependent) pairs. Withdrawal of any
    root invalidates every dependent reachable through one or more support hops.
    """
    adjacency: dict[str, list[str]] = {}
    for source, dependent in direct_edges:
        if not isinstance(source, str) or not isinstance(dependent, str):
            raise InvalidContractValue("support edges must be string pairs")
        adjacency.setdefault(source, []).append(dependent)
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(adjacency.get(node, ()))
    return frozenset(seen)


def invalidate_reflection_support_transitive(
    proposals: Sequence[ReflectionProposalV1],
    withdrawn_candidate_refs: Sequence[str],
    support_edges: Sequence[tuple[str, str]] = (),
) -> tuple[ReflectionProposalV1, ...]:
    """Drop proposals whose support intersects the transitive closure of withdrawn candidates."""
    withdrawn = transitive_support_closure(support_edges, withdrawn_candidate_refs) | set(withdrawn_candidate_refs)
    return tuple(
        proposal for proposal in proposals
        if withdrawn.isdisjoint(proposal.support_candidate_refs)
    )

NATIVE_SHADOW_MEASUREMENT_V1 = "second-brain-native-shadow-measurement-v1"
NATIVE_SHADOW_SAMPLE_V1 = "second-brain-native-shadow-sample-v1"
NATIVE_SHADOW_SOURCES = ("Codex", "Claude/Memory Bank", "Git", "Markdown")
NATIVE_SHADOW_OUTCOMES = ("valid", "invalid", "abstained", "source-unavailable")

__all__ = [
    "NATIVE_SHADOW_MEASUREMENT_V1",
    "NATIVE_SHADOW_SAMPLE_V1",
    "NATIVE_SHADOW_SOURCES",
    "NATIVE_SHADOW_OUTCOMES",
    "EVALUATION_GOVERNANCE_V1",
    "BENCHMARK_MANIFEST_V1",
    "HOLDOUT_MANIFEST_V1",
    "RECALL_SLO_V1",
    "REFLECTION_PROPOSAL_V1",
    "MANAGED_PROJECTION_V1",
    "BenchmarkManifestV1",
    "HoldoutManifestV1",
    "RecallSloV1",
    "EvaluationGovernanceV1",
    "ReflectionProposalV1",
    "ManagedProjectionV1",
    "assert_evaluation_isolated_from_serving",
    "assert_reflection_allowed",
    "assert_projection_export_allowed",
    "invalidate_reflection_support",
    "invalidate_reflection_support_transitive",
    "transitive_support_closure",
    "assert_rationale_egress_allowed",
    "canonical_ledger_digest",
]
