"""Stage-6 cutover decision, cohort state machine, and decommission gates.

No function in this module performs a production route switch or destructive
decommission. It only validates signed CutoverDecisionV1 evidence, cohort
roster/scope equality, the quantitative PASS formula, and the legal state
transitions up to but not including unauthorized live activation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .errors import InvalidContractValue
from .second_brain_contracts import ResolvedScopeV1
from .second_brain_ledger_contracts import canonical_ledger_digest
from .second_brain_product_release import resolved_scope_digest

CUTOVER_DECISION_V1 = "second-brain-cutover-decision-v1"
COHORT_MANIFEST_V1 = "second-brain-migration-cohort-manifest-v1"
_HEX64 = frozenset("0123456789abcdef")
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


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in _HEX64 for ch in value):
        raise InvalidContractValue(f"{field} must be a lowercase sha256 hex digest")
    return value


def _text(value: Any, field: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise InvalidContractValue(f"{field} must be a non-empty bounded string")
    return value


def _strict(data: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(data, Mapping) or any(not isinstance(k, str) for k in data):
        raise InvalidContractValue("contract must be an object with string keys")
    unknown, missing = set(data) - fields, fields - set(data)
    if unknown or missing:
        raise InvalidContractValue(f"contract fields invalid unknown={sorted(unknown)} missing={sorted(missing)}")
    return {key: data[key] for key in fields}


def _uint(value: Any, field: str, *, minimum: int = 0, maximum: int = 10**9) -> int:
    if type(value) is not int or isinstance(value, bool) or not minimum <= value <= maximum:
        raise InvalidContractValue(f"{field} out of range")
    return value


def _bool(value: Any, field: str) -> bool:
    if value is not True and value is not False:
        raise InvalidContractValue(f"{field} must be a boolean")
    return value


@dataclass(frozen=True, slots=True)
class MigrationCohortManifestV1:
    """Source-by-source final-workspace non-serving cohort roster."""

    FIELDS = {
        "manifest_version", "workspace_ref", "cohort_state", "source_names",
        "resolved_scope_digest", "source_manifest_digest", "manifest_digest",
    }
    manifest_version: str
    workspace_ref: str
    cohort_state: str
    source_names: tuple[str, ...]
    resolved_scope_digest: str
    source_manifest_digest: str
    manifest_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MigrationCohortManifestV1":
        values = _strict(data, cls.FIELDS)
        if values["manifest_version"] != COHORT_MANIFEST_V1:
            raise InvalidContractValue("unsupported cohort manifest version")
        state = _text(values["cohort_state"], "cohort_state", maximum=64)
        if state not in _COHORT_STATES:
            raise InvalidContractValue(f"unknown cohort_state: {state}")
        if not isinstance(values["source_names"], (list, tuple)) or not values["source_names"]:
            raise InvalidContractValue("source_names must be a non-empty list")
        sources = tuple(_text(name, "source_names") for name in values["source_names"])
        if len(set(sources)) != len(sources):
            raise InvalidContractValue("source_names must be unique")
        # DB-07 / ADR-0028: source-by-source cutover — one migration source per cohort.
        if len(sources) != 1:
            raise InvalidContractValue("cohort must contain exactly one migration source at a time")
        body = {
            "manifest_version": COHORT_MANIFEST_V1,
            "workspace_ref": _text(values["workspace_ref"], "workspace_ref"),
            "cohort_state": state,
            "source_names": list(sources),
            "resolved_scope_digest": _digest(values["resolved_scope_digest"], "resolved_scope_digest"),
            "source_manifest_digest": _digest(values["source_manifest_digest"], "source_manifest_digest"),
        }
        digest = _digest(values["manifest_digest"], "manifest_digest")
        if digest != canonical_ledger_digest("migration-cohort-manifest-v1", body):
            raise InvalidContractValue("cohort manifest_digest does not bind its body")
        return cls(COHORT_MANIFEST_V1, body["workspace_ref"], state, sources,
                   body["resolved_scope_digest"], body["source_manifest_digest"], digest)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "workspace_ref": self.workspace_ref,
            "cohort_state": self.cohort_state,
            "source_names": list(self.source_names),
            "resolved_scope_digest": self.resolved_scope_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "manifest_digest": self.manifest_digest,
        }


def assert_cohort_subset_of_enabled_migration_sources(
    cohort: MigrationCohortManifestV1,
    scope: ResolvedScopeV1,
) -> None:
    """Cohort roster must be a subset of enabled migration sources and bind scope digests."""
    if cohort.resolved_scope_digest != resolved_scope_digest(scope):
        raise InvalidContractValue("cohort resolved_scope_digest mismatch")
    if cohort.source_manifest_digest != scope.source_manifest_digest:
        raise InvalidContractValue("cohort source_manifest_digest mismatch")
    enabled = set(scope.enabled_migration_sources)
    disabled = dict(scope.disabled_migration_sources)
    for name in cohort.source_names:
        if name not in enabled:
            raise InvalidContractValue(f"cohort source not enabled in resolved scope: {name}")
        if name in disabled:
            raise InvalidContractValue(f"disabled migration source cannot join cohort: {name}")


def assert_cohort_transition(current: str, nxt: str) -> None:
    if current not in _COHORT_STATES or nxt not in _COHORT_STATES:
        raise InvalidContractValue("unknown cohort state")
    if nxt not in _ALLOWED_TRANSITIONS[current]:
        raise InvalidContractValue(f"illegal cohort transition {current} -> {nxt}")


def assert_pre_mutation_rollback_allowed(state: str) -> None:
    """Emergency rollback is only legal before the first canonical mutation."""
    if state != "ROUTE_SWITCHED_NO_MUTATION":
        raise InvalidContractValue("pre-mutation rollback only from ROUTE_SWITCHED_NO_MUTATION")


def assert_post_mutation_fail_closed(state: str, *, action: str) -> None:
    """After CANONICAL_MUTATED, external rollback is closed."""
    if state in {"CANONICAL_MUTATED", "ROLLBACK_CLOSED", "DECOMMISSIONED"} and action == "external_rollback":
        raise InvalidContractValue("external rollback is closed after canonical mutation")


@dataclass(frozen=True, slots=True)
class CutoverDecisionV1:
    """Signed quantitative cutover decision. Does not itself switch production routes."""

    FIELDS = {
        "decision_version", "decision_id", "workspace_ref", "cohort_manifest_digest",
        "resolved_scope_digest", "contract_digest", "source_manifest_digest",
        "capability_manifest_digest", "benchmark_manifest_digest", "holdout_manifest_digest",
        "generation_digest", "checkpoint_digest", "route_version", "observation_days",
        "parity_cases_per_source", "cohort_e2e_queries", "safety_violations",
        "parity_bps_lower", "citation_bps_lower", "completeness_bps_lower", "availability_bps_lower",
        "parity_min_bps", "citation_min_bps", "completeness_min_bps", "availability_min_bps",
        "holdout_changed", "approver_roles", "formula_pass", "decision_digest",
    }
    decision_version: str
    decision_id: str
    workspace_ref: str
    cohort_manifest_digest: str
    resolved_scope_digest: str
    contract_digest: str
    source_manifest_digest: str
    capability_manifest_digest: str
    benchmark_manifest_digest: str
    holdout_manifest_digest: str
    generation_digest: str
    checkpoint_digest: str
    route_version: str
    observation_days: int
    parity_cases_per_source: int
    cohort_e2e_queries: int
    safety_violations: int
    parity_bps_lower: int
    citation_bps_lower: int
    completeness_bps_lower: int
    availability_bps_lower: int
    parity_min_bps: int
    citation_min_bps: int
    completeness_min_bps: int
    availability_min_bps: int
    holdout_changed: bool
    approver_roles: tuple[str, ...]
    formula_pass: bool
    decision_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CutoverDecisionV1":
        values = _strict(data, cls.FIELDS)
        if values["decision_version"] != CUTOVER_DECISION_V1:
            raise InvalidContractValue("unsupported cutover decision version")
        if not isinstance(values["approver_roles"], (list, tuple)):
            raise InvalidContractValue("approver_roles must be a list")
        roles = tuple(sorted(_text(role, "approver_roles", maximum=64).lower() for role in values["approver_roles"]))
        if set(roles) != set(_REQUIRED_APPROVER_ROLES) or len(roles) != len(_REQUIRED_APPROVER_ROLES):
            raise InvalidContractValue("approver_roles must be exactly migration, quality, security, product")
        ints = {
            "observation_days": _uint(values["observation_days"], "observation_days", minimum=0, maximum=3650),
            "parity_cases_per_source": _uint(values["parity_cases_per_source"], "parity_cases_per_source", minimum=0),
            "cohort_e2e_queries": _uint(values["cohort_e2e_queries"], "cohort_e2e_queries", minimum=0),
            "safety_violations": _uint(values["safety_violations"], "safety_violations", minimum=0, maximum=10**6),
            "parity_bps_lower": _uint(values["parity_bps_lower"], "parity_bps_lower", maximum=10000),
            "citation_bps_lower": _uint(values["citation_bps_lower"], "citation_bps_lower", maximum=10000),
            "completeness_bps_lower": _uint(values["completeness_bps_lower"], "completeness_bps_lower", maximum=10000),
            "availability_bps_lower": _uint(values["availability_bps_lower"], "availability_bps_lower", maximum=10000),
            "parity_min_bps": _uint(values["parity_min_bps"], "parity_min_bps", maximum=10000),
            "citation_min_bps": _uint(values["citation_min_bps"], "citation_min_bps", maximum=10000),
            "completeness_min_bps": _uint(values["completeness_min_bps"], "completeness_min_bps", maximum=10000),
            "availability_min_bps": _uint(values["availability_min_bps"], "availability_min_bps", maximum=10000),
        }
        holdout_changed = _bool(values["holdout_changed"], "holdout_changed")
        # PASS = S∧W∧N∧P∧C∧D∧Q∧L∧A∧R (plan formula; R/holdout encoded as holdout_changed false)
        computed = (
            ints["safety_violations"] == 0
            and ints["observation_days"] >= 3
            and ints["parity_cases_per_source"] >= 200
            and ints["cohort_e2e_queries"] >= 500
            and ints["parity_bps_lower"] >= ints["parity_min_bps"]
            and ints["citation_bps_lower"] >= ints["citation_min_bps"]
            and ints["completeness_bps_lower"] >= ints["completeness_min_bps"]
            and ints["availability_bps_lower"] >= ints["availability_min_bps"]
            and holdout_changed is False
        )
        formula_pass = _bool(values["formula_pass"], "formula_pass")
        if formula_pass != computed:
            raise InvalidContractValue("formula_pass does not match quantitative PASS formula")
        body = {
            "decision_version": CUTOVER_DECISION_V1,
            "decision_id": _text(values["decision_id"], "decision_id", maximum=128),
            "workspace_ref": _text(values["workspace_ref"], "workspace_ref"),
            "cohort_manifest_digest": _digest(values["cohort_manifest_digest"], "cohort_manifest_digest"),
            "resolved_scope_digest": _digest(values["resolved_scope_digest"], "resolved_scope_digest"),
            "contract_digest": _digest(values["contract_digest"], "contract_digest"),
            "source_manifest_digest": _digest(values["source_manifest_digest"], "source_manifest_digest"),
            "capability_manifest_digest": _digest(values["capability_manifest_digest"], "capability_manifest_digest"),
            "benchmark_manifest_digest": _digest(values["benchmark_manifest_digest"], "benchmark_manifest_digest"),
            "holdout_manifest_digest": _digest(values["holdout_manifest_digest"], "holdout_manifest_digest"),
            "generation_digest": _digest(values["generation_digest"], "generation_digest"),
            "checkpoint_digest": _digest(values["checkpoint_digest"], "checkpoint_digest"),
            "route_version": _text(values["route_version"], "route_version", maximum=64),
            **ints,
            "holdout_changed": holdout_changed,
            "approver_roles": list(roles),
            "formula_pass": formula_pass,
        }
        digest = _digest(values["decision_digest"], "decision_digest")
        if digest != canonical_ledger_digest("cutover-decision-v1", body):
            raise InvalidContractValue("decision_digest does not bind its body")
        return cls(
            CUTOVER_DECISION_V1, body["decision_id"], body["workspace_ref"], body["cohort_manifest_digest"],
            body["resolved_scope_digest"], body["contract_digest"], body["source_manifest_digest"],
            body["capability_manifest_digest"], body["benchmark_manifest_digest"], body["holdout_manifest_digest"],
            body["generation_digest"], body["checkpoint_digest"], body["route_version"],
            ints["observation_days"], ints["parity_cases_per_source"], ints["cohort_e2e_queries"],
            ints["safety_violations"], ints["parity_bps_lower"], ints["citation_bps_lower"],
            ints["completeness_bps_lower"], ints["availability_bps_lower"], ints["parity_min_bps"],
            ints["citation_min_bps"], ints["completeness_min_bps"], ints["availability_min_bps"],
            holdout_changed, roles, formula_pass, digest,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "decision_version": self.decision_version,
            "decision_id": self.decision_id,
            "workspace_ref": self.workspace_ref,
            "cohort_manifest_digest": self.cohort_manifest_digest,
            "resolved_scope_digest": self.resolved_scope_digest,
            "contract_digest": self.contract_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "capability_manifest_digest": self.capability_manifest_digest,
            "benchmark_manifest_digest": self.benchmark_manifest_digest,
            "holdout_manifest_digest": self.holdout_manifest_digest,
            "generation_digest": self.generation_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "route_version": self.route_version,
            "observation_days": self.observation_days,
            "parity_cases_per_source": self.parity_cases_per_source,
            "cohort_e2e_queries": self.cohort_e2e_queries,
            "safety_violations": self.safety_violations,
            "parity_bps_lower": self.parity_bps_lower,
            "citation_bps_lower": self.citation_bps_lower,
            "completeness_bps_lower": self.completeness_bps_lower,
            "availability_bps_lower": self.availability_bps_lower,
            "parity_min_bps": self.parity_min_bps,
            "citation_min_bps": self.citation_min_bps,
            "completeness_min_bps": self.completeness_min_bps,
            "availability_min_bps": self.availability_min_bps,
            "holdout_changed": self.holdout_changed,
            "approver_roles": list(self.approver_roles),
            "formula_pass": self.formula_pass,
            "decision_digest": self.decision_digest,
        }


def assert_cutover_decision_joins_scope_and_cohort(
    decision: CutoverDecisionV1,
    scope: ResolvedScopeV1,
    cohort: MigrationCohortManifestV1,
    *,
    contract_digest: str,
) -> None:
    if decision.resolved_scope_digest != resolved_scope_digest(scope):
        raise InvalidContractValue("cutover decision resolved_scope_digest mismatch")
    if decision.contract_digest != _digest(contract_digest, "contract_digest"):
        raise InvalidContractValue("cutover decision contract_digest mismatch")
    if decision.cohort_manifest_digest != cohort.manifest_digest:
        raise InvalidContractValue("cutover decision cohort_manifest_digest mismatch")
    if decision.source_manifest_digest != scope.source_manifest_digest or decision.source_manifest_digest != cohort.source_manifest_digest:
        raise InvalidContractValue("cutover decision source_manifest_digest mismatch")
    if decision.capability_manifest_digest != scope.capability_manifest_digest:
        raise InvalidContractValue("cutover decision capability_manifest_digest mismatch")
    if cohort.cohort_state not in {"CUTOVER_READY", "ROUTE_SWITCHED_NO_MUTATION"}:
        raise InvalidContractValue("cutover decision requires cohort CUTOVER_READY or ROUTE_SWITCHED_NO_MUTATION")
    if not decision.formula_pass:
        raise InvalidContractValue("cutover decision formula_pass is false")


def assert_live_route_switch_authorized(
    decision: CutoverDecisionV1,
    *,
    human_external_approvals_present: bool,
) -> None:
    """Live production route switch requires formula PASS and human external approvals.

    This module never performs the switch; callers must still be gated here.
    """
    if not decision.formula_pass:
        raise InvalidContractValue("live route switch refused: formula_pass is false")
    if not human_external_approvals_present:
        raise InvalidContractValue(
            "live route switch refused: human-controlled external approvals are required"
        )


def assert_destructive_decommission_authorized(
    state: str,
    *,
    retention_days_elapsed: int,
    evidence_backed: bool,
    human_external_approvals_present: bool,
) -> None:
    if state != "ROLLBACK_CLOSED":
        raise InvalidContractValue("decommission only from ROLLBACK_CLOSED")
    if retention_days_elapsed < 90:
        raise InvalidContractValue("90-day read-only retention not elapsed")
    if not evidence_backed:
        raise InvalidContractValue("decommission requires evidence-backed criteria")
    if not human_external_approvals_present:
        raise InvalidContractValue("decommission requires human-controlled external approvals")


__all__ = [
    "CUTOVER_DECISION_V1",
    "COHORT_MANIFEST_V1",
    "MigrationCohortManifestV1",
    "CutoverDecisionV1",
    "assert_cohort_subset_of_enabled_migration_sources",
    "assert_cohort_transition",
    "assert_pre_mutation_rollback_allowed",
    "assert_post_mutation_fail_closed",
    "assert_cutover_decision_joins_scope_and_cohort",
    "assert_live_route_switch_authorized",
    "assert_destructive_decommission_authorized",
    "canonical_ledger_digest",
]
