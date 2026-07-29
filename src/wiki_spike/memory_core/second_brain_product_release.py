"""Stage-5 product-release evidence DAG and operations drill receipts.

The product-release namespace is deliberately separate from Gate 8 / encrypted-
lifecycle foundational evidence. A product DAG may *reference* a foundational
receipt by exact digest, but it must never import, relabel, or rewrite Gate 8
artifacts. ResolvedScopeV1 and the Stage-0 contract digest are bound into every
product-release envelope so a scope/manifest mismatch fails closed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .errors import InvalidContractValue
from .second_brain_contracts import ResolvedScopeV1
from .second_brain_ledger_contracts import canonical_ledger_digest

PRODUCT_RELEASE_ENVELOPE_V1 = "second-brain-product-release-envelope-v1"
OPS_DRILL_RECEIPT_V1 = "second-brain-ops-drill-receipt-v1"
PRODUCT_RELEASE_NAMESPACE = "artifacts/product-release/second-brain-v1"
_FORBIDDEN_FOUNDATION_PATH_MARKERS = (
    "artifacts/conformance/encrypted-lifecycle/gate8",
    "artifacts/encrypted-lifecycle/gate8",
    "GATE8_",
    "gate8-runbook",
)
_HEX64 = frozenset("0123456789abcdef")
_DRILL_KINDS = frozenset({
    "recovery", "deletion", "credential", "route", "backup", "outage", "alert", "floor",
})


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in _HEX64 for ch in value):
        raise InvalidContractValue(f"{field} must be a lowercase sha256 hex digest")
    return value


def _text(value: Any, field: str, *, maximum: int = 512) -> str:
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


def assert_product_release_path(path: str) -> str:
    """Accept only paths inside the product-release namespace; reject Gate 8 paths."""
    text = _text(path, "path", maximum=1024)
    normalized = text.replace("\\", "/").lstrip("./")
    for marker in _FORBIDDEN_FOUNDATION_PATH_MARKERS:
        if marker in normalized:
            raise InvalidContractValue("product-release path must not import or relabel Gate 8 evidence")
    if not normalized.startswith(PRODUCT_RELEASE_NAMESPACE + "/") and normalized != PRODUCT_RELEASE_NAMESPACE:
        raise InvalidContractValue(
            f"product-release artifacts must live under {PRODUCT_RELEASE_NAMESPACE}/"
        )
    return normalized


@dataclass(frozen=True, slots=True)
class FoundationalReceiptRefV1:
    """Exact-digest reference to a separately authorized foundational receipt."""

    FIELDS = {"receipt_kind", "receipt_digest", "authorized_at", "authority_ref"}
    receipt_kind: str
    receipt_digest: str
    authorized_at: str
    authority_ref: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "FoundationalReceiptRefV1":
        values = _strict(data, cls.FIELDS)
        kind = _text(values["receipt_kind"], "receipt_kind", maximum=128)
        if kind.startswith("gate8") or "gate-8" in kind or kind.startswith("encrypted-lifecycle-gate8"):
            # Kind labels that claim to *be* Gate 8 product evidence are forbidden.
            # Referencing a foundational digest is allowed; relabeling is not.
            raise InvalidContractValue("foundational receipt kind must not relabel Gate 8 as product evidence")
        return cls(
            kind,
            _digest(values["receipt_digest"], "receipt_digest"),
            _text(values["authorized_at"], "authorized_at", maximum=64),
            _text(values["authority_ref"], "authority_ref", maximum=256),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "receipt_kind": self.receipt_kind,
            "receipt_digest": self.receipt_digest,
            "authorized_at": self.authorized_at,
            "authority_ref": self.authority_ref,
        }


@dataclass(frozen=True, slots=True)
class OpsDrillReceiptV1:
    """Body-free receipt for a recovery/deletion/credential/route/alert drill."""

    FIELDS = {
        "receipt_version", "drill_kind", "workspace_ref", "scenario_digest",
        "outcome", "observed_at", "operator_ref", "receipt_digest",
    }
    receipt_version: str
    drill_kind: str
    workspace_ref: str
    scenario_digest: str
    outcome: str
    observed_at: str
    operator_ref: str
    receipt_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "OpsDrillReceiptV1":
        values = _strict(data, cls.FIELDS)
        if values["receipt_version"] != OPS_DRILL_RECEIPT_V1:
            raise InvalidContractValue("unsupported ops drill receipt version")
        kind = _text(values["drill_kind"], "drill_kind", maximum=64)
        if kind not in _DRILL_KINDS:
            raise InvalidContractValue(f"unknown drill_kind: {kind}")
        outcome = _text(values["outcome"], "outcome", maximum=32)
        if outcome not in {"PASS", "FAIL", "BLOCKED"}:
            raise InvalidContractValue("drill outcome must be PASS, FAIL, or BLOCKED")
        body = {
            "receipt_version": OPS_DRILL_RECEIPT_V1,
            "drill_kind": kind,
            "workspace_ref": _text(values["workspace_ref"], "workspace_ref", maximum=256),
            "scenario_digest": _digest(values["scenario_digest"], "scenario_digest"),
            "outcome": outcome,
            "observed_at": _text(values["observed_at"], "observed_at", maximum=64),
            "operator_ref": _text(values["operator_ref"], "operator_ref", maximum=256),
        }
        digest = _digest(values["receipt_digest"], "receipt_digest")
        if digest != canonical_ledger_digest("ops-drill-receipt-v1", body):
            raise InvalidContractValue("ops drill receipt_digest does not bind its body")
        return cls(OPS_DRILL_RECEIPT_V1, kind, body["workspace_ref"], body["scenario_digest"],
                   outcome, body["observed_at"], body["operator_ref"], digest)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "receipt_version": self.receipt_version,
            "drill_kind": self.drill_kind,
            "workspace_ref": self.workspace_ref,
            "scenario_digest": self.scenario_digest,
            "outcome": self.outcome,
            "observed_at": self.observed_at,
            "operator_ref": self.operator_ref,
            "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True, slots=True)
class ProductReleaseEnvelopeV1:
    """Product-release evidence envelope bound to ResolvedScopeV1 and contract digest."""

    FIELDS = {
        "envelope_version", "release_id", "workspace_ref", "resolved_scope_digest",
        "contract_digest", "source_manifest_digest", "capability_manifest_digest",
        "benchmark_manifest_digest", "holdout_manifest_digest", "drill_receipt_digests",
        "foundational_receipt_refs", "artifact_paths", "envelope_digest",
    }
    envelope_version: str
    release_id: str
    workspace_ref: str
    resolved_scope_digest: str
    contract_digest: str
    source_manifest_digest: str
    capability_manifest_digest: str
    benchmark_manifest_digest: str
    holdout_manifest_digest: str
    drill_receipt_digests: tuple[str, ...]
    foundational_receipt_refs: tuple[FoundationalReceiptRefV1, ...]
    artifact_paths: tuple[str, ...]
    envelope_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ProductReleaseEnvelopeV1":
        values = _strict(data, cls.FIELDS)
        if values["envelope_version"] != PRODUCT_RELEASE_ENVELOPE_V1:
            raise InvalidContractValue("unsupported product-release envelope version")
        if not isinstance(values["drill_receipt_digests"], (list, tuple)) or not values["drill_receipt_digests"]:
            raise InvalidContractValue("drill_receipt_digests must be a non-empty list")
        drills = tuple(_digest(item, "drill_receipt_digests") for item in values["drill_receipt_digests"])
        if len(set(drills)) != len(drills):
            raise InvalidContractValue("drill_receipt_digests must be unique")
        if not isinstance(values["foundational_receipt_refs"], (list, tuple)):
            raise InvalidContractValue("foundational_receipt_refs must be a list")
        foundations = tuple(
            FoundationalReceiptRefV1.from_mapping(item) for item in values["foundational_receipt_refs"]
        )
        if not isinstance(values["artifact_paths"], (list, tuple)) or not values["artifact_paths"]:
            raise InvalidContractValue("artifact_paths must be a non-empty list")
        paths = tuple(assert_product_release_path(item) for item in values["artifact_paths"])
        if len(set(paths)) != len(paths):
            raise InvalidContractValue("artifact_paths must be unique")
        body = {
            "envelope_version": PRODUCT_RELEASE_ENVELOPE_V1,
            "release_id": _text(values["release_id"], "release_id", maximum=128),
            "workspace_ref": _text(values["workspace_ref"], "workspace_ref", maximum=256),
            "resolved_scope_digest": _digest(values["resolved_scope_digest"], "resolved_scope_digest"),
            "contract_digest": _digest(values["contract_digest"], "contract_digest"),
            "source_manifest_digest": _digest(values["source_manifest_digest"], "source_manifest_digest"),
            "capability_manifest_digest": _digest(values["capability_manifest_digest"], "capability_manifest_digest"),
            "benchmark_manifest_digest": _digest(values["benchmark_manifest_digest"], "benchmark_manifest_digest"),
            "holdout_manifest_digest": _digest(values["holdout_manifest_digest"], "holdout_manifest_digest"),
            "drill_receipt_digests": list(drills),
            "foundational_receipt_refs": [item.to_mapping() for item in foundations],
            "artifact_paths": list(paths),
        }
        digest = _digest(values["envelope_digest"], "envelope_digest")
        if digest != canonical_ledger_digest("product-release-envelope-v1", body):
            raise InvalidContractValue("envelope_digest does not bind its body")
        return cls(
            PRODUCT_RELEASE_ENVELOPE_V1, body["release_id"], body["workspace_ref"],
            body["resolved_scope_digest"], body["contract_digest"],
            body["source_manifest_digest"], body["capability_manifest_digest"],
            body["benchmark_manifest_digest"], body["holdout_manifest_digest"],
            drills, foundations, paths, digest,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "envelope_version": self.envelope_version,
            "release_id": self.release_id,
            "workspace_ref": self.workspace_ref,
            "resolved_scope_digest": self.resolved_scope_digest,
            "contract_digest": self.contract_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "capability_manifest_digest": self.capability_manifest_digest,
            "benchmark_manifest_digest": self.benchmark_manifest_digest,
            "holdout_manifest_digest": self.holdout_manifest_digest,
            "drill_receipt_digests": list(self.drill_receipt_digests),
            "foundational_receipt_refs": [item.to_mapping() for item in self.foundational_receipt_refs],
            "artifact_paths": list(self.artifact_paths),
            "envelope_digest": self.envelope_digest,
        }


def resolved_scope_digest(scope: ResolvedScopeV1) -> str:
    return canonical_ledger_digest("resolved-scope-body-v1", scope.to_mapping())


def assert_envelope_matches_scope_and_contract(
    envelope: ProductReleaseEnvelopeV1,
    scope: ResolvedScopeV1,
    contract_digest: str,
    *,
    source_manifest_digest: str,
    capability_manifest_digest: str,
    benchmark_manifest_digest: str,
    holdout_manifest_digest: str,
    known_foundational_digests: Sequence[str] = (),
    stale_foundational_digests: Sequence[str] = (),
) -> None:
    """Fail closed on resolved-scope/manifest mismatch or stale foundational refs."""
    if envelope.resolved_scope_digest != resolved_scope_digest(scope):
        raise InvalidContractValue("product-release envelope resolved_scope_digest mismatch")
    if envelope.contract_digest != _digest(contract_digest, "contract_digest"):
        raise InvalidContractValue("product-release envelope contract_digest mismatch")
    if envelope.source_manifest_digest != _digest(source_manifest_digest, "source_manifest_digest"):
        raise InvalidContractValue("source_manifest_digest mismatch")
    if envelope.capability_manifest_digest != _digest(capability_manifest_digest, "capability_manifest_digest"):
        raise InvalidContractValue("capability_manifest_digest mismatch")
    if envelope.benchmark_manifest_digest != _digest(benchmark_manifest_digest, "benchmark_manifest_digest"):
        raise InvalidContractValue("benchmark_manifest_digest mismatch")
    if envelope.holdout_manifest_digest != _digest(holdout_manifest_digest, "holdout_manifest_digest"):
        raise InvalidContractValue("holdout_manifest_digest mismatch")
    if scope.source_manifest_digest != envelope.source_manifest_digest:
        raise InvalidContractValue("envelope source manifest does not match resolved scope")
    if scope.capability_manifest_digest != envelope.capability_manifest_digest:
        raise InvalidContractValue("envelope capability manifest does not match resolved scope")
    known = set(known_foundational_digests)
    stale = set(stale_foundational_digests)
    for ref in envelope.foundational_receipt_refs:
        if ref.receipt_digest in stale:
            raise InvalidContractValue("stale foundational receipt cannot join product-release evidence")
        if known and ref.receipt_digest not in known:
            raise InvalidContractValue("unknown foundational receipt digest")


def assert_required_drills_present(
    drills: Sequence[OpsDrillReceiptV1],
    *,
    required_kinds: Sequence[str] = ("recovery", "deletion", "credential", "route", "alert"),
) -> None:
    """Stage-5 exit requires the named drill kinds, all PASS."""
    by_kind = {}
    for drill in drills:
        if drill.drill_kind in by_kind:
            raise InvalidContractValue(f"duplicate drill kind: {drill.drill_kind}")
        by_kind[drill.drill_kind] = drill
    missing = [kind for kind in required_kinds if kind not in by_kind]
    if missing:
        raise InvalidContractValue(f"missing required drill kinds: {missing}")
    for kind in required_kinds:
        if by_kind[kind].outcome != "PASS":
            raise InvalidContractValue(f"required drill {kind} did not PASS")


__all__ = [
    "PRODUCT_RELEASE_ENVELOPE_V1",
    "OPS_DRILL_RECEIPT_V1",
    "PRODUCT_RELEASE_NAMESPACE",
    "FoundationalReceiptRefV1",
    "OpsDrillReceiptV1",
    "ProductReleaseEnvelopeV1",
    "resolved_scope_digest",
    "assert_product_release_path",
    "assert_envelope_matches_scope_and_contract",
    "assert_required_drills_present",
    "canonical_ledger_digest",
]
