"""Stage 5: product-release evidence DAG and ops drill receipts."""
from __future__ import annotations

import pytest
from test_decision_contracts import DIGEST, scope
from test_stage3_ledger_persistence import digest, ref
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_product_release import (
    OPS_DRILL_RECEIPT_V1,
    PRODUCT_RELEASE_ENVELOPE_V1,
    PRODUCT_RELEASE_NAMESPACE,
    FoundationalReceiptRefV1,
    OpsDrillReceiptV1,
    ProductReleaseEnvelopeV1,
    assert_envelope_matches_scope_and_contract,
    assert_product_release_path,
    assert_required_drills_present,
    canonical_ledger_digest,
    resolved_scope_digest,
)


def _scope() -> ResolvedScopeV1:
    return ResolvedScopeV1.from_mapping(scope())


def _drill(kind: str, *, outcome: str = "PASS") -> OpsDrillReceiptV1:
    body = {
        "receipt_version": OPS_DRILL_RECEIPT_V1,
        "drill_kind": kind,
        "workspace_ref": ref("workspace", "ops"),
        "scenario_digest": digest(f"scenario-{kind}"),
        "outcome": outcome,
        "observed_at": "2026-07-29T00:00:00Z",
        "operator_ref": ref("operator", "sre"),
    }
    body["receipt_digest"] = canonical_ledger_digest("ops-drill-receipt-v1", body)
    return OpsDrillReceiptV1.from_mapping(body)


def _envelope(
    scope_obj: ResolvedScopeV1,
    drills: list[OpsDrillReceiptV1],
    *,
    foundations: list[dict] | None = None,
    paths: list[str] | None = None,
    contract_digest: str | None = None,
    benchmark_digest: str | None = None,
) -> ProductReleaseEnvelopeV1:
    body = {
        "envelope_version": PRODUCT_RELEASE_ENVELOPE_V1,
        "release_id": "second-brain-v1.0.0-rc1",
        "workspace_ref": ref("workspace", "ops"),
        "resolved_scope_digest": resolved_scope_digest(scope_obj),
        "contract_digest": contract_digest or digest("contract"),
        "source_manifest_digest": scope_obj.source_manifest_digest,
        "capability_manifest_digest": scope_obj.capability_manifest_digest,
        "benchmark_manifest_digest": benchmark_digest or digest("benchmark"),
        "holdout_manifest_digest": digest("holdout"),
        "drill_receipt_digests": [item.receipt_digest for item in drills],
        "foundational_receipt_refs": foundations or [],
        "artifact_paths": paths or [
            f"{PRODUCT_RELEASE_NAMESPACE}/drills/recovery.json",
            f"{PRODUCT_RELEASE_NAMESPACE}/envelope.json",
        ],
    }
    body["envelope_digest"] = canonical_ledger_digest("product-release-envelope-v1", body)
    return ProductReleaseEnvelopeV1.from_mapping(body)


def test_product_release_path_rejects_gate8_import_and_requires_namespace() -> None:
    assert_product_release_path(f"{PRODUCT_RELEASE_NAMESPACE}/envelope.json")
    with pytest.raises(InvalidContractValue, match="Gate 8"):
        assert_product_release_path("artifacts/conformance/encrypted-lifecycle/gate8/g012-local-close-report.json")
    with pytest.raises(InvalidContractValue, match="Gate 8"):
        assert_product_release_path("docs/GATE8_COMPLETION_KR.md")
    with pytest.raises(InvalidContractValue, match="product-release artifacts must live under"):
        assert_product_release_path("artifacts/conformance/second-brain/g016-suite-receipt.json")


def test_foundational_ref_allows_exact_digest_but_rejects_gate8_relabel() -> None:
    ok = FoundationalReceiptRefV1.from_mapping({
        "receipt_kind": "encrypted-lifecycle-foundation",
        "receipt_digest": digest("foundation"),
        "authorized_at": "2026-07-28T00:00:00Z",
        "authority_ref": "security-board",
    })
    assert ok.receipt_digest == digest("foundation")
    with pytest.raises(InvalidContractValue, match="relabel Gate 8"):
        FoundationalReceiptRefV1.from_mapping({
            "receipt_kind": "gate8-product-release",
            "receipt_digest": digest("foundation"),
            "authorized_at": "2026-07-28T00:00:00Z",
            "authority_ref": "security-board",
        })


def test_required_drills_must_all_pass() -> None:
    drills = [_drill(kind) for kind in ("recovery", "deletion", "credential", "route", "alert")]
    assert_required_drills_present(drills)
    with pytest.raises(InvalidContractValue, match="missing required drill"):
        assert_required_drills_present(drills[:-1])
    bad = drills[:-1] + [_drill("alert", outcome="FAIL")]
    with pytest.raises(InvalidContractValue, match="did not PASS"):
        assert_required_drills_present(bad)


def test_envelope_binds_scope_contract_and_manifests() -> None:
    scope_obj = _scope()
    drills = [_drill(kind) for kind in ("recovery", "deletion", "credential", "route", "alert")]
    envelope = _envelope(scope_obj, drills, contract_digest=digest("contract"), benchmark_digest=digest("benchmark"))
    assert_envelope_matches_scope_and_contract(
        envelope, scope_obj, digest("contract"),
        source_manifest_digest=scope_obj.source_manifest_digest,
        capability_manifest_digest=scope_obj.capability_manifest_digest,
        benchmark_manifest_digest=digest("benchmark"),
        holdout_manifest_digest=digest("holdout"),
    )
    with pytest.raises(InvalidContractValue, match="contract_digest mismatch"):
        assert_envelope_matches_scope_and_contract(
            envelope, scope_obj, digest("other-contract"),
            source_manifest_digest=scope_obj.source_manifest_digest,
            capability_manifest_digest=scope_obj.capability_manifest_digest,
            benchmark_manifest_digest=digest("benchmark"),
            holdout_manifest_digest=digest("holdout"),
        )
    with pytest.raises(InvalidContractValue, match="resolved_scope_digest mismatch"):
        raw = scope()
        raw["mandatory_release_constraints"] = ["other-constraint"]
        other = ResolvedScopeV1.from_mapping(raw)
        assert_envelope_matches_scope_and_contract(
            envelope, other, digest("contract"),
            source_manifest_digest=scope_obj.source_manifest_digest,
            capability_manifest_digest=scope_obj.capability_manifest_digest,
            benchmark_manifest_digest=digest("benchmark"),
            holdout_manifest_digest=digest("holdout"),
        )


def test_stale_and_unknown_foundational_receipts_fail_closed() -> None:
    scope_obj = _scope()
    drills = [_drill(kind) for kind in ("recovery", "deletion", "credential", "route", "alert")]
    foundation = {
        "receipt_kind": "encrypted-lifecycle-foundation",
        "receipt_digest": digest("fresh-foundation"),
        "authorized_at": "2026-07-28T00:00:00Z",
        "authority_ref": "security-board",
    }
    envelope = _envelope(scope_obj, drills, foundations=[foundation])
    assert_envelope_matches_scope_and_contract(
        envelope, scope_obj, digest("contract"),
        source_manifest_digest=scope_obj.source_manifest_digest,
        capability_manifest_digest=scope_obj.capability_manifest_digest,
        benchmark_manifest_digest=digest("benchmark"),
        holdout_manifest_digest=digest("holdout"),
        known_foundational_digests=(digest("fresh-foundation"),),
    )
    with pytest.raises(InvalidContractValue, match="stale foundational"):
        assert_envelope_matches_scope_and_contract(
            envelope, scope_obj, digest("contract"),
            source_manifest_digest=scope_obj.source_manifest_digest,
            capability_manifest_digest=scope_obj.capability_manifest_digest,
            benchmark_manifest_digest=digest("benchmark"),
            holdout_manifest_digest=digest("holdout"),
            stale_foundational_digests=(digest("fresh-foundation"),),
        )
    with pytest.raises(InvalidContractValue, match="unknown foundational"):
        assert_envelope_matches_scope_and_contract(
            envelope, scope_obj, digest("contract"),
            source_manifest_digest=scope_obj.source_manifest_digest,
            capability_manifest_digest=scope_obj.capability_manifest_digest,
            benchmark_manifest_digest=digest("benchmark"),
            holdout_manifest_digest=digest("holdout"),
            known_foundational_digests=(digest("other-foundation"),),
        )


def test_envelope_rejects_gate8_artifact_path_inside_mapping() -> None:
    scope_obj = _scope()
    drills = [_drill(kind) for kind in ("recovery", "deletion", "credential", "route", "alert")]
    with pytest.raises(InvalidContractValue, match="Gate 8"):
        _envelope(
            scope_obj, drills,
            paths=[f"{PRODUCT_RELEASE_NAMESPACE}/ok.json", "artifacts/conformance/encrypted-lifecycle/gate8/x.json"],
        )
