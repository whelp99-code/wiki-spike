"""Adversarial / red-team suite for G017: Stage-5 product-release evidence DAG.

Surface: API / package / algorithm. Prove product-release fail-closed across the
frozen attack classes (Gate 8 path import variants, Gate 8 kind relabel,
stale/unknown foundational digests, scope/contract/manifest mismatches,
missing/failing required drills, duplicate drill kinds, path outside
product-release namespace, envelope digest tamper).
"""
from __future__ import annotations

import copy

import pytest
from test_decision_contracts import scope
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

_REQUIRED_KINDS = ("recovery", "deletion", "credential", "route", "alert")
_GATE8_PATH_VARIANTS = (
    "artifacts/conformance/encrypted-lifecycle/gate8/g012-local-close-report.json",
    "artifacts/conformance/encrypted-lifecycle/gate8/redteam/red-team-report.json",
    "artifacts/encrypted-lifecycle/gate8/join/manifest.json",
    "docs/GATE8_COMPLETION_KR.md",
    "runbooks/gate8-runbook.md",
    # Relative form that still retains the literal Gate 8 marker substring.
    f"./{PRODUCT_RELEASE_NAMESPACE}/drills/../../../artifacts/conformance/encrypted-lifecycle/gate8/x.json",
    "artifacts\\conformance\\encrypted-lifecycle\\gate8\\x.json",
    "prefix/artifacts/conformance/encrypted-lifecycle/gate8/nested.json",
    "docs/ops/GATE8_notes.md",
    # Nested under product-release namespace but still carrying the literal marker.
    f"{PRODUCT_RELEASE_NAMESPACE}/nested/artifacts/conformance/encrypted-lifecycle/gate8/x.json",
    f"{PRODUCT_RELEASE_NAMESPACE}/vendor/artifacts/encrypted-lifecycle/gate8/canary.json",
)
_GATE8_KIND_RELABELS = (
    "gate8-product-release",
    "gate8",
    "gate8-close-receipt",
    "encrypted-lifecycle-gate8",
    "encrypted-lifecycle-gate8-join",
    "product-gate-8-evidence",
    "my-gate-8-relabel",
)
_OUTSIDE_NAMESPACE_PATHS = (
    "artifacts/conformance/second-brain/g016-suite-receipt.json",
    "artifacts/product-release/other-product/envelope.json",
    "artifacts/second-brain/stage5.json",
    "docs/product/decisions/DB-05-benchmark-governance.md",
    "tmp/product-release.json",
    PRODUCT_RELEASE_NAMESPACE + "-adjacent/envelope.json",
    "artifacts/product-release/second-brain-v2/envelope.json",
)


def _scope(**overrides: object) -> ResolvedScopeV1:
    raw = scope()
    raw.update(overrides)
    return ResolvedScopeV1.from_mapping(raw)


def _drill(kind: str, *, outcome: str = "PASS", suffix: str = "") -> OpsDrillReceiptV1:
    body = {
        "receipt_version": OPS_DRILL_RECEIPT_V1,
        "drill_kind": kind,
        "workspace_ref": ref("workspace", "ops"),
        "scenario_digest": digest(f"scenario-{kind}{suffix}"),
        "outcome": outcome,
        "observed_at": "2026-07-29T00:00:00Z",
        "operator_ref": ref("operator", "sre"),
    }
    body["receipt_digest"] = canonical_ledger_digest("ops-drill-receipt-v1", body)
    return OpsDrillReceiptV1.from_mapping(body)


def _required_drills(*, fail_kind: str | None = None) -> list[OpsDrillReceiptV1]:
    drills: list[OpsDrillReceiptV1] = []
    for kind in _REQUIRED_KINDS:
        outcome = "FAIL" if kind == fail_kind else "PASS"
        drills.append(_drill(kind, outcome=outcome))
    return drills


def _foundation(
    *,
    kind: str = "encrypted-lifecycle-foundation",
    receipt_digest: str | None = None,
) -> dict[str, str]:
    return {
        "receipt_kind": kind,
        "receipt_digest": receipt_digest or digest("fresh-foundation"),
        "authorized_at": "2026-07-28T00:00:00Z",
        "authority_ref": "security-board",
    }


def _envelope_body(
    scope_obj: ResolvedScopeV1,
    drills: list[OpsDrillReceiptV1],
    *,
    foundations: list[dict] | None = None,
    paths: list[str] | None = None,
    contract_digest: str | None = None,
    source_manifest_digest: str | None = None,
    capability_manifest_digest: str | None = None,
    benchmark_digest: str | None = None,
    holdout_digest: str | None = None,
) -> dict:
    body = {
        "envelope_version": PRODUCT_RELEASE_ENVELOPE_V1,
        "release_id": "second-brain-v1.0.0-rc1",
        "workspace_ref": ref("workspace", "ops"),
        "resolved_scope_digest": resolved_scope_digest(scope_obj),
        "contract_digest": contract_digest or digest("contract"),
        "source_manifest_digest": source_manifest_digest or scope_obj.source_manifest_digest,
        "capability_manifest_digest": capability_manifest_digest or scope_obj.capability_manifest_digest,
        "benchmark_manifest_digest": benchmark_digest or digest("benchmark"),
        "holdout_manifest_digest": holdout_digest or digest("holdout"),
        "drill_receipt_digests": [item.receipt_digest for item in drills],
        "foundational_receipt_refs": foundations if foundations is not None else [],
        "artifact_paths": paths or [
            f"{PRODUCT_RELEASE_NAMESPACE}/drills/recovery.json",
            f"{PRODUCT_RELEASE_NAMESPACE}/envelope.json",
        ],
    }
    body["envelope_digest"] = canonical_ledger_digest("product-release-envelope-v1", body)
    return body


def _envelope(
    scope_obj: ResolvedScopeV1,
    drills: list[OpsDrillReceiptV1],
    **kwargs: object,
) -> ProductReleaseEnvelopeV1:
    return ProductReleaseEnvelopeV1.from_mapping(_envelope_body(scope_obj, drills, **kwargs))


def _assert_match(
    envelope: ProductReleaseEnvelopeV1,
    scope_obj: ResolvedScopeV1,
    *,
    contract_digest: str | None = None,
    source_manifest_digest: str | None = None,
    capability_manifest_digest: str | None = None,
    benchmark_manifest_digest: str | None = None,
    holdout_manifest_digest: str | None = None,
    known_foundational_digests: tuple[str, ...] = (),
    stale_foundational_digests: tuple[str, ...] = (),
) -> None:
    assert_envelope_matches_scope_and_contract(
        envelope,
        scope_obj,
        contract_digest or digest("contract"),
        source_manifest_digest=source_manifest_digest or scope_obj.source_manifest_digest,
        capability_manifest_digest=capability_manifest_digest or scope_obj.capability_manifest_digest,
        benchmark_manifest_digest=benchmark_manifest_digest or digest("benchmark"),
        holdout_manifest_digest=holdout_manifest_digest or digest("holdout"),
        known_foundational_digests=known_foundational_digests,
        stale_foundational_digests=stale_foundational_digests,
    )


# ---------------------------------------------------------------------------
# A1 -- Gate 8 path import variants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", _GATE8_PATH_VARIANTS, ids=lambda p: p.replace("/", "_")[:80])
def test_g017_a1_gate8_path_import_variant_refuses(path: str) -> None:
    with pytest.raises(InvalidContractValue, match="Gate 8"):
        assert_product_release_path(path)


def test_g017_a1_gate8_path_inside_envelope_artifact_paths_refuses() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    for gate8_path in (
        "artifacts/conformance/encrypted-lifecycle/gate8/x.json",
        "docs/GATE8_COMPLETION_KR.md",
        "artifacts/encrypted-lifecycle/gate8/canary.json",
        "notes/gate8-runbook-excerpt.md",
    ):
        with pytest.raises(InvalidContractValue, match="Gate 8"):
            _envelope(
                scope_obj,
                drills,
                paths=[f"{PRODUCT_RELEASE_NAMESPACE}/ok.json", gate8_path],
            )


def test_g017_a1_honest_product_release_path_still_accepted() -> None:
    assert assert_product_release_path(f"{PRODUCT_RELEASE_NAMESPACE}/envelope.json") == (
        f"{PRODUCT_RELEASE_NAMESPACE}/envelope.json"
    )
    assert assert_product_release_path(PRODUCT_RELEASE_NAMESPACE) == PRODUCT_RELEASE_NAMESPACE
    assert assert_product_release_path(f"./{PRODUCT_RELEASE_NAMESPACE}/drills/alert.json") == (
        f"{PRODUCT_RELEASE_NAMESPACE}/drills/alert.json"
    )


def test_g017_a1_dotdot_escape_omitting_literal_marker_is_observed_gap() -> None:
    """Path segments are collapsed before namespace/marker checks so a
    ``namespace/../gate8/...`` escape cannot omit the Gate 8 marker while still
    targeting foundational evidence.
    """
    sneaky = f"{PRODUCT_RELEASE_NAMESPACE}/../conformance/encrypted-lifecycle/gate8/x.json"
    with pytest.raises(InvalidContractValue, match="Gate 8|product-release artifacts must live under"):
        assert_product_release_path(sneaky)

    sneaky2 = f"{PRODUCT_RELEASE_NAMESPACE}/foo/../../encrypted-lifecycle/gate8/x.json"
    with pytest.raises(InvalidContractValue, match="Gate 8|product-release artifacts must live under"):
        assert_product_release_path(sneaky2)


# ---------------------------------------------------------------------------
# A2 -- Gate 8 kind relabel
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", _GATE8_KIND_RELABELS)
def test_g017_a2_gate8_kind_relabel_refuses(kind: str) -> None:
    with pytest.raises(InvalidContractValue, match="relabel Gate 8"):
        FoundationalReceiptRefV1.from_mapping(_foundation(kind=kind))


def test_g017_a2_gate8_kind_relabel_inside_envelope_refuses() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    with pytest.raises(InvalidContractValue, match="relabel Gate 8"):
        _envelope(
            scope_obj,
            drills,
            foundations=[_foundation(kind="gate8-product-proof")],
        )


def test_g017_a2_honest_foundational_kind_still_accepted() -> None:
    ok = FoundationalReceiptRefV1.from_mapping(_foundation())
    assert ok.receipt_kind == "encrypted-lifecycle-foundation"
    assert ok.receipt_digest == digest("fresh-foundation")
    # Adjacent-looking but non-relabel kinds remain legal exact-digest refs.
    also = FoundationalReceiptRefV1.from_mapping(
        _foundation(kind="encrypted-lifecycle-foundation-v2")
    )
    assert also.receipt_kind == "encrypted-lifecycle-foundation-v2"


# ---------------------------------------------------------------------------
# A3 -- stale / unknown foundational digests
# ---------------------------------------------------------------------------


def test_g017_a3_stale_foundational_digest_refuses() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    foundation = _foundation(receipt_digest=digest("stale-foundation"))
    envelope = _envelope(scope_obj, drills, foundations=[foundation])
    with pytest.raises(InvalidContractValue, match="stale foundational"):
        _assert_match(
            envelope,
            scope_obj,
            known_foundational_digests=(digest("stale-foundation"),),
            stale_foundational_digests=(digest("stale-foundation"),),
        )


def test_g017_a3_unknown_foundational_digest_refuses() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    foundation = _foundation(receipt_digest=digest("not-on-allowlist"))
    envelope = _envelope(scope_obj, drills, foundations=[foundation])
    with pytest.raises(InvalidContractValue, match="unknown foundational"):
        _assert_match(
            envelope,
            scope_obj,
            known_foundational_digests=(digest("authorized-only"),),
        )


def test_g017_a3_fresh_known_foundational_digest_accepted() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    foundation = _foundation(receipt_digest=digest("fresh-ok"))
    envelope = _envelope(scope_obj, drills, foundations=[foundation])
    _assert_match(
        envelope,
        scope_obj,
        known_foundational_digests=(digest("fresh-ok"), digest("other-authorized")),
        stale_foundational_digests=(digest("some-other-stale"),),
    )


def test_g017_a3_mixed_refs_fail_when_any_is_stale_or_unknown() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    good = _foundation(receipt_digest=digest("good-f"))
    stale = _foundation(receipt_digest=digest("stale-f"), kind="security-floor")
    envelope = _envelope(scope_obj, drills, foundations=[good, stale])
    with pytest.raises(InvalidContractValue, match="stale foundational"):
        _assert_match(
            envelope,
            scope_obj,
            known_foundational_digests=(digest("good-f"), digest("stale-f")),
            stale_foundational_digests=(digest("stale-f"),),
        )
    unknown = _foundation(receipt_digest=digest("unknown-f"), kind="security-floor")
    envelope2 = _envelope(scope_obj, drills, foundations=[good, unknown])
    with pytest.raises(InvalidContractValue, match="unknown foundational"):
        _assert_match(
            envelope2,
            scope_obj,
            known_foundational_digests=(digest("good-f"),),
        )


# ---------------------------------------------------------------------------
# A4 -- scope / contract / manifest mismatches
# ---------------------------------------------------------------------------


def test_g017_a4_contract_digest_mismatch_refuses() -> None:
    scope_obj = _scope()
    envelope = _envelope(scope_obj, _required_drills(), contract_digest=digest("contract-a"))
    with pytest.raises(InvalidContractValue, match="contract_digest mismatch"):
        _assert_match(envelope, scope_obj, contract_digest=digest("contract-b"))


def test_g017_a4_resolved_scope_digest_mismatch_refuses() -> None:
    scope_obj = _scope()
    envelope = _envelope(scope_obj, _required_drills())
    other = _scope(mandatory_release_constraints=["other-constraint"])
    with pytest.raises(InvalidContractValue, match="resolved_scope_digest mismatch"):
        _assert_match(envelope, other)


def test_g017_a4_source_manifest_digest_mismatch_refuses() -> None:
    scope_obj = _scope()
    envelope = _envelope(scope_obj, _required_drills())
    with pytest.raises(InvalidContractValue, match="source_manifest_digest mismatch"):
        _assert_match(envelope, scope_obj, source_manifest_digest=digest("other-source"))


def test_g017_a4_capability_manifest_digest_mismatch_refuses() -> None:
    scope_obj = _scope()
    envelope = _envelope(scope_obj, _required_drills())
    with pytest.raises(InvalidContractValue, match="capability_manifest_digest mismatch"):
        _assert_match(envelope, scope_obj, capability_manifest_digest=digest("other-cap"))


def test_g017_a4_benchmark_manifest_digest_mismatch_refuses() -> None:
    scope_obj = _scope()
    envelope = _envelope(scope_obj, _required_drills(), benchmark_digest=digest("bench-a"))
    with pytest.raises(InvalidContractValue, match="benchmark_manifest_digest mismatch"):
        _assert_match(envelope, scope_obj, benchmark_manifest_digest=digest("bench-b"))


def test_g017_a4_holdout_manifest_digest_mismatch_refuses() -> None:
    scope_obj = _scope()
    envelope = _envelope(scope_obj, _required_drills(), holdout_digest=digest("hold-a"))
    with pytest.raises(InvalidContractValue, match="holdout_manifest_digest mismatch"):
        _assert_match(envelope, scope_obj, holdout_manifest_digest=digest("hold-b"))


def test_g017_a4_envelope_source_manifest_diverges_from_scope_refuses() -> None:
    """Envelope binds a different source digest than the presented ResolvedScopeV1."""
    scope_obj = _scope()
    foreign_source = digest("foreign-source-manifest")
    assert foreign_source != scope_obj.source_manifest_digest
    envelope = _envelope(
        scope_obj,
        _required_drills(),
        source_manifest_digest=foreign_source,
    )
    # Match path supplies the foreign digest so field-level check passes, then
    # the scope cross-check must still fail closed.
    with pytest.raises(InvalidContractValue, match="source manifest does not match resolved scope"):
        assert_envelope_matches_scope_and_contract(
            envelope,
            scope_obj,
            digest("contract"),
            source_manifest_digest=foreign_source,
            capability_manifest_digest=scope_obj.capability_manifest_digest,
            benchmark_manifest_digest=digest("benchmark"),
            holdout_manifest_digest=digest("holdout"),
        )


def test_g017_a4_envelope_capability_manifest_diverges_from_scope_refuses() -> None:
    scope_obj = _scope()
    foreign_cap = digest("foreign-capability-manifest")
    assert foreign_cap != scope_obj.capability_manifest_digest
    envelope = _envelope(
        scope_obj,
        _required_drills(),
        capability_manifest_digest=foreign_cap,
    )
    with pytest.raises(InvalidContractValue, match="capability manifest does not match resolved scope"):
        assert_envelope_matches_scope_and_contract(
            envelope,
            scope_obj,
            digest("contract"),
            source_manifest_digest=scope_obj.source_manifest_digest,
            capability_manifest_digest=foreign_cap,
            benchmark_manifest_digest=digest("benchmark"),
            holdout_manifest_digest=digest("holdout"),
        )


def test_g017_a4_honest_scope_contract_manifest_binding_accepted() -> None:
    scope_obj = _scope()
    envelope = _envelope(scope_obj, _required_drills())
    _assert_match(envelope, scope_obj)


# ---------------------------------------------------------------------------
# A5 -- missing / failing required drills
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing_kind", _REQUIRED_KINDS)
def test_g017_a5_missing_required_drill_kind_refuses(missing_kind: str) -> None:
    drills = [_drill(kind) for kind in _REQUIRED_KINDS if kind != missing_kind]
    with pytest.raises(InvalidContractValue, match="missing required drill"):
        assert_required_drills_present(drills)


@pytest.mark.parametrize("fail_kind", _REQUIRED_KINDS)
def test_g017_a5_failing_required_drill_refuses(fail_kind: str) -> None:
    drills = _required_drills(fail_kind=fail_kind)
    with pytest.raises(InvalidContractValue, match=f"required drill {fail_kind} did not PASS"):
        assert_required_drills_present(drills)


def test_g017_a5_blocked_required_drill_refuses() -> None:
    drills = [_drill(kind, outcome="BLOCKED" if kind == "route" else "PASS") for kind in _REQUIRED_KINDS]
    with pytest.raises(InvalidContractValue, match="required drill route did not PASS"):
        assert_required_drills_present(drills)


def test_g017_a5_empty_drill_set_refuses() -> None:
    with pytest.raises(InvalidContractValue, match="missing required drill"):
        assert_required_drills_present([])


def test_g017_a5_optional_kinds_alone_do_not_satisfy_required_set() -> None:
    drills = [_drill(kind) for kind in ("backup", "outage", "floor")]
    with pytest.raises(InvalidContractValue, match="missing required drill"):
        assert_required_drills_present(drills)


def test_g017_a5_all_required_pass_with_optional_extras_accepted() -> None:
    drills = _required_drills() + [_drill("backup"), _drill("outage"), _drill("floor")]
    assert_required_drills_present(drills)


# ---------------------------------------------------------------------------
# A6 -- duplicate drill kinds
# ---------------------------------------------------------------------------


def test_g017_a6_duplicate_required_drill_kind_refuses() -> None:
    drills = _required_drills() + [_drill("alert", suffix="-dup")]
    with pytest.raises(InvalidContractValue, match="duplicate drill kind: alert"):
        assert_required_drills_present(drills)


def test_g017_a6_duplicate_optional_drill_kind_refuses() -> None:
    drills = _required_drills() + [_drill("backup", suffix="-a"), _drill("backup", suffix="-b")]
    with pytest.raises(InvalidContractValue, match="duplicate drill kind: backup"):
        assert_required_drills_present(drills)


def test_g017_a6_duplicate_drill_receipt_digests_in_envelope_refuse() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    body = _envelope_body(scope_obj, drills)
    # Smuggle a duplicate digest entry while keeping a valid list shape.
    body["drill_receipt_digests"] = list(body["drill_receipt_digests"]) + [drills[0].receipt_digest]
    body["envelope_digest"] = canonical_ledger_digest("product-release-envelope-v1", {
        k: v for k, v in body.items() if k != "envelope_digest"
    })
    with pytest.raises(InvalidContractValue, match="drill_receipt_digests must be unique"):
        ProductReleaseEnvelopeV1.from_mapping(body)


# ---------------------------------------------------------------------------
# A7 -- path outside product-release namespace
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", _OUTSIDE_NAMESPACE_PATHS, ids=lambda p: p.replace("/", "_")[:80])
def test_g017_a7_path_outside_product_release_namespace_refuses(path: str) -> None:
    with pytest.raises(InvalidContractValue, match="product-release artifacts must live under"):
        assert_product_release_path(path)


def test_g017_a7_outside_namespace_path_inside_envelope_refuses() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    with pytest.raises(InvalidContractValue, match="product-release artifacts must live under"):
        _envelope(
            scope_obj,
            drills,
            paths=[
                f"{PRODUCT_RELEASE_NAMESPACE}/envelope.json",
                "artifacts/conformance/second-brain/g016-suite-receipt.json",
            ],
        )


def test_g017_a7_duplicate_artifact_paths_refuse() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    path = f"{PRODUCT_RELEASE_NAMESPACE}/envelope.json"
    with pytest.raises(InvalidContractValue, match="artifact_paths must be unique"):
        _envelope(scope_obj, drills, paths=[path, path])


# ---------------------------------------------------------------------------
# A8 -- envelope / drill receipt digest tamper
# ---------------------------------------------------------------------------


def test_g017_a8_envelope_digest_tamper_refuses() -> None:
    scope_obj = _scope()
    body = _envelope_body(scope_obj, _required_drills())
    body["envelope_digest"] = digest("unrelated-tamper")
    with pytest.raises(InvalidContractValue, match="envelope_digest does not bind"):
        ProductReleaseEnvelopeV1.from_mapping(body)


def test_g017_a8_envelope_body_field_swap_without_redigest_refuses() -> None:
    scope_obj = _scope()
    body = _envelope_body(scope_obj, _required_drills())
    # Mutate a bound field while leaving envelope_digest stale.
    body["release_id"] = "second-brain-v1.0.0-rc1-tampered"
    with pytest.raises(InvalidContractValue, match="envelope_digest does not bind"):
        ProductReleaseEnvelopeV1.from_mapping(body)


def test_g017_a8_envelope_path_swap_without_redigest_refuses() -> None:
    scope_obj = _scope()
    body = _envelope_body(scope_obj, _required_drills())
    body["artifact_paths"] = [
        f"{PRODUCT_RELEASE_NAMESPACE}/drills/recovery.json",
        f"{PRODUCT_RELEASE_NAMESPACE}/drills/alert.json",
    ]
    with pytest.raises(InvalidContractValue, match="envelope_digest does not bind"):
        ProductReleaseEnvelopeV1.from_mapping(body)


def test_g017_a8_drill_receipt_digest_tamper_refuses() -> None:
    body = {
        "receipt_version": OPS_DRILL_RECEIPT_V1,
        "drill_kind": "recovery",
        "workspace_ref": ref("workspace", "ops"),
        "scenario_digest": digest("scenario-recovery"),
        "outcome": "PASS",
        "observed_at": "2026-07-29T00:00:00Z",
        "operator_ref": ref("operator", "sre"),
        "receipt_digest": digest("forged-drill-digest"),
    }
    with pytest.raises(InvalidContractValue, match="ops drill receipt_digest does not bind"):
        OpsDrillReceiptV1.from_mapping(body)


def test_g017_a8_drill_outcome_swap_without_redigest_refuses() -> None:
    honest = _drill("deletion")
    body = honest.to_mapping()
    body = copy.deepcopy(body)
    body["outcome"] = "FAIL"
    with pytest.raises(InvalidContractValue, match="ops drill receipt_digest does not bind"):
        OpsDrillReceiptV1.from_mapping(body)


def test_g017_a8_foundational_receipt_digest_must_be_sha256_hex() -> None:
    with pytest.raises(InvalidContractValue, match="lowercase sha256"):
        FoundationalReceiptRefV1.from_mapping({
            "receipt_kind": "encrypted-lifecycle-foundation",
            "receipt_digest": "not-a-digest",
            "authorized_at": "2026-07-28T00:00:00Z",
            "authority_ref": "security-board",
        })


def test_g017_a8_empty_artifact_paths_refuse() -> None:
    scope_obj = _scope()
    body = _envelope_body(scope_obj, _required_drills(), paths=[f"{PRODUCT_RELEASE_NAMESPACE}/x.json"])
    body["artifact_paths"] = []
    body["envelope_digest"] = canonical_ledger_digest(
        "product-release-envelope-v1",
        {k: v for k, v in body.items() if k != "envelope_digest"},
    )
    with pytest.raises(InvalidContractValue, match="artifact_paths must be a non-empty list"):
        ProductReleaseEnvelopeV1.from_mapping(body)


def test_g017_a8_empty_drill_receipt_digests_refuse() -> None:
    scope_obj = _scope()
    body = _envelope_body(scope_obj, _required_drills())
    body["drill_receipt_digests"] = []
    body["envelope_digest"] = canonical_ledger_digest(
        "product-release-envelope-v1",
        {k: v for k, v in body.items() if k != "envelope_digest"},
    )
    with pytest.raises(InvalidContractValue, match="drill_receipt_digests must be a non-empty list"):
        ProductReleaseEnvelopeV1.from_mapping(body)


def test_g017_a8_round_trip_honest_envelope_binds() -> None:
    scope_obj = _scope()
    drills = _required_drills()
    foundation = _foundation(receipt_digest=digest("bound-foundation"))
    envelope = _envelope(scope_obj, drills, foundations=[foundation])
    again = ProductReleaseEnvelopeV1.from_mapping(envelope.to_mapping())
    assert again.envelope_digest == envelope.envelope_digest
    assert again.artifact_paths == envelope.artifact_paths
    _assert_match(
        again,
        scope_obj,
        known_foundational_digests=(digest("bound-foundation"),),
    )
