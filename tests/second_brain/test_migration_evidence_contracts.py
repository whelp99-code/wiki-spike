"""Contract tests for the DB-03 migration-source evidence family.

DB-03 grants a `GO` one source at a time, and each one demands a read-only
export, a pinned schema with identity/revision mapping, watermark evidence, and
deletion/history samples that distinguish three states without inferring any of
them. These tests pin the refusals that make the bundle mean something: a
snapshot taken while writers ran is not a zero-write proof, an absent tombstone
representation cannot yield tombstone samples, and four components assembled
across different sources or snapshots prove nothing about either.
"""
from __future__ import annotations

from hashlib import sha256

import pytest

from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.second_brain_migration_evidence_contracts import (
    MIGRATION_EXPORT_PROFILE_V1,
    MIGRATION_HISTORY_TREATMENT_V1,
    MIGRATION_SNAPSHOT_V1,
    MIGRATION_SOURCE_EVIDENCE_V1,
    MIGRATION_SOURCE_NAMES,
    MIGRATION_UNIQUENESS_DIFF_V1,
    MigrationExportProfileV1,
    MigrationHistoryTreatmentV1,
    MigrationSnapshotV1,
    MigrationSourceEvidenceV1,
    MigrationUniquenessDiffV1,
    assert_migration_evidence_bundle_coherent,
    assert_migration_source_registrable,
)

WORKSPACE = "workspace:second-brain-final"


def d(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def bind(domain: str, body: dict, field: str) -> dict:
    return {**body, field: canonical_ledger_digest(domain, body)}


def snapshot_body(**overrides) -> dict:
    body = {
        "snapshot_version": MIGRATION_SNAPSHOT_V1,
        "source_name": "unified-db",
        "snapshot_ref": "snapshot:unified-db-2026-07-30",
        "writers_quiesced_at": "2026-07-30T00:00:00Z",
        "snapshot_taken_at": "2026-07-30T00:05:00Z",
        "source_root_digest_before": d("root"),
        "source_root_digest_after": d("root"),
        "active_run_observed": False,
        "snapshot_package_digest": d("package"),
        "owner_key_ref": "key:migration-owner-2026",
        "owner_attestation_digest": d("owner-attestation"),
    }
    body.update(overrides)
    return bind("migration-snapshot-v1", body, "snapshot_binding_digest")


def snapshot(**overrides) -> MigrationSnapshotV1:
    return MigrationSnapshotV1.from_mapping(snapshot_body(**overrides))


def profile_body(bound: MigrationSnapshotV1, **overrides) -> dict:
    body = {
        "profile_version": MIGRATION_EXPORT_PROFILE_V1,
        "source_name": bound.source_name,
        "snapshot_binding_digest": bound.snapshot_binding_digest,
        "export_method": "read-only-transaction",
        "write_capability_absent": True,
        "write_capability_probe_digest": d("write-capability-probe"),
        "source_mutation_attempted": False,
        "schema_version": "unified-db-2026-07",
        "schema_digest": d("schema"),
        "native_identity_fields": ["source_id", "native_id", "content_hash"],
        "identity_mapping_digest": d("identity-mapping"),
        "revision_semantics": "content-hash-revision",
        "revision_mapping_digest": d("revision-mapping"),
        "watermark_cursor_field": "source_cursor",
        "overlap_behavior": "replay-overlap",
        "restart_evidence_digest": d("restart"),
        "page_size_limit": "500",
        "retention_days": "90",
        "source_fixture_digest": d("fixture"),
    }
    body.update(overrides)
    return bind("migration-export-profile-v1", body, "profile_digest")


def diff_body(bound: MigrationSnapshotV1, **overrides) -> dict:
    unique = [d("unique-1"), d("unique-2")]
    body = {
        "diff_version": MIGRATION_UNIQUENESS_DIFF_V1,
        "source_name": bound.source_name,
        "snapshot_binding_digest": bound.snapshot_binding_digest,
        "canonical_corpus_digest": d("canonical-corpus"),
        "comparison_method": "content-digest-set-difference",
        "candidate_item_count": "3",
        "duplicate_item_count": "1",
        "unique_item_count": "2",
        "unique_item_digests": unique,
    }
    body.update(overrides)
    return bind("migration-uniqueness-diff-v1", body, "diff_digest")


def treatment_body(bound: MigrationSnapshotV1, **overrides) -> dict:
    body = {
        "treatment_version": MIGRATION_HISTORY_TREATMENT_V1,
        "source_name": bound.source_name,
        "snapshot_binding_digest": bound.snapshot_binding_digest,
        "tombstone_representation": "absent",
        "history_availability": "partial-with-proof",
        "absence_is_not_deletion": True,
        "tombstone_sample_digests": [],
        "retained_history_sample_digests": [d("retained-1")],
        "unavailable_history_sample_digests": [d("unavailable-1")],
    }
    body.update(overrides)
    return bind("migration-history-treatment-v1", body, "treatment_digest")


def evidence_body(
    bound: MigrationSnapshotV1,
    profile: MigrationExportProfileV1,
    diff: MigrationUniquenessDiffV1,
    treatment: MigrationHistoryTreatmentV1,
    **overrides,
) -> dict:
    body = {
        "evidence_version": MIGRATION_SOURCE_EVIDENCE_V1,
        "source_name": bound.source_name,
        "workspace_ref": WORKSPACE,
        "snapshot_binding_digest": bound.snapshot_binding_digest,
        "export_profile_digest": profile.profile_digest,
        "uniqueness_diff_digest": diff.diff_digest,
        "history_treatment_digest": treatment.treatment_digest,
        "owner_attestation_digest": bound.owner_attestation_digest,
        "security_review_digest": d("security-review"),
    }
    body.update(overrides)
    return bind("migration-source-evidence-v1", body, "evidence_digest")


@pytest.fixture
def bundle():
    bound = snapshot()
    profile = MigrationExportProfileV1.from_mapping(profile_body(bound))
    diff = MigrationUniquenessDiffV1.from_mapping(diff_body(bound))
    treatment = MigrationHistoryTreatmentV1.from_mapping(treatment_body(bound))
    evidence = MigrationSourceEvidenceV1.from_mapping(
        evidence_body(bound, profile, diff, treatment)
    )
    return evidence, bound, profile, diff, treatment


def test_a_coherent_bundle_round_trips_and_binds_its_components(bundle):
    evidence, bound, profile, diff, treatment = bundle
    assert_migration_evidence_bundle_coherent(evidence, bound, profile, diff, treatment)
    assert MigrationSourceEvidenceV1.from_mapping(evidence.to_mapping()) == evidence
    assert evidence.evidence_digest == canonical_ledger_digest(
        "migration-source-evidence-v1",
        {k: v for k, v in evidence.to_mapping().items() if k != "evidence_digest"},
    )


@pytest.mark.parametrize("name", MIGRATION_SOURCE_NAMES)
def test_each_db03_scope_name_is_accepted_and_others_are_not(name):
    assert snapshot(source_name=name).source_name == name
    with pytest.raises(InvalidContractValue):
        snapshot(source_name="hermes")


def test_a_changed_source_root_is_not_a_zero_write_proof():
    """Unequal before/after roots mean writers were never quiesced."""
    with pytest.raises(InvalidContractValue, match="writers were not quiesced"):
        snapshot(source_root_digest_after=d("root-after-a-write"))


def test_a_snapshot_derived_from_a_live_instance_is_refused():
    with pytest.raises(InvalidContractValue, match="active_run_observed"):
        snapshot(active_run_observed=True)


def test_a_snapshot_taken_before_writers_were_quiesced_is_refused():
    with pytest.raises(InvalidContractValue, match="precedes"):
        snapshot(snapshot_taken_at="2026-07-29T23:59:59Z")


def test_fractional_seconds_do_not_invert_the_quiesce_ordering():
    """"00:00:00.5Z" sorts before "00:00:00Z" as text but is the later instant."""
    assert snapshot(
        writers_quiesced_at="2026-07-30T00:00:00Z",
        snapshot_taken_at="2026-07-30T00:00:00.5Z",
    ).snapshot_taken_at.startswith("2026-07-30T00:00:00.5")


@pytest.mark.parametrize(
    "override",
    [
        {"export_method": "read-write-transaction"},
        {"write_capability_absent": False},
        {"source_mutation_attempted": True},
        {"revision_semantics": "none"},
        {"overlap_behavior": "unknown"},
    ],
)
def test_an_export_that_could_mutate_or_cannot_reconcile_is_refused(override):
    bound = snapshot()
    with pytest.raises(InvalidContractValue):
        MigrationExportProfileV1.from_mapping(profile_body(bound, **override))


@pytest.mark.parametrize(
    "reused,collides_with",
    [
        ("revision_mapping_digest", "identity-mapping"),
        ("write_capability_probe_digest", "restart"),
        ("source_fixture_digest", "schema"),
    ],
)
def test_each_piece_of_export_evidence_must_be_its_own_document(reused, collides_with):
    """One document cannot prove two independent claims about the source."""
    bound = snapshot()
    with pytest.raises(InvalidContractValue, match="six distinct documents"):
        MigrationExportProfileV1.from_mapping(
            profile_body(bound, **{reused: d(collides_with)})
        )


def test_the_write_capability_claim_carries_a_probe_digest():
    """DB-03's 'cannot mutate the source' may not be a bare boolean."""
    bound = snapshot()
    body = profile_body(bound)
    assert body["write_capability_probe_digest"] == d("write-capability-probe")
    reduced = {k: v for k, v in body.items() if k != "write_capability_probe_digest"}
    with pytest.raises(InvalidContractValue, match="write_capability_probe_digest"):
        MigrationExportProfileV1.from_mapping(reduced)


@pytest.mark.parametrize(
    "value",
    ["0", "007", "1.0", "-1", 500, True, "\u0665\u0660\u0660", "\u00b2", "1" * 21],
)
def test_page_size_limit_must_be_a_positive_canonical_decimal_string(value):
    """Non-ASCII digits would give one value two digest-bound encodings."""
    bound = snapshot()
    with pytest.raises(InvalidContractValue):
        MigrationExportProfileV1.from_mapping(profile_body(bound, page_size_limit=value))


@pytest.mark.parametrize("value", ["\u0665\u0660\u0660", "\u00b2", "9" * 21, "0" * 25])
def test_a_count_int_can_never_parse_is_refused_before_int_sees_it(value):
    """`²` is isdigit-true but int() raises; the contract must fail closed by type."""
    bound = snapshot()
    with pytest.raises(InvalidContractValue, match="canonical decimal string"):
        MigrationUniquenessDiffV1.from_mapping(diff_body(bound, unique_item_count=value))


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "a" * 129),
        ("schema_version", "owner@example.com"),
        ("schema_version", "/var/lib/unified-db/rows"),
        ("watermark_cursor_field", "cursor with a record excerpt"),
        ("watermark_cursor_field", "\x00"),
    ],
)
def test_metadata_fields_reject_anything_that_is_not_an_identifier(field, value):
    bound = snapshot()
    with pytest.raises(InvalidContractValue, match="identifier characters"):
        MigrationExportProfileV1.from_mapping(profile_body(bound, **{field: value}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("snapshot_ref", "snapshot:/var/lib/unified-db"),
        ("snapshot_ref", "snapshot:" + "a" * 129),
        ("snapshot_ref", "snapshot:with\x00nul"),
        ("owner_key_ref", "key:owner@example.com"),
        ("snapshot_ref", "unified-db-2026-07-30"),
    ],
)
def test_refs_reject_paths_excerpts_and_missing_prefixes(field, value):
    with pytest.raises(InvalidContractValue):
        snapshot(**{field: value})


def test_uniqueness_counts_must_partition_the_candidate_set():
    bound = snapshot()
    with pytest.raises(InvalidContractValue, match="partition"):
        MigrationUniquenessDiffV1.from_mapping(diff_body(bound, candidate_item_count="4"))


def test_the_unique_count_must_match_the_enumerated_digests():
    bound = snapshot()
    with pytest.raises(InvalidContractValue, match="unique_item_count"):
        MigrationUniquenessDiffV1.from_mapping(
            diff_body(bound, unique_item_digests=[d("unique-1")])
        )


def test_a_source_that_adds_nothing_is_representable_not_forbidden():
    """Zero unique items is a real, recordable finding: it argues for NO_GO."""
    bound = snapshot()
    diff = MigrationUniquenessDiffV1.from_mapping(
        diff_body(
            bound,
            candidate_item_count="3",
            duplicate_item_count="3",
            unique_item_count="0",
            unique_item_digests=[],
        )
    )
    assert diff.unique_item_digests == ()


def test_a_source_without_tombstones_cannot_present_tombstone_samples():
    bound = snapshot()
    with pytest.raises(InvalidContractValue, match="absence is not deletion"):
        MigrationHistoryTreatmentV1.from_mapping(
            treatment_body(bound, tombstone_sample_digests=[d("inferred-tombstone")])
        )


def test_a_declared_tombstone_representation_requires_a_sample():
    bound = snapshot()
    with pytest.raises(InvalidContractValue, match="requires at least one tombstone sample"):
        MigrationHistoryTreatmentV1.from_mapping(
            treatment_body(bound, tombstone_representation="explicit-tombstone-column")
        )


@pytest.mark.parametrize(
    "override,match",
    [
        (
            {"history_availability": "unavailable"},
            "cannot also present retained history samples",
        ),
        (
            {
                "history_availability": "complete",
                "unavailable_history_sample_digests": [d("unavailable-1")],
            },
            "cannot also present unavailable samples",
        ),
        (
            {
                "history_availability": "partial-with-proof",
                "unavailable_history_sample_digests": [],
            },
            "must present both",
        ),
    ],
)
def test_history_availability_must_agree_with_the_samples(override, match):
    bound = snapshot()
    with pytest.raises(InvalidContractValue, match=match):
        MigrationHistoryTreatmentV1.from_mapping(treatment_body(bound, **override))


def test_one_record_cannot_be_in_two_history_states():
    bound = snapshot()
    shared = d("retained-1")
    with pytest.raises(InvalidContractValue, match="overlap"):
        MigrationHistoryTreatmentV1.from_mapping(
            treatment_body(bound, unavailable_history_sample_digests=[shared])
        )


def test_absence_is_not_deletion_cannot_be_switched_off():
    bound = snapshot()
    with pytest.raises(InvalidContractValue, match="absence_is_not_deletion"):
        MigrationHistoryTreatmentV1.from_mapping(
            treatment_body(bound, absence_is_not_deletion=False)
        )


def test_one_component_digest_cannot_fill_two_slots(bundle):
    _, bound, profile, diff, treatment = bundle
    with pytest.raises(InvalidContractValue, match="six distinct artifacts"):
        MigrationSourceEvidenceV1.from_mapping(
            evidence_body(
                bound, profile, diff, treatment, uniqueness_diff_digest=profile.profile_digest
            )
        )


@pytest.mark.parametrize(
    "component", ["export_profile_digest", "uniqueness_diff_digest", "history_treatment_digest"]
)
def test_a_component_cannot_double_as_the_security_review(bundle, component):
    """A 'Security review' that is really the export profile is not a review."""
    _, bound, profile, diff, treatment = bundle
    body = evidence_body(bound, profile, diff, treatment)
    with pytest.raises(InvalidContractValue, match="six distinct artifacts"):
        MigrationSourceEvidenceV1.from_mapping(
            evidence_body(
                bound, profile, diff, treatment, security_review_digest=body[component]
            )
        )


def test_owner_attestation_and_security_review_must_be_separate_documents(bundle):
    _, bound, profile, diff, treatment = bundle
    with pytest.raises(InvalidContractValue, match="separate documents"):
        MigrationSourceEvidenceV1.from_mapping(
            evidence_body(
                bound, profile, diff, treatment,
                security_review_digest=bound.owner_attestation_digest,
            )
        )


def test_components_taken_from_another_source_are_refused(bundle):
    evidence, bound, _, diff, treatment = bundle
    other = snapshot(source_name="me-wiki")
    foreign = MigrationExportProfileV1.from_mapping(profile_body(other))
    with pytest.raises(InvalidContractValue, match="same source name"):
        assert_migration_evidence_bundle_coherent(evidence, bound, foreign, diff, treatment)


def test_components_taken_from_another_snapshot_are_refused(bundle):
    evidence, bound, profile, diff, _ = bundle
    later = snapshot(snapshot_ref="snapshot:unified-db-2026-08-01")
    stale = MigrationHistoryTreatmentV1.from_mapping(treatment_body(later))
    with pytest.raises(InvalidContractValue, match="history treatment binds a different snapshot"):
        assert_migration_evidence_bundle_coherent(evidence, bound, profile, diff, stale)


def test_evidence_must_carry_the_snapshot_owner_attestation(bundle):
    _, bound, profile, diff, treatment = bundle
    spliced = MigrationSourceEvidenceV1.from_mapping(
        evidence_body(
            bound, profile, diff, treatment, owner_attestation_digest=d("someone-else")
        )
    )
    with pytest.raises(InvalidContractValue, match="owner_attestation_digest"):
        assert_migration_evidence_bundle_coherent(spliced, bound, profile, diff, treatment)


def scope(**overrides) -> ResolvedScopeV1:
    body = {
        "scope_version": "second-brain-resolved-scope-v1",
        "enabled_source_profiles": ["Codex"],
        "disabled_source_profiles": {},
        "enabled_migration_sources": ["unified-db"],
        "disabled_migration_sources": {},
        "feature_flags": [],
        "egress_destinations": [],
        "enabled_external_model_routes": [],
        "disabled_external_model_routes": {},
        "disabled_export_destinations": {},
        "capability_manifest_digest": d("capability-manifest"),
        "source_manifest_digest": d("source-manifest"),
        "mandatory_release_constraints": ["local-default"],
    }
    body.update(overrides)
    return ResolvedScopeV1.from_mapping(body)


def test_a_go_source_is_registrable(bundle):
    evidence = bundle[0]
    assert_migration_source_registrable(evidence, scope())


def test_a_no_go_or_unresolved_source_is_not_registrable(bundle):
    evidence = bundle[0]
    with pytest.raises(InvalidContractValue, match="NO_GO"):
        assert_migration_source_registrable(
            evidence,
            scope(enabled_migration_sources=[], disabled_migration_sources={"unified-db": "DB-03"}),
        )
    with pytest.raises(InvalidContractValue, match="not enabled by a signed DB-03 GO"):
        assert_migration_source_registrable(evidence, scope(enabled_migration_sources=[]))


@pytest.mark.parametrize(
    "override,label",
    [
        ({"enabled_source_profiles": ["unified-db"]}, "live capture source profile"),
        ({"enabled_external_model_routes": ["unified-db"]}, "external model route"),
        ({"egress_destinations": ["unified-db"]}, "egress destination"),
    ],
)
def test_a_migration_source_may_never_double_as_a_serving_surface(bundle, override, label):
    evidence = bundle[0]
    with pytest.raises(InvalidContractValue, match=label):
        assert_migration_source_registrable(evidence, scope(**override))


@pytest.mark.parametrize(
    "loader,body_fn",
    [
        (MigrationSnapshotV1, lambda: snapshot_body()),
        (MigrationExportProfileV1, lambda: profile_body(snapshot())),
        (MigrationUniquenessDiffV1, lambda: diff_body(snapshot())),
        (MigrationHistoryTreatmentV1, lambda: treatment_body(snapshot())),
    ],
)
def test_every_artifact_refuses_unknown_and_missing_fields(loader, body_fn):
    body = body_fn()
    with pytest.raises(InvalidContractValue):
        loader.from_mapping({**body, "backdoor": 1})
    reduced = dict(body)
    reduced.pop("source_name")
    with pytest.raises(InvalidContractValue):
        loader.from_mapping(reduced)


@pytest.mark.parametrize(
    "loader,body_fn,field",
    [
        (MigrationSnapshotV1, lambda: snapshot_body(), "snapshot_binding_digest"),
        (MigrationExportProfileV1, lambda: profile_body(snapshot()), "profile_digest"),
        (MigrationUniquenessDiffV1, lambda: diff_body(snapshot()), "diff_digest"),
        (MigrationHistoryTreatmentV1, lambda: treatment_body(snapshot()), "treatment_digest"),
    ],
)
def test_every_binding_digest_actually_binds_its_body(loader, body_fn, field):
    body = body_fn()
    loader.from_mapping(body)
    with pytest.raises(InvalidContractValue, match="bind"):
        loader.from_mapping({**body, "source_name": "me-wiki"})
    with pytest.raises(InvalidContractValue, match="bind"):
        loader.from_mapping({**body, field: d("forged")})
