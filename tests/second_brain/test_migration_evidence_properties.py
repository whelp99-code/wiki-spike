"""Structural properties every migration-evidence contract must hold.

Two things the example-based tests do not establish.

First, `to_mapping` is the serialisation path an operator's artifact travels, and
only the bundle was ever round-tripped. A field dropped or mistyped on the way
out would survive.

Second, and more important: a binding digest is only worth something if it
actually covers every field. If a field were left out of the `body` dict inside
`from_mapping`, the artifact would still parse, still self-verify, and still be
tamperable in exactly that field without breaking its own digest. So every
field is varied in turn and the digest is required to move.
"""
from __future__ import annotations

from hashlib import sha256

import pytest

from wiki_spike.memory_core.errors import InvalidContractValue
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
)


def d(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def bind(domain: str, body: dict, field: str) -> dict:
    return {**body, field: canonical_ledger_digest(domain, body)}


def snapshot_body(source: str = "unified-db", **over) -> dict:
    body = {
        "snapshot_version": MIGRATION_SNAPSHOT_V1, "source_name": source,
        "snapshot_ref": "snapshot:s", "writers_quiesced_at": "2026-07-30T00:00:00Z",
        "snapshot_taken_at": "2026-07-30T00:05:00Z",
        "source_root_digest_before": d("root"), "source_root_digest_after": d("root"),
        "active_run_observed": False, "snapshot_package_digest": d("pkg"),
        "owner_key_ref": "key:owner", "owner_attestation_digest": d("owner"),
    }
    body.update(over)
    return bind("migration-snapshot-v1", body, "snapshot_binding_digest")


def profile_body(sb: str, source: str = "unified-db", **over) -> dict:
    body = {
        "profile_version": MIGRATION_EXPORT_PROFILE_V1, "source_name": source,
        "snapshot_binding_digest": sb, "export_method": "read-only-transaction",
        "write_capability_absent": True, "write_capability_probe_digest": d("probe"),
        "source_mutation_attempted": False, "schema_version": "v2026-07",
        "schema_digest": d("schema"), "native_identity_fields": ["source_id", "native_id"],
        "identity_mapping_digest": d("identity"),
        "revision_semantics": "content-hash-revision",
        "revision_mapping_digest": d("revision"), "watermark_cursor_field": "cursor",
        "overlap_behavior": "replay-overlap", "restart_evidence_digest": d("restart"),
        "page_size_limit": "500", "retention_days": "90",
        "source_fixture_digest": d("fixture"),
    }
    body.update(over)
    return bind("migration-export-profile-v1", body, "profile_digest")


def diff_body(sb: str, source: str = "unified-db", **over) -> dict:
    body = {
        "diff_version": MIGRATION_UNIQUENESS_DIFF_V1, "source_name": source,
        "snapshot_binding_digest": sb, "canonical_corpus_digest": d("corpus"),
        "comparison_method": "content-digest-set-difference",
        "candidate_item_count": "3", "duplicate_item_count": "1", "unique_item_count": "2",
        "unique_item_digests": [d("u1"), d("u2")],
    }
    body.update(over)
    return bind("migration-uniqueness-diff-v1", body, "diff_digest")


def treatment_body(sb: str, source: str = "unified-db", **over) -> dict:
    body = {
        "treatment_version": MIGRATION_HISTORY_TREATMENT_V1, "source_name": source,
        "snapshot_binding_digest": sb, "tombstone_representation": "absent",
        "history_availability": "partial-with-proof", "absence_is_not_deletion": True,
        "tombstone_sample_digests": [], "retained_history_sample_digests": [d("ret")],
        "unavailable_history_sample_digests": [d("un")],
    }
    body.update(over)
    return bind("migration-history-treatment-v1", body, "treatment_digest")


def evidence_body(sb: str, pd: str, dd: str, td: str, source: str = "unified-db", **over) -> dict:
    body = {
        "evidence_version": MIGRATION_SOURCE_EVIDENCE_V1, "source_name": source,
        "workspace_ref": "workspace:w", "snapshot_binding_digest": sb,
        "export_profile_digest": pd, "uniqueness_diff_digest": dd,
        "history_treatment_digest": td, "owner_attestation_digest": d("owner"),
        "security_review_digest": d("security"),
    }
    body.update(over)
    return bind("migration-source-evidence-v1", body, "evidence_digest")


def build(source: str = "unified-db"):
    snap = MigrationSnapshotV1.from_mapping(snapshot_body(source))
    sb = snap.snapshot_binding_digest
    profile = MigrationExportProfileV1.from_mapping(profile_body(sb, source))
    diff = MigrationUniquenessDiffV1.from_mapping(diff_body(sb, source))
    treatment = MigrationHistoryTreatmentV1.from_mapping(treatment_body(sb, source))
    evidence = MigrationSourceEvidenceV1.from_mapping(
        evidence_body(sb, profile.profile_digest, diff.diff_digest,
                      treatment.treatment_digest, source)
    )
    return snap, profile, diff, treatment, evidence


ALL = ["snapshot", "profile", "diff", "treatment", "evidence"]


@pytest.mark.parametrize("source", MIGRATION_SOURCE_NAMES)
@pytest.mark.parametrize("index,name", list(enumerate(ALL)))
def test_every_contract_round_trips_through_to_mapping(source, index, name):
    """Only the bundle was round-tripped before; a dropped field would have survived."""
    artifacts = build(source)
    artifact = artifacts[index]
    loader = type(artifact)
    assert loader.from_mapping(artifact.to_mapping()) == artifact


@pytest.mark.parametrize("index,name", list(enumerate(ALL)))
def test_to_mapping_emits_exactly_the_declared_field_set(index, name):
    artifact = build()[index]
    assert set(artifact.to_mapping()) == type(artifact).FIELDS


# Per contract: a valid alternate value for every field the digest must cover.
VARIANTS = {
    "snapshot": ("migration-snapshot-v1", "snapshot_binding_digest", snapshot_body, {
        "source_name": "me-wiki", "snapshot_ref": "snapshot:other",
        "writers_quiesced_at": "2026-07-29T00:00:00Z",
        "snapshot_taken_at": "2026-07-30T06:00:00Z",
        "source_root_digest_before": d("other-root"),
        "source_root_digest_after": d("other-root"),
        "snapshot_package_digest": d("other-pkg"), "owner_key_ref": "key:other",
        "owner_attestation_digest": d("other-owner"),
    }),
    "diff": ("migration-uniqueness-diff-v1", "diff_digest", None, {
        "source_name": "me-wiki", "canonical_corpus_digest": d("other-corpus"),
        "candidate_item_count": "4", "unique_item_digests": [d("u1"), d("u3")],
    }),
    "treatment": ("migration-history-treatment-v1", "treatment_digest", None, {
        "source_name": "me-wiki", "tombstone_representation": "explicit-tombstone-column",
        "history_availability": "complete",
        "retained_history_sample_digests": [d("other-ret")],
    }),
}


def test_every_snapshot_field_is_covered_by_its_binding_digest():
    base = snapshot_body()
    domain, field, _, variants = VARIANTS["snapshot"]
    for key, value in variants.items():
        other = snapshot_body(**{key: value}) if key != "source_name" else snapshot_body(value)
        assert other[field] != base[field], f"{key} is not covered by {field}"


def test_every_profile_field_is_covered_by_its_binding_digest():
    sb = MigrationSnapshotV1.from_mapping(snapshot_body()).snapshot_binding_digest
    base = profile_body(sb)
    for key, value in {
        "export_method": "read-only-file-copy",
        "write_capability_probe_digest": d("other-probe"),
        "schema_version": "v2026-08", "schema_digest": d("other-schema"),
        "native_identity_fields": ["source_id"],
        "identity_mapping_digest": d("other-identity"),
        "revision_semantics": "explicit-revision-column",
        "revision_mapping_digest": d("other-revision"),
        "watermark_cursor_field": "other_cursor",
        "overlap_behavior": "exactly-once-cursor",
        "restart_evidence_digest": d("other-restart"),
        "page_size_limit": "250", "retention_days": "30",
        "source_fixture_digest": d("other-fixture"),
    }.items():
        other = profile_body(sb, **{key: value})
        assert other["profile_digest"] != base["profile_digest"], (
            f"{key} is not covered by profile_digest"
        )


def test_every_bundle_field_is_covered_by_its_binding_digest():
    snap, profile, diff, treatment, _ = build()
    sb = snap.snapshot_binding_digest
    base = evidence_body(sb, profile.profile_digest, diff.diff_digest,
                         treatment.treatment_digest)
    for key, value in {
        "workspace_ref": "workspace:other",
        "snapshot_binding_digest": d("other-snapshot"),
        "export_profile_digest": d("other-profile"),
        "uniqueness_diff_digest": d("other-diff"),
        "history_treatment_digest": d("other-treatment"),
        "owner_attestation_digest": d("other-owner"),
        "security_review_digest": d("other-security"),
    }.items():
        other = evidence_body(sb, profile.profile_digest, diff.diff_digest,
                              treatment.treatment_digest, **{key: value})
        assert other["evidence_digest"] != base["evidence_digest"], (
            f"{key} is not covered by evidence_digest"
        )


def test_two_sources_never_share_an_artifact_digest():
    """Identical evidence for different sources must not collide."""
    digests = set()
    for source in MIGRATION_SOURCE_NAMES:
        snap, profile, diff, treatment, evidence = build(source)
        for artifact, field in (
            (snap, "snapshot_binding_digest"), (profile, "profile_digest"),
            (diff, "diff_digest"), (treatment, "treatment_digest"),
            (evidence, "evidence_digest"),
        ):
            digests.add(getattr(artifact, field))
    assert len(digests) == 5 * len(MIGRATION_SOURCE_NAMES)


@pytest.mark.parametrize("size", [1, 2, 50, 500])
def test_a_uniqueness_diff_scales_to_a_real_export(size):
    """The unified-db inventory counted 1,525 events; fixed 2-item examples prove little."""
    sb = MigrationSnapshotV1.from_mapping(snapshot_body()).snapshot_binding_digest
    unique = [d(f"item-{i}") for i in range(size)]
    body = diff_body(
        sb, candidate_item_count=str(size + 2), duplicate_item_count="2",
        unique_item_count=str(size), unique_item_digests=unique,
    )
    loaded = MigrationUniquenessDiffV1.from_mapping(body)
    assert loaded.unique_item_digests == tuple(unique)
    assert MigrationUniquenessDiffV1.from_mapping(loaded.to_mapping()) == loaded


def test_a_duplicated_entry_in_a_large_diff_is_still_caught():
    sb = MigrationSnapshotV1.from_mapping(snapshot_body()).snapshot_binding_digest
    unique = [d(f"item-{i}") for i in range(200)]
    unique[199] = unique[0]
    with pytest.raises(InvalidContractValue, match="unique"):
        MigrationUniquenessDiffV1.from_mapping(
            diff_body(sb, candidate_item_count="202", duplicate_item_count="2",
                      unique_item_count="200", unique_item_digests=unique)
        )
