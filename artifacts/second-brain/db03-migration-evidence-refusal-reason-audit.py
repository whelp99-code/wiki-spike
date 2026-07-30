#!/usr/bin/env python3.12
"""Audit the adversarial suite for vacuous passes.

`refuses()` in the committed driver treats any InvalidContractValue as a pass.
That is too generous: a case could be refused for a reason unrelated to the
property it claims to test, and still be recorded green. This re-runs the
refusal cases and asserts the refusal message actually names the property under
test.
"""
from __future__ import annotations

import sys
from hashlib import sha256
from pathlib import Path

REPO = Path("/tmp/wiki-spike-native-measurement")
sys.path.insert(0, str(REPO / "src"))

from wiki_spike.memory_core.errors import InvalidContractValue  # noqa: E402
from wiki_spike.memory_core.second_brain_ledger_contracts import (  # noqa: E402
    canonical_ledger_digest,
)
from wiki_spike.memory_core.second_brain_migration_evidence_contracts import (  # noqa: E402
    MigrationExportProfileV1,
    MigrationHistoryTreatmentV1,
    MigrationSnapshotV1,
    MigrationSourceEvidenceV1,
    MigrationUniquenessDiffV1,
)


def d(t: str) -> str:
    return sha256(t.encode()).hexdigest()


def bind(domain, body, field):
    b = dict(body)
    b[field] = canonical_ledger_digest(domain, b)
    return b


SNAP = bind("migration-snapshot-v1", {
    "snapshot_version": "second-brain-migration-snapshot-v1", "source_name": "unified-db",
    "snapshot_ref": "snapshot:u", "writers_quiesced_at": "2026-07-30T00:00:00Z",
    "snapshot_taken_at": "2026-07-30T00:05:00Z",
    "source_root_digest_before": d("r"), "source_root_digest_after": d("r"),
    "active_run_observed": False, "snapshot_package_digest": d("pkg"),
    "owner_key_ref": "key:o", "owner_attestation_digest": d("own"),
}, "snapshot_binding_digest")
SB = SNAP["snapshot_binding_digest"]

PROF = bind("migration-export-profile-v1", {
    "profile_version": "second-brain-migration-export-profile-v1", "source_name": "unified-db",
    "snapshot_binding_digest": SB, "export_method": "read-only-transaction",
    "write_capability_absent": True, "write_capability_probe_digest": d("probe"),
    "source_mutation_attempted": False, "schema_version": "unified-db-2026-07",
    "schema_digest": d("schema"), "native_identity_fields": ["source_id"],
    "identity_mapping_digest": d("identity"), "revision_semantics": "content-hash-revision",
    "revision_mapping_digest": d("revision"), "watermark_cursor_field": "source_cursor",
    "overlap_behavior": "replay-overlap", "restart_evidence_digest": d("restart"),
    "page_size_limit": "500", "retention_days": "90", "source_fixture_digest": d("fixture"),
}, "profile_digest")

DIFF = bind("migration-uniqueness-diff-v1", {
    "diff_version": "second-brain-migration-uniqueness-diff-v1", "source_name": "unified-db",
    "snapshot_binding_digest": SB, "canonical_corpus_digest": d("canon"),
    "comparison_method": "content-digest-set-difference", "candidate_item_count": "3",
    "duplicate_item_count": "1", "unique_item_count": "2",
    "unique_item_digests": [d("u1"), d("u2")],
}, "diff_digest")

TREAT = bind("migration-history-treatment-v1", {
    "treatment_version": "second-brain-migration-history-treatment-v1",
    "source_name": "unified-db", "snapshot_binding_digest": SB,
    "tombstone_representation": "absent", "history_availability": "partial-with-proof",
    "absence_is_not_deletion": True, "tombstone_sample_digests": [],
    "retained_history_sample_digests": [d("ret")],
    "unavailable_history_sample_digests": [d("un")],
}, "treatment_digest")

EV = bind("migration-source-evidence-v1", {
    "evidence_version": "second-brain-migration-source-evidence-v1",
    "source_name": "unified-db", "workspace_ref": "workspace:w",
    "snapshot_binding_digest": SB, "export_profile_digest": PROF["profile_digest"],
    "uniqueness_diff_digest": DIFF["diff_digest"],
    "history_treatment_digest": TREAT["treatment_digest"],
    "owner_attestation_digest": d("own"), "security_review_digest": d("sec"),
}, "evidence_digest")


def mutate(base, domain, field, **over):
    b = {k: v for k, v in base.items() if k != field}
    b.update(over)
    return bind(domain, b, field)


# (case id, loader, mutated body, substring the refusal message MUST contain)
CHECKS = [
    ("a-01", MigrationUniquenessDiffV1, mutate(DIFF, "migration-uniqueness-diff-v1", "diff_digest", unique_item_count="\u0665\u0660\u0660"), "canonical decimal"),
    ("a-02", MigrationUniquenessDiffV1, mutate(DIFF, "migration-uniqueness-diff-v1", "diff_digest", unique_item_count="\u00b2"), "canonical decimal"),
    ("a-03", MigrationUniquenessDiffV1, mutate(DIFF, "migration-uniqueness-diff-v1", "diff_digest", unique_item_count="1" * 4301), "canonical decimal"),
    ("a-05", MigrationUniquenessDiffV1, mutate(DIFF, "migration-uniqueness-diff-v1", "diff_digest", unique_item_count="007"), "canonical decimal"),
    ("a-06", MigrationUniquenessDiffV1, mutate(DIFF, "migration-uniqueness-diff-v1", "diff_digest", unique_item_count="99", candidate_item_count="100"), "unique_item_count"),
    ("a-07", MigrationUniquenessDiffV1, mutate(DIFF, "migration-uniqueness-diff-v1", "diff_digest", candidate_item_count="2"), "partition"),
    ("a-08", MigrationUniquenessDiffV1, mutate(DIFF, "migration-uniqueness-diff-v1", "diff_digest", comparison_method="operator-judgement"), "comparison_method"),
    ("a-13", MigrationExportProfileV1, mutate(PROF, "migration-export-profile-v1", "profile_digest", schema_version="owner@example.com"), "identifier characters"),
    ("a-14", MigrationExportProfileV1, mutate(PROF, "migration-export-profile-v1", "profile_digest", schema_version="/var/lib/db"), "identifier characters"),
    ("a-15", MigrationExportProfileV1, mutate(PROF, "migration-export-profile-v1", "profile_digest", watermark_cursor_field="cur\x00sor"), "identifier characters"),
    ("a-17", MigrationExportProfileV1, mutate(PROF, "migration-export-profile-v1", "profile_digest", schema_version="patient record 12345"), "identifier characters"),
    ("a-20", MigrationExportProfileV1, mutate(PROF, "migration-export-profile-v1", "profile_digest", schema_version="a" * 129), "identifier characters"),
    ("a-21", MigrationExportProfileV1, mutate(PROF, "migration-export-profile-v1", "profile_digest", revision_mapping_digest=d("identity")), "six distinct documents"),
    ("a-22", MigrationExportProfileV1, mutate(PROF, "migration-export-profile-v1", "profile_digest", write_capability_probe_digest=d("restart")), "six distinct documents"),
    ("a-23", MigrationExportProfileV1, mutate(PROF, "migration-export-profile-v1", "profile_digest", source_fixture_digest=d("schema")), "six distinct documents"),
    ("a-25", MigrationSnapshotV1, mutate(SNAP, "migration-snapshot-v1", "snapshot_binding_digest", active_run_observed=True), "active_run_observed"),
    ("a-26", MigrationSnapshotV1, mutate(SNAP, "migration-snapshot-v1", "snapshot_binding_digest", source_root_digest_after=d("changed")), "writers were not quiesced"),
    ("a-29", MigrationHistoryTreatmentV1, mutate(TREAT, "migration-history-treatment-v1", "treatment_digest", tombstone_sample_digests=[d("guess")]), "absence is not deletion"),
    ("a-30", MigrationHistoryTreatmentV1, mutate(TREAT, "migration-history-treatment-v1", "treatment_digest", history_availability="unavailable"), "cannot also present retained"),
    ("a-31", MigrationHistoryTreatmentV1, mutate(TREAT, "migration-history-treatment-v1", "treatment_digest", unavailable_history_sample_digests=[d("ret")]), "overlap"),
    ("a-32", MigrationHistoryTreatmentV1, mutate(TREAT, "migration-history-treatment-v1", "treatment_digest", absence_is_not_deletion=False), "absence_is_not_deletion"),
    ("a-33", MigrationSourceEvidenceV1, mutate(EV, "migration-source-evidence-v1", "evidence_digest", security_review_digest=d("own")), "separate documents"),
    ("a-34", MigrationSourceEvidenceV1, mutate(EV, "migration-source-evidence-v1", "evidence_digest", security_review_digest=PROF["profile_digest"]), "six distinct artifacts"),
    ("a-35", MigrationSourceEvidenceV1, mutate(EV, "migration-source-evidence-v1", "evidence_digest", uniqueness_diff_digest=PROF["profile_digest"]), "six distinct artifacts"),
]


def main() -> int:
    vacuous, wrong_reason = [], []
    for cid, loader, body, expect in CHECKS:
        try:
            loader.from_mapping(body)
            vacuous.append((cid, "ACCEPTED - the case does not refuse at all"))
            continue
        except InvalidContractValue as exc:
            msg = str(exc)
        except Exception as exc:  # noqa: BLE001
            wrong_reason.append((cid, f"escaped as {type(exc).__name__}: {exc}"))
            continue
        if expect.lower() not in msg.lower():
            wrong_reason.append((cid, f"expected reason {expect!r}, got {msg!r}"))
    print(f"refusal cases audited: {len(CHECKS)}")
    print(f"  not refused at all : {len(vacuous)}")
    print(f"  refused wrong reason: {len(wrong_reason)}")
    for cid, why in vacuous + wrong_reason:
        print(f"    {cid}: {why}")
    if not vacuous and not wrong_reason:
        print("\nNo vacuous passes: every refusal names the property it claims to test.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
