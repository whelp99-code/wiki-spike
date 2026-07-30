#!/usr/bin/env python3
"""Build the per-source evidence bundle whose digest DB-03 must bind.

DB-03 resolves one migration source at a time, and a source-specific GO requires
a read-only export fixture, a pinned schema with identity/revision mapping,
watermark evidence covering overlap and restart, deletion/history samples that
distinguish tombstones from retained history from unavailable history, and
signed evidence digests. `MigrationSourceEvidenceV1` is that bundle, and its
`evidence_digest` is the value DB-03's `evidence_digest` takes.

The unified-db inventory stopped at STOP_PENDING_IMMUTABLE_SNAPSHOT_AND_DIFF and
named five missing items. Three of them are human work this tool refuses to
simulate: the immutable snapshot taken after writers are quiesced, the
before/after zero-write proof, and the owner key binding and signature. The tool
takes their digests as input and fails closed when they are absent or
inconsistent. The other two -- the body-free per-source uniqueness diff and the
per-source deletion/history treatment -- are computations over that snapshot,
and this tool performs them from real input.

Producing a bundle is not approval. It makes DB-03 signable; it does not sign it,
and it does not register, import, or route any source.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from second_brain_evidence_common import (  # noqa: E402
    EvidenceToolError,
    dispatch_version,
    emit,
    item_digests,
    load_object,
    reject_duplicates,
    run,
    write_atomic,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (  # noqa: E402
    canonical_ledger_digest,
    canonical_ledger_instant,
)
from wiki_spike.memory_core.second_brain_migration_evidence_contracts import (  # noqa: E402
    HISTORY_AVAILABILITIES,
    MIGRATION_EXPORT_PROFILE_V1,
    MIGRATION_HISTORY_TREATMENT_V1,
    MIGRATION_SNAPSHOT_V1,
    MIGRATION_SOURCE_EVIDENCE_V1,
    MIGRATION_SOURCE_NAMES,
    MIGRATION_UNIQUENESS_DIFF_V1,
    OVERLAP_BEHAVIORS,
    READ_ONLY_EXPORT_METHODS,
    REVISION_SEMANTICS,
    TOMBSTONE_REPRESENTATIONS,
    MigrationExportProfileV1,
    MigrationHistoryTreatmentV1,
    MigrationSnapshotV1,
    MigrationSourceEvidenceV1,
    MigrationUniquenessDiffV1,
    assert_migration_evidence_bundle_coherent,
)

CANONICAL_CORPUS_DOMAIN = "migration-canonical-corpus-v1"


def read_digest_list(path: Path, label: str) -> list[str]:
    """Accept either a bare JSON array or the `{"item_digests": [...]}` this tool emits."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, ValueError) as exc:
        raise EvidenceToolError(f"cannot read {path}: {exc}") from exc
    if isinstance(raw, dict):
        raw = raw.get("item_digests")
    if not isinstance(raw, list) or not raw:
        raise EvidenceToolError(
            f"{label} must be a non-empty JSON array of digests, "
            'or an object carrying "item_digests"'
        )
    for item in raw:
        if not isinstance(item, str) or len(item) != 64 or any(
            ch not in "0123456789abcdef" for ch in item
        ):
            raise EvidenceToolError(f"{label} holds a value that is not a sha256 digest")
    if len(set(raw)) != len(raw):
        raise EvidenceToolError(
            f"{label} holds duplicate digests; deduplicate before diffing so the counts "
            "mean what they say"
        )
    return list(raw)


def canonical_corpus_digest(digests: list[str]) -> str:
    """Bind the exact canonical corpus a diff was taken against."""
    return canonical_ledger_digest(CANONICAL_CORPUS_DOMAIN, {"item_digests": sorted(digests)})


def cmd_digests(args: argparse.Namespace) -> int:
    digests = item_digests(Path(args.dir))
    payload = {"count": len(digests), "item_digests": digests}
    if args.out:
        write_atomic(Path(args.out), json.dumps(payload, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"written_to": args.out, "count": len(digests)}, indent=2))
    else:
        print(json.dumps(payload, indent=2))
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    body = {
        "snapshot_version": MIGRATION_SNAPSHOT_V1,
        "source_name": args.source_name,
        "snapshot_ref": args.snapshot_ref,
        # Canonicalise here so the body and its digest derive from one value; a
        # legal-but-non-canonical spelling must be accepted, not reported as a
        # digest mismatch by the contract further down.
        "writers_quiesced_at": canonical_ledger_instant(
            args.writers_quiesced_at, "writers_quiesced_at"
        ),
        "snapshot_taken_at": canonical_ledger_instant(
            args.snapshot_taken_at, "snapshot_taken_at"
        ),
        "source_root_digest_before": args.source_root_digest_before,
        "source_root_digest_after": args.source_root_digest_after,
        "active_run_observed": False,
        "snapshot_package_digest": args.snapshot_package_digest,
        "owner_key_ref": args.owner_key_ref,
        "owner_attestation_digest": args.owner_attestation_digest,
    }
    probe = dict(body)
    probe["snapshot_binding_digest"] = canonical_ledger_digest("migration-snapshot-v1", body)
    MigrationSnapshotV1.from_mapping(probe)
    return emit(body, "snapshot_binding_digest", "migration-snapshot-v1", args.out)


def cmd_export_profile(args: argparse.Namespace) -> int:
    snapshot = MigrationSnapshotV1.from_mapping(load_object(Path(args.snapshot)))
    body = {
        "profile_version": MIGRATION_EXPORT_PROFILE_V1,
        "source_name": snapshot.source_name,
        "snapshot_binding_digest": snapshot.snapshot_binding_digest,
        "export_method": args.export_method,
        "write_capability_absent": True,
        "write_capability_probe_digest": args.write_capability_probe_digest,
        "source_mutation_attempted": False,
        "schema_version": args.schema_version,
        "schema_digest": args.schema_digest,
        "native_identity_fields": list(args.native_identity_field),
        "identity_mapping_digest": args.identity_mapping_digest,
        "revision_semantics": args.revision_semantics,
        "revision_mapping_digest": args.revision_mapping_digest,
        "watermark_cursor_field": args.watermark_cursor_field,
        "overlap_behavior": args.overlap_behavior,
        "restart_evidence_digest": args.restart_evidence_digest,
        "page_size_limit": args.page_size_limit,
        "retention_days": args.retention_days,
        "source_fixture_digest": args.source_fixture_digest,
    }
    probe = dict(body)
    probe["profile_digest"] = canonical_ledger_digest("migration-export-profile-v1", body)
    MigrationExportProfileV1.from_mapping(probe)
    return emit(body, "profile_digest", "migration-export-profile-v1", args.out)


def cmd_uniqueness_diff(args: argparse.Namespace) -> int:
    snapshot = MigrationSnapshotV1.from_mapping(load_object(Path(args.snapshot)))
    candidates = read_digest_list(Path(args.candidates), "--candidates")
    canonical = read_digest_list(Path(args.canonical), "--canonical")
    canonical_set = set(canonical)
    unique = [digest for digest in candidates if digest not in canonical_set]
    body = {
        "diff_version": MIGRATION_UNIQUENESS_DIFF_V1,
        "source_name": snapshot.source_name,
        "snapshot_binding_digest": snapshot.snapshot_binding_digest,
        "canonical_corpus_digest": canonical_corpus_digest(canonical),
        "comparison_method": "content-digest-set-difference",
        "candidate_item_count": str(len(candidates)),
        "duplicate_item_count": str(len(candidates) - len(unique)),
        "unique_item_count": str(len(unique)),
        "unique_item_digests": unique,
    }
    probe = dict(body)
    probe["diff_digest"] = canonical_ledger_digest("migration-uniqueness-diff-v1", body)
    MigrationUniquenessDiffV1.from_mapping(probe)
    result = emit(body, "diff_digest", "migration-uniqueness-diff-v1", args.out)
    if not unique:
        print(
            "Every candidate item already exists in the supported canonical sources. "
            "This source adds nothing; it is a NO_GO candidate, not a GO one.",
            file=sys.stderr,
        )
    return result


def cmd_history_treatment(args: argparse.Namespace) -> int:
    snapshot = MigrationSnapshotV1.from_mapping(load_object(Path(args.snapshot)))
    body = {
        "treatment_version": MIGRATION_HISTORY_TREATMENT_V1,
        "source_name": snapshot.source_name,
        "snapshot_binding_digest": snapshot.snapshot_binding_digest,
        "tombstone_representation": args.tombstone_representation,
        "history_availability": args.history_availability,
        "absence_is_not_deletion": True,
        "tombstone_sample_digests": list(args.tombstone_sample),
        "retained_history_sample_digests": list(args.retained_sample),
        "unavailable_history_sample_digests": list(args.unavailable_sample),
    }
    probe = dict(body)
    probe["treatment_digest"] = canonical_ledger_digest("migration-history-treatment-v1", body)
    MigrationHistoryTreatmentV1.from_mapping(probe)
    return emit(body, "treatment_digest", "migration-history-treatment-v1", args.out)


def cmd_evidence(args: argparse.Namespace) -> int:
    snapshot = MigrationSnapshotV1.from_mapping(load_object(Path(args.snapshot)))
    profile = MigrationExportProfileV1.from_mapping(load_object(Path(args.export_profile)))
    diff = MigrationUniquenessDiffV1.from_mapping(load_object(Path(args.uniqueness_diff)))
    treatment = MigrationHistoryTreatmentV1.from_mapping(load_object(Path(args.history_treatment)))
    body = {
        "evidence_version": MIGRATION_SOURCE_EVIDENCE_V1,
        "source_name": snapshot.source_name,
        "workspace_ref": args.workspace_ref,
        "snapshot_binding_digest": snapshot.snapshot_binding_digest,
        "export_profile_digest": profile.profile_digest,
        "uniqueness_diff_digest": diff.diff_digest,
        "history_treatment_digest": treatment.treatment_digest,
        "owner_attestation_digest": snapshot.owner_attestation_digest,
        "security_review_digest": args.security_review_digest,
    }
    probe = dict(body)
    probe["evidence_digest"] = canonical_ledger_digest("migration-source-evidence-v1", body)
    evidence = MigrationSourceEvidenceV1.from_mapping(probe)
    assert_migration_evidence_bundle_coherent(evidence, snapshot, profile, diff, treatment)
    result = emit(body, "evidence_digest", "migration-source-evidence-v1", args.out)
    print(
        f"This evidence_digest is the value DB-03's evidence_digest takes for "
        f"{snapshot.source_name!r}. It makes the record signable; it is not a GO.",
        file=sys.stderr,
    )
    return result


_ARTIFACTS = {
    MIGRATION_SNAPSHOT_V1: (MigrationSnapshotV1, "snapshot_binding_digest"),
    MIGRATION_EXPORT_PROFILE_V1: (MigrationExportProfileV1, "profile_digest"),
    MIGRATION_UNIQUENESS_DIFF_V1: (MigrationUniquenessDiffV1, "diff_digest"),
    MIGRATION_HISTORY_TREATMENT_V1: (MigrationHistoryTreatmentV1, "treatment_digest"),
    MIGRATION_SOURCE_EVIDENCE_V1: (MigrationSourceEvidenceV1, "evidence_digest"),
}
_VERSION_FIELDS = (
    "snapshot_version", "profile_version", "diff_version", "treatment_version",
    "evidence_version",
)


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.file)
    data = load_object(path)
    version, loader, digest_field = dispatch_version(path, data, _VERSION_FIELDS, _ARTIFACTS)
    loaded = loader.from_mapping(data)
    print(
        json.dumps(
            {
                "file": str(path),
                "version": version,
                "digest_field": digest_field,
                "digest": getattr(loaded, digest_field),
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    digests = sub.add_parser(
        "digests", help="hash an exported snapshot directory into body-free item digests"
    )
    digests.add_argument("--dir", required=True)
    digests.add_argument("--out")
    digests.set_defaults(func=cmd_digests)

    snapshot = sub.add_parser(
        "snapshot", help="bind an owner-produced immutable snapshot and its zero-write proof"
    )
    snapshot.add_argument("--source-name", required=True, choices=list(MIGRATION_SOURCE_NAMES))
    snapshot.add_argument("--snapshot-ref", required=True)
    snapshot.add_argument("--writers-quiesced-at", required=True)
    snapshot.add_argument("--snapshot-taken-at", required=True)
    snapshot.add_argument("--source-root-digest-before", required=True)
    snapshot.add_argument("--source-root-digest-after", required=True)
    snapshot.add_argument("--snapshot-package-digest", required=True)
    snapshot.add_argument("--owner-key-ref", required=True)
    snapshot.add_argument("--owner-attestation-digest", required=True)
    snapshot.add_argument("--out")
    snapshot.set_defaults(func=cmd_snapshot)

    profile = sub.add_parser(
        "export-profile", help="pin the read-only export, schema, identity/revision and watermark"
    )
    profile.add_argument("--snapshot", required=True)
    profile.add_argument("--export-method", required=True, choices=list(READ_ONLY_EXPORT_METHODS))
    profile.add_argument(
        "--write-capability-probe-digest", required=True,
        help="digest of the evidence that a write through the export credential was refused",
    )
    profile.add_argument("--schema-version", required=True)
    profile.add_argument("--schema-digest", required=True)
    profile.add_argument(
        "--native-identity-field", required=True, action="append",
        help="repeat once per field that forms the native identity",
    )
    profile.add_argument("--identity-mapping-digest", required=True)
    profile.add_argument("--revision-semantics", required=True, choices=list(REVISION_SEMANTICS))
    profile.add_argument("--revision-mapping-digest", required=True)
    profile.add_argument("--watermark-cursor-field", required=True)
    profile.add_argument("--overlap-behavior", required=True, choices=list(OVERLAP_BEHAVIORS))
    profile.add_argument("--restart-evidence-digest", required=True)
    profile.add_argument("--page-size-limit", required=True)
    profile.add_argument("--retention-days", required=True)
    profile.add_argument("--source-fixture-digest", required=True)
    profile.add_argument("--out")
    profile.set_defaults(func=cmd_export_profile)

    diff = sub.add_parser(
        "uniqueness-diff", help="diff candidate item digests against the canonical corpus"
    )
    diff.add_argument("--snapshot", required=True)
    diff.add_argument("--candidates", required=True)
    diff.add_argument("--canonical", required=True)
    diff.add_argument("--out")
    diff.set_defaults(func=cmd_uniqueness_diff)

    treatment = sub.add_parser(
        "history-treatment", help="record deletion/history treatment without inferring it"
    )
    treatment.add_argument("--snapshot", required=True)
    treatment.add_argument(
        "--tombstone-representation", required=True, choices=list(TOMBSTONE_REPRESENTATIONS)
    )
    treatment.add_argument(
        "--history-availability", required=True, choices=list(HISTORY_AVAILABILITIES)
    )
    treatment.add_argument("--tombstone-sample", action="append", default=[])
    treatment.add_argument("--retained-sample", action="append", default=[])
    treatment.add_argument("--unavailable-sample", action="append", default=[])
    treatment.add_argument("--out")
    treatment.set_defaults(func=cmd_history_treatment)

    evidence = sub.add_parser(
        "evidence", help="bind the four components into the digest DB-03 must reference"
    )
    evidence.add_argument("--snapshot", required=True)
    evidence.add_argument("--export-profile", required=True)
    evidence.add_argument("--uniqueness-diff", required=True)
    evidence.add_argument("--history-treatment", required=True)
    evidence.add_argument("--workspace-ref", required=True)
    evidence.add_argument("--security-review-digest", required=True)
    evidence.add_argument("--out")
    evidence.set_defaults(func=cmd_evidence)

    verify = sub.add_parser("verify", help="revalidate any artifact this tool produced")
    verify.add_argument("--file", required=True)
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args.func, args)


if __name__ == "__main__":
    raise SystemExit(main())
