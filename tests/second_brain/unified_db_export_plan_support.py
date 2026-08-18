"""Profile, plan, fixture, and reader builders for export tests."""
from __future__ import annotations

from tests.second_brain.unified_db_export_row_support import (
    CATALOG_COMMIT,
    DATA_ROOT_COMMIT,
    DB_COMMIT,
    SOURCE_COMMIT,
    standard_rows,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportRowV1
from wiki_spike.memory_core.unified_db_snapshot_export_cursors import (
    SnapshotCursorMapV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_fixture import (
    UnifiedDbExportFixtureV1,
    row_set_digest,
)
from wiki_spike.memory_core.unified_db_snapshot_export_profile import (
    UnifiedDbExportPlanV1,
    UnifiedDbExportProfileV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_proof import (
    UnifiedDbReadSafetyProofV1,
)


def profile_body(
    *,
    allowlist: tuple[str, ...] = ("notes",),
    max_records: str = "8",
    max_record_bytes: str = "1048576",
    max_aggregate_bytes: str = "1048576",
) -> dict[str, JsonValue]:
    return {
        "profile_version": "second-brain-unified-db-export-profile-v1",
        "source_name": "unified-db",
        "operation": "EXPORT_ONLY",
        "source_allowlist": list(allowlist),
        "identity_mapping": "source_id+native_id",
        "revision_mapping": "declared_revision",
        "watermark_mapping": "explicit_cursor_map",
        "deletion_policy": "EXPLICIT_TOMBSTONE_ONLY",
        "history_policy": "DECLARED_ROWS_ONLY",
        "absence_policy": "ABSENCE_IS_NOT_DELETION",
        "import_requested": False,
        "serve_requested": False,
        "promote_requested": False,
        "cutover_requested": False,
        "max_records": max_records,
        "max_record_bytes": max_record_bytes,
        "max_aggregate_bytes": max_aggregate_bytes,
    }


def profile(
    *,
    allowlist: tuple[str, ...] = ("notes",),
    max_records: str = "8",
    max_record_bytes: str = "1048576",
    max_aggregate_bytes: str = "1048576",
) -> UnifiedDbExportProfileV1:
    body = profile_body(
        allowlist=allowlist,
        max_records=max_records,
        max_record_bytes=max_record_bytes,
        max_aggregate_bytes=max_aggregate_bytes,
    )
    return UnifiedDbExportProfileV1.from_mapping(
        body
        | {
            "profile_digest": canonical_ledger_digest(
                "unified-db-export-profile-v1",
                body,
            )
        }
    )


def cursors_for(rows: tuple[UnifiedDbExportRowV1, ...]) -> SnapshotCursorMapV1:
    sources = {item.source_id for item in rows}
    return SnapshotCursorMapV1.create(
        {source: f"snapshot-cursor-{source}" for source in sources}
    )


def make_fixture(
    rows: tuple[UnifiedDbExportRowV1, ...] | None = None,
) -> UnifiedDbExportFixtureV1:
    chosen = standard_rows() if rows is None else rows
    cursors = cursors_for(chosen)
    body: dict[str, JsonValue] = {
        "fixture_version": "second-brain-unified-db-export-fixture-v1",
        "fixture_id": "fixture-unified-db-001",
        "db_commitment": DB_COMMIT,
        "catalog_commitment": CATALOG_COMMIT,
        "source_commitment": SOURCE_COMMIT,
        "data_root_commitment": DATA_ROOT_COMMIT,
        "cursors": cursors.to_mapping(),
        "rows": [item.to_mapping() for item in chosen],
        "row_set_digest": row_set_digest(chosen),
        "fixture_digest": "0" * 64,
    }
    fixture = UnifiedDbExportFixtureV1(
        "second-brain-unified-db-export-fixture-v1",
        "fixture-unified-db-001",
        DB_COMMIT,
        CATALOG_COMMIT,
        SOURCE_COMMIT,
        DATA_ROOT_COMMIT,
        cursors,
        chosen,
        row_set_digest(chosen),
        "0" * 64,
    )
    return UnifiedDbExportFixtureV1.from_mapping(
        body | {"fixture_digest": fixture.computed_digest()}
    )


def plan_body(
    profile_digest: str,
    fixture: UnifiedDbExportFixtureV1,
    *,
    sources: tuple[str, ...],
) -> dict[str, JsonValue]:
    return {
        "plan_version": "second-brain-unified-db-export-plan-v1",
        "profile_digest": profile_digest,
        "fixture_id": fixture.fixture_id,
        "fixture_digest": fixture.fixture_digest,
        "row_set_digest": fixture.row_set_digest,
        "expected_source_ids": list(sources),
        "row_order": "source_id,native_id",
        "db_commitment": DB_COMMIT,
        "catalog_commitment": CATALOG_COMMIT,
        "source_commitment": SOURCE_COMMIT,
        "data_root_commitment": DATA_ROOT_COMMIT,
    }


def plan_for(
    exported: UnifiedDbExportProfileV1,
    rows: tuple[UnifiedDbExportRowV1, ...] | None = None,
) -> UnifiedDbExportPlanV1:
    fixture = make_fixture(rows)
    body = plan_body(
        exported.profile_digest, fixture, sources=exported.source_allowlist
    )
    return UnifiedDbExportPlanV1.from_mapping(
        body
        | {
            "plan_digest": canonical_ledger_digest("unified-db-export-plan-v1", body),
        }
    )


def proof(phase: str) -> UnifiedDbReadSafetyProofV1:
    body: dict[str, JsonValue] = {
        "proof_version": "second-brain-unified-db-export-read-safety-proof-v1",
        "phase": phase,
        "isolation": "SERIALIZABLE",
        "read_only": True,
        "deferrable": True,
        "writer_count": "0",
        "db_commitment": DB_COMMIT,
        "catalog_commitment": CATALOG_COMMIT,
        "source_commitment": SOURCE_COMMIT,
        "data_root_commitment": DATA_ROOT_COMMIT,
    }
    return UnifiedDbReadSafetyProofV1.from_mapping(
        body
        | {
            "proof_digest": canonical_ledger_digest(
                "unified-db-export-read-safety-proof-v1",
                body,
            )
        }
    )


def bound_reader(
    rows: tuple[UnifiedDbExportRowV1, ...] | None = None,
):
    from wiki_spike.applications.unified_db_snapshot_export_service import (
        StaticUnifiedDbFixtureReader,
    )

    chosen = standard_rows() if rows is None else rows
    fixture = make_fixture(chosen)
    return StaticUnifiedDbFixtureReader(
        chosen,
        proof("OPENING"),
        proof("CLOSING"),
        fixture.cursors,
        fixture.fixture_id,
        fixture.fixture_digest,
        fixture.row_set_digest,
    )
