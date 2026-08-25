from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

import pytest
from tests.second_brain.snapshot_importer_support import (
    digest_of,
    import_request,
    import_service,
    snapshot_from_records,
    verified_persistence,
)

from wiki_spike.applications.source_discovery_service import (
    CertifiedSourceDiscoveryV1,
    discover_certified_source,
)
from wiki_spike.applications.source_import_service import (
    ReconciledSnapshotImportV1,
    SourceImportError,
)
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.snapshot_import_store import LifecycleSnapshotImportStore
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.source_discovery import (
    SOURCE_DISCOVERY_REQUEST_V1,
    SourceDiscoveryRequestV1,
)


def _record(native_id: str, revision: str, path: str, content: str) -> dict[str, JsonValue]:
    return {
        "native_id": native_id,
        "revision": revision,
        "watermark": f"watermark-{revision}",
        "tombstone": False,
        "relative_path": path,
        "content_digest": digest_of(content),
        "keyed_dedupe_ref": f"keyed-content:{digest_of(native_id)}",
    }


def _certified(root: Path) -> CertifiedSourceDiscoveryV1:
    return discover_certified_source(
        SourceDiscoveryRequestV1.from_mapping(
            {
                "request_version": SOURCE_DISCOVERY_REQUEST_V1,
                "source_name": "me-wiki",
                "source_root": str(root.resolve()),
            }
        )
    )


def _prepared(tmp_path: Path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "alpha.md").write_text("after", encoding="utf-8")
    certified = _certified(root)
    previous = snapshot_from_records(
        [
            _record("alpha", "1", "alpha.md", "before"),
            _record("missing", "1", "missing.md", "gone"),
        ],
        "watermark-1",
    )
    current = snapshot_from_records(
        [_record("alpha", "2", "alpha.md", "after")],
        "watermark-2",
    )
    request = import_request(root, certified.manifest.manifest_digest, current)
    service, store, database, cas_root = import_service(tmp_path)
    return root, certified, previous, current, request, service, store, database, cas_root


def _count(database: LifecycleDatabase, table: str) -> int:
    assert database.con is not None
    return int(database.con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def test_reconciliation_commits_one_checkpoint_event_outbox_and_domain_record(
    tmp_path: Path,
) -> None:
    # Given: a complete certified successor with one update and one proven absence.
    _, certified, previous, current, request, service, _, database, _ = _prepared(tmp_path)

    # When: import and reconciliation cross the durable boundary.
    receipt = service.import_reconciled_snapshot(
        ReconciledSnapshotImportV1(
            request, previous, current, certified.manifest, certified.certificate
        )
    )

    # Then: the full outcome is represented by one atomic durable unit.
    assert receipt.cohort_id == request.cohort_id
    for table in (
        "snapshot_reconciliation_commit",
        "snapshot_reconciliation_checkpoint",
        "event_log",
        "outbox",
    ):
        assert _count(database, table) == 1
    assert _count(database, "snapshot_import_cohort") == 1
    assert database.con is not None
    commit = database.con.execute(
        "SELECT quarantined_sequence,tombstoned_sequence,edge_removal_sequence "
        "FROM snapshot_reconciliation_commit WHERE cohort_id=?",
        (request.cohort_id,),
    ).fetchone()
    assert tuple(commit) == ("0", "1", "1")
    database.close()


def test_precommit_crash_exposes_no_reconciliation_checkpoint(tmp_path: Path) -> None:
    # Given: a fault at the final checkpoint insert inside the reconciliation transaction.
    _, certified, previous, current, request, service, _, database, _ = _prepared(tmp_path)
    assert database.con is not None
    database.con.execute(
        "CREATE TEMP TRIGGER inject_crash BEFORE INSERT ON snapshot_reconciliation_checkpoint "
        "BEGIN SELECT RAISE(ABORT, 'injected reconciliation crash'); END"
    )

    # When: persistence reaches the injected precommit failure.
    with pytest.raises(sqlite3.IntegrityError, match="injected reconciliation crash"):
        service.import_reconciled_snapshot(
            ReconciledSnapshotImportV1(
                request, previous, current, certified.manifest, certified.certificate
            )
        )

    # Then: no database component of the lifecycle unit is visible.
    for table in (
        "snapshot_import_cohort",
        "snapshot_reconciliation_commit",
        "snapshot_reconciliation_checkpoint",
        "event_log",
        "outbox",
    ):
        assert _count(database, table) == 0
    database.close()


def test_postcommit_restart_and_concurrent_retry_return_one_receipt(tmp_path: Path) -> None:
    # Given: one committed reconciliation and its encrypted CAS/profile bindings.
    _, certified, previous, current, request, service, store, database, _ = _prepared(tmp_path)
    expected = service.import_reconciled_snapshot(
        ReconciledSnapshotImportV1(
            request, previous, current, certified.manifest, certified.certificate
        )
    )
    cas = store._cas
    database.close()

    def retry() -> str:
        reopened = LifecycleDatabase(tmp_path / "target.sqlite")
        reopened.initialize()
        reopened_store = LifecycleSnapshotImportStore(
            reopened, cas, verified_persistence(reopened, cas), b"\x13" * 32
        )
        from wiki_spike.applications.source_import_service import SourceImportService

        retried = SourceImportService(reopened_store, 1024 * 1024).import_reconciled_snapshot(
            ReconciledSnapshotImportV1(
                request, previous, current, certified.manifest, certified.certificate
            )
        )
        reopened.close()
        return retried.receipt_digest

    # When: two independent restarted writers retry the exact operation.
    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = tuple(pool.map(lambda _: retry(), range(2)))

    # Then: both return the sole durable receipt without duplicate effects.
    assert receipts == (expected.receipt_digest, expected.receipt_digest)
    reopened = LifecycleDatabase(tmp_path / "target.sqlite")
    reopened.initialize()
    assert _count(reopened, "snapshot_reconciliation_checkpoint") == 1
    assert _count(reopened, "event_log") == 1
    assert _count(reopened, "outbox") == 1
    reopened.close()


def test_revision_mutation_is_quarantined_without_deletion(tmp_path: Path) -> None:
    # Given: a certified source whose native revision was reused for changed content.
    root = tmp_path / "source"
    root.mkdir()
    (root / "alpha.md").write_text("changed", encoding="utf-8")
    certified = _certified(root)
    previous = snapshot_from_records([_record("alpha", "1", "alpha.md", "before")], "watermark-1")
    current = snapshot_from_records([_record("alpha", "1", "alpha.md", "changed")], "watermark-2")
    request = import_request(root, certified.manifest.manifest_digest, current)
    service, _, database, _ = import_service(tmp_path)

    # When: reconciliation observes the same-revision payload mutation.
    service.import_reconciled_snapshot(
        ReconciledSnapshotImportV1(
            request, previous, current, certified.manifest, certified.certificate
        )
    )

    # Then: it persists quarantine and no provenance deletion commitment.
    assert database.con is not None
    commit = database.con.execute(
        "SELECT quarantined_sequence,tombstoned_sequence,edge_removal_sequence "
        "FROM snapshot_reconciliation_commit"
    ).fetchone()
    assert tuple(commit) == ("1", "0", "0")
    database.close()


def test_same_path_stale_certificate_fails_before_reads_or_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a certificate for an old scan and a new manifest with the same path after mutation.
    root = tmp_path / "source"
    root.mkdir()
    live = root / "alpha.md"
    live.write_text("before", encoding="utf-8")
    stale = _certified(root)
    live.write_text("after-longer", encoding="utf-8")
    current_evidence = _certified(root)
    previous = snapshot_from_records(
        [
            _record("alpha", "1", "alpha.md", "before"),
            _record("missing", "1", "missing.md", "gone"),
        ],
        "watermark-1",
    )
    current = snapshot_from_records(
        [_record("alpha", "2", "alpha.md", "after-longer")],
        "watermark-2",
    )
    request = import_request(root, current_evidence.manifest.manifest_digest, current)
    service, store, database, cas_root = import_service(tmp_path)
    read_probe = Mock(side_effect=AssertionError("_read_all reached"))
    cas_probe = Mock(side_effect=AssertionError("CAS reached"))
    uow_probe = Mock(side_effect=AssertionError("UoW reached"))
    monkeypatch.setattr(service, "_read_all", read_probe)
    monkeypatch.setattr(store._cas, "put", cas_probe)
    monkeypatch.setattr(database, "unit_of_work", uow_probe)

    # When: the caller supplies the exact current manifest but the old same-path certificate.
    with pytest.raises(SourceImportError, match="certificate"):
        service.import_reconciled_snapshot(
            ReconciledSnapshotImportV1(
                request,
                previous,
                current,
                current_evidence.manifest,
                stale.certificate,
            )
        )

    # Then: rejection precedes source reads, CAS, UoW, tombstones, and every domain row.
    read_probe.assert_not_called()
    cas_probe.assert_not_called()
    uow_probe.assert_not_called()
    assert not any(path.is_file() for path in cas_root.rglob("*"))
    for table in (
        "snapshot_import_cohort",
        "snapshot_import_record",
        "snapshot_import_transition",
        "snapshot_import_reconciliation",
        "snapshot_reconciliation_commit",
        "snapshot_reconciliation_checkpoint",
        "canonical_artifact",
        "deletion_state",
        "event_log",
        "outbox",
    ):
        assert _count(database, table) == 0
    database.close()


def test_invalid_certificate_fails_before_absence_can_be_persisted(tmp_path: Path) -> None:
    # Given: an absence and a certificate issued for a different complete scan.
    _, certified, previous, current, request, service, _, database, _ = _prepared(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    (other / "other.md").write_text("other", encoding="utf-8")
    wrong = _certified(other)

    # When/Then: certificate verification fails before reconciliation or persistence.
    with pytest.raises(SourceImportError, match="certificate"):
        service.import_reconciled_snapshot(
            ReconciledSnapshotImportV1(
                request, previous, current, certified.manifest, wrong.certificate
            )
        )
    assert _count(database, "snapshot_reconciliation_checkpoint") == 0
    assert _count(database, "snapshot_import_cohort") == 0
    database.close()
