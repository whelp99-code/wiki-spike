from __future__ import annotations

import ast
from pathlib import Path

from tests.second_brain.snapshot_importer_support import import_service
from tests.second_brain.unified_db_export_support import (
    EXPORT_PY,
    authority,
    bound_reader,
    plan_for,
    profile,
)
from wiki_spike.applications.unified_db_snapshot_export_handoff import (
    bridge_snapshot_import_handoff,
)
from wiki_spike.applications.unified_db_snapshot_export_service import (
    UnifiedDbSnapshotExportService,
)
from wiki_spike.infrastructure.local_snapshot_package_writer import (
    LocalSnapshotPackageWriter,
)
from wiki_spike.memory_core.snapshot_import_result import (
    SCOPE_AUTHORITY_NON_AUTHORITATIVE,
)


def test_exported_snapshot_imports_ready_non_serving_without_exporter_import(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "pkg"
    exported = profile()
    receipt = UnifiedDbSnapshotExportService(
        reader=bound_reader(),
        writer=LocalSnapshotPackageWriter(),
    ).export_fixture(authority(), exported, plan_for(exported), str(dest))
    handoff = bridge_snapshot_import_handoff(
        str(dest),
        cohort_id="cohort-unified-db-001",
        resolved_scope_digest="a" * 64,
    )
    live = {
        record.relative_path
        for record in handoff.snapshot.records
        if record.relative_path
    }
    assert live == {entry.relative_path for entry in handoff.discovery.entries}
    assert handoff.snapshot.source_name == "unified-db"
    service, store, database, _cas = import_service(tmp_path)
    imported = service.import_snapshot(
        request=handoff.request,
        snapshot=handoff.snapshot,
        discovery=handoff.discovery,
    )
    restored = service.restore_snapshot(handoff.request.cohort_id)
    assert [item.tombstone for item in restored.records] == [False, False, True]
    assert restored.records[0].revision != ""
    assert restored.records[0].watermark != ""
    assert imported.state == "READY_NON_SERVING"
    assert imported.scope_authority_state == SCOPE_AUTHORITY_NON_AUTHORITATIVE
    assert imported.cutover_eligible is False
    assert imported.serving_promoted is False
    assert receipt.import_invoked is False
    assert store.record_count(handoff.request.cohort_id) == 3
    database.close()
    for path in EXPORT_PY:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "source_import_service" not in node.module
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "source_import_service" not in alias.name
