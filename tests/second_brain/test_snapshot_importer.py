from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from tests.second_brain.snapshot_importer_support import (
    digest_of,
    discovery_of,
    import_request,
    import_service,
    snapshot_of,
    verified_persistence,
)
from wiki_spike.applications.source_import_service import SourceImportError
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.snapshot_import_store import (
    LifecycleSnapshotImportStore,
    SnapshotImportStoreError,
)


def test_import_preserves_native_state_encrypted_and_ready_non_serving(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    first = root / "alpha.md"
    second = root / "beta.json"
    first.write_text("alpha plaintext", encoding="utf-8")
    second.write_text('{"beta":"plaintext"}', encoding="utf-8")
    before = {
        path: (digest_of(path.read_bytes()), path.stat().st_mtime_ns)
        for path in (first, second)
    }
    discovery = discovery_of(root)
    snapshot = snapshot_of(root)
    request = import_request(root, discovery.manifest_digest, snapshot)
    service, store, database, cas_root = import_service(tmp_path)

    receipt = service.import_snapshot(
        request=request,
        snapshot=snapshot,
        discovery=discovery,
    )
    restored = service.restore_snapshot(request.cohort_id)

    assert receipt.state == "READY_NON_SERVING"
    assert receipt.transitions == (
        "DISCOVERED",
        "IMPORTING",
        "RECONCILING",
        "READY_NON_SERVING",
    )
    assert receipt.serving_promoted is False
    assert [(record.native_id, record.revision, record.watermark, record.tombstone) for record in restored.records] == [
        ("note-alpha", "7", "watermark-11", False),
        ("note-beta", "3", "watermark-12", False),
        ("note-deleted", "9", "watermark-13", True),
    ]
    assert restored.records[0].content == b"alpha plaintext"
    assert restored.records[1].content == b'{"beta":"plaintext"}'
    assert restored.records[2].content is None
    assert before == {
        path: (digest_of(path.read_bytes()), path.stat().st_mtime_ns)
        for path in (first, second)
    }
    target_bytes = (tmp_path / "target.sqlite").read_bytes() + b"".join(
        path.read_bytes() for path in cas_root.rglob("*") if path.is_file()
    )
    assert b"alpha plaintext" not in target_bytes
    assert b'"beta":"plaintext"' not in target_bytes
    assert store.record_count(request.cohort_id) == 3
    database.close()


def test_import_rejects_source_mutation_before_any_target_write(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "alpha.md").write_text("alpha", encoding="utf-8")
    (root / "beta.json").write_text("{}", encoding="utf-8")
    discovery = discovery_of(root)
    snapshot = snapshot_of(root)
    request = import_request(root, discovery.manifest_digest, snapshot)
    service, store, database, _cas_root = import_service(tmp_path)
    (root / "alpha.md").write_text("mutated", encoding="utf-8")

    with pytest.raises(SourceImportError, match="mutation"):
        _ = service.import_snapshot(
            request=request,
            snapshot=snapshot,
            discovery=discovery,
        )
    assert store.record_count(request.cohort_id) == 0
    database.close()


@pytest.mark.parametrize(
    ("source_name", "target_namespace", "reconciliation_mode", "promote"),
    [
        ("unknown-source", "second-brain:import:unknown", "REQUIRED", False),
        ("me-wiki", "second-brain:import:unified-db", "REQUIRED", False),
        ("me-wiki", "second-brain:import:me-wiki", "SKIP", False),
        ("me-wiki", "second-brain:import:me-wiki", "REQUIRED", True),
    ],
)
def test_request_rejects_unknown_cross_namespace_skip_and_serving_promotion(
    tmp_path: Path,
    source_name: str,
    target_namespace: str,
    reconciliation_mode: str,
    promote: bool,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "alpha.md").write_text("alpha", encoding="utf-8")
    (root / "beta.json").write_text("{}", encoding="utf-8")
    snapshot = snapshot_of(root)

    with pytest.raises(ValueError):
        _ = import_request(
            root,
            digest_of("discovery"),
            snapshot,
            source_name=source_name,
            target_namespace=target_namespace,
            reconciliation_mode=reconciliation_mode,
            serving_promotion_requested=promote,
        )


def test_store_rejects_runtime_fallback_and_wrong_profile_binding(
    tmp_path: Path,
) -> None:
    database = LifecycleDatabase(tmp_path / "target.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    other_cas = EncryptedContentStore(tmp_path / "other-cas")
    profile = verified_persistence(database, cas)

    with pytest.raises(SnapshotImportStoreError, match="persistence profile"):
        _ = LifecycleSnapshotImportStore(
            database=database,
            cas=other_cas,
            persistence_profile=profile,
            encryption_key=b"\x13" * 32,
        )
    with pytest.raises(SnapshotImportStoreError, match="LifecycleDatabase"):
        _ = LifecycleSnapshotImportStore(
            database=cast(LifecycleDatabase, object()),
            cas=cas,
            persistence_profile=profile,
            encryption_key=b"\x13" * 32,
        )
    database.close()
