from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path

import pytest
from tests.second_brain.unified_db_export_support import (
    ALPHA,
    BETA,
    CATALOG_COMMIT,
    authority,
    bound_reader,
    plan_for,
    profile,
    row,
    standard_rows,
)

from wiki_spike.applications.second_brain_source_sync_contracts import (
    SourceScanV1,
    SourceSyncAdapterErrorV1,
    SourceSyncAdapterFailureV1,
    SourceSyncChangeV1,
    SourceSyncTaskContextV1,
)
from wiki_spike.applications.unified_db_snapshot_export_service import (
    UnifiedDbSnapshotExportService,
)
from wiki_spike.connectors.unified_db import UnifiedDbMigrationAdapter, UnifiedDbSourceError
from wiki_spike.infrastructure.local_snapshot_package_writer import LocalSnapshotPackageWriter
from wiki_spike.memory_core.second_brain_source_profiles import parse_source_identity
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportRowV1
from wiki_spike.memory_core.unified_db_snapshot_export_bind import bind_native_id
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

SOURCE = "source:" + "a" * 64


def _package(tmp_path: Path, rows: tuple[UnifiedDbExportRowV1, ...] | None = None) -> Path:
    dest = tmp_path / "pkg"
    exported = profile()
    chosen = standard_rows() if rows is None else rows
    UnifiedDbSnapshotExportService(
        reader=bound_reader(chosen),
        writer=LocalSnapshotPackageWriter(),
    ).export_fixture(authority(), exported, plan_for(exported, chosen), str(dest))
    return dest


def _adapter(root: Path, *, enabled: bool = True) -> UnifiedDbMigrationAdapter:
    return UnifiedDbMigrationAdapter(root, parse_source_identity("unified-db"), enabled)


def _scan(adapter: UnifiedDbMigrationAdapter) -> SourceScanV1 | SourceSyncAdapterFailureV1:
    return adapter.scan(SOURCE, None, SourceSyncTaskContextV1.create(30.0))


def _unlock(root: Path) -> None:
    os.chmod(root, 0o700)
    os.chmod(root / "payload", 0o700)
    for child in (*root.iterdir(), *(root / "payload").iterdir()):
        if child.is_file():
            os.chmod(child, 0o600)


def _lock(root: Path) -> None:
    for child in (root / "payload").iterdir():
        os.chmod(child, 0o400)
    os.chmod(root / "payload", 0o500)
    for child in root.iterdir():
        if child.is_file():
            os.chmod(child, 0o400)
    os.chmod(root, 0o500)


def _fingerprint(root: Path) -> bytes:
    digest = sha256()
    for path in sorted(root.rglob("*")):
        meta = path.lstat()
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(f"{meta.st_mode:o}:{meta.st_size}:{meta.st_mtime_ns}".encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.digest()


def test_scan_reads_signed_catalog_items_when_export_is_valid(tmp_path: Path) -> None:
    # Given: an owner-created immutable unified-db export with a signed catalog.
    dest = _package(tmp_path)
    opening = decode_json_object((dest / "opening-proof.json").read_text(encoding="utf-8"))

    # When: the canonical adapter scans the export.
    result = _scan(_adapter(dest))

    # Then: the signed catalog is required and live rows become readable work items.
    assert opening["catalog_commitment"] == CATALOG_COMMIT
    assert isinstance(result, SourceScanV1)
    by_ref = {item.item_ref: item for item in result.items}
    alpha = by_ref["item:" + bind_native_id("notes", "alpha")]
    assert alpha.payload == ALPHA
    assert alpha.tombstone is False


def test_scan_quarantines_when_signed_catalog_is_missing(tmp_path: Path) -> None:
    # Given: a valid export whose signed catalog proof was removed.
    dest = _package(tmp_path)
    _unlock(dest)
    (dest / "opening-proof.json").unlink()
    _lock(dest)

    # When: the adapter scans the incomplete export.
    result = _scan(_adapter(dest))

    # Then: the missing catalog is quarantined.
    assert isinstance(result, SourceSyncAdapterFailureV1)
    assert result.error is SourceSyncAdapterErrorV1.QUARANTINED


def test_scan_reports_unsupported_version_when_snapshot_version_is_unknown(tmp_path: Path) -> None:
    # Given: an export whose snapshot version is not the supported contract.
    dest = _package(tmp_path)
    snapshot = dest / "bounded-snapshot.json"
    _unlock(dest)
    payload = decode_json_object(snapshot.read_text(encoding="utf-8"))
    payload["snapshot_version"] = "bounded-source-snapshot-v0"
    snapshot.write_text(json.dumps(payload), encoding="utf-8")
    _lock(dest)

    # When: the adapter scans the unsupported export.
    result = _scan(_adapter(dest))

    # Then: the unknown version is refused as unsupported.
    assert isinstance(result, SourceSyncAdapterFailureV1)
    assert result.error is SourceSyncAdapterErrorV1.FORMAT_UNSUPPORTED


def test_scan_preserves_declared_revision_when_row_names_native_revision(tmp_path: Path) -> None:
    # Given: a live export row that declares a native revision distinct from its digest.
    declared = "rev-notes-alpha-2"
    dest = _package(tmp_path, (row("alpha", ALPHA, "cursor-alpha", revision=declared),))

    # When: the adapter scans the export.
    result = _scan(_adapter(dest))

    # Then: the declared native revision is conserved as the work-item revision.
    assert isinstance(result, SourceScanV1)
    assert result.items[0].revision_ref == declared


def test_scan_emits_explicit_tombstone_when_export_marks_deletion(tmp_path: Path) -> None:
    # Given: a complete export that marks one native identity as an explicit tombstone.
    dest = _package(tmp_path)

    # When: the adapter scans the export.
    result = _scan(_adapter(dest))

    # Then: only the declared tombstone is emitted, with an empty body.
    assert isinstance(result, SourceScanV1)
    gone = next(item for item in result.items if item.tombstone)
    assert gone.item_ref == "item:" + bind_native_id("notes", "gone")
    assert gone.payload == b""


def test_scan_binds_identity_and_omits_forbidden_fields_when_reading_rows(tmp_path: Path) -> None:
    # Given: a valid unified-db export whose native ids must stay bound.
    dest = _package(tmp_path)

    # When: the adapter materializes work items.
    result = _scan(_adapter(dest))

    # Then: raw native ids and connection secrets are absent from public item fields.
    assert isinstance(result, SourceScanV1)
    rendered = " ".join(f"{item.item_ref} {item.revision_ref}" for item in result.items)
    assert "alpha" not in rendered
    assert "postgres://" not in rendered
    assert "password" not in rendered
    assert all(item.item_ref.startswith("item:") and len(item.item_ref) == 69 for item in result.items)


def test_scan_makes_zero_source_writes_when_export_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a valid immutable export and a write-syscall trap.
    dest = _package(tmp_path)
    before = _fingerprint(dest)

    def forbid_write(*_args: str | bytes | int, **_kwargs: str | bytes | int) -> None:
        pytest.fail("unified-db adapter attempted a source write")

    monkeypatch.setattr(os, "write", forbid_write)
    monkeypatch.setattr(os, "replace", forbid_write)
    monkeypatch.setattr(os, "rename", forbid_write)
    monkeypatch.setattr(os, "unlink", forbid_write)

    # When: the adapter scans and prepares one live item.
    adapter = _adapter(dest)
    result = _scan(adapter)
    assert isinstance(result, SourceScanV1)
    live = next(item for item in result.items if not item.tombstone)
    prepared = adapter.prepare(live, SourceSyncTaskContextV1.create(30.0))

    # Then: the export bytes and modes are conserved and prepare keeps the revision.
    assert _fingerprint(dest) == before
    assert prepared == SourceSyncChangeV1(live.item_ref, live.revision_ref, False)
    assert BETA in {item.payload for item in result.items}


def test_scan_quarantines_when_export_payload_is_mutated(tmp_path: Path) -> None:
    # Given: a previously valid export whose payload digest no longer matches.
    dest = _package(tmp_path)
    payload = dest / "payload" / "00000000.json"
    _unlock(dest)
    payload.write_bytes(payload.read_bytes() + b"x")
    _lock(dest)

    # When: the adapter scans the mutated export.
    result = _scan(_adapter(dest))

    # Then: the mutated export is quarantined.
    assert isinstance(result, SourceSyncAdapterFailureV1)
    assert result.error is SourceSyncAdapterErrorV1.QUARANTINED


def test_scan_opens_no_export_when_scope_is_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a disabled unified-db scope and a valid export that must not be opened.
    dest = _package(tmp_path)
    opened: list[str] = []
    original_open = os.open

    def record_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        opened.append(os.fsdecode(path))
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", record_open)

    # When: the disabled adapter is asked to scan.
    result = _scan(_adapter(dest, enabled=False))

    # Then: the export is never opened and the scan quarantines before I/O.
    assert isinstance(result, SourceSyncAdapterFailureV1)
    assert result.error is SourceSyncAdapterErrorV1.QUARANTINED
    assert opened == []


def test_adapter_rejects_database_snapshot_alias_when_constructed(tmp_path: Path) -> None:
    # Given: the certified-v2 Database snapshot identity, which is not unified-db.
    dest = tmp_path / "unused"

    # When / Then: construction refuses the alias before any export is opened.
    with pytest.raises(UnifiedDbSourceError):
        UnifiedDbMigrationAdapter(dest, parse_source_identity("Database snapshot"), True)
