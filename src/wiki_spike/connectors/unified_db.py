"""Canonical read-only unified-db migration adapter for owner-created exports."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final, assert_never

from wiki_spike.applications.second_brain_source_sync_contracts import (
    SourcePrepareResultV1,
    SourceScanResultV1,
    SourceScanV1,
    SourceSyncAdapterErrorV1,
    SourceSyncAdapterFailureV1,
    SourceSyncChangeV1,
    SourceSyncTaskContextV1,
    SourceWorkItemV1,
)
from wiki_spike.applications.unified_db_snapshot_export_io import HARD_CAP
from wiki_spike.applications.unified_db_snapshot_export_tree import (
    assert_root_allowlist,
    open_package_root,
    read_payload_tree_at,
    read_root_file,
)
from wiki_spike.applications.unified_db_snapshot_export_verify import verify_export_package
from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion
from wiki_spike.memory_core.second_brain_source_profiles import (
    SourceIdentityV2,
    SourceKindV2,
    parse_source_identity,
)
from wiki_spike.memory_core.snapshot_import import BoundedSnapshotV1, SnapshotRecordV1
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object
from wiki_spike.memory_core.unified_db_snapshot_export_proof import UnifiedDbReadSafetyProofV1

UNIFIED_DB_IDENTITY: Final = parse_source_identity("unified-db")


@dataclass(frozen=True, slots=True)
class UnifiedDbSourceError(ValueError):
    detail: str

    def __str__(self) -> str:
        return self.detail


class UnifiedDbMigrationAdapter:
    """Read an immutable unified-db export. Construction never opens the export."""

    def __init__(self, export_root: Path, identity: SourceIdentityV2, scope_enabled: bool) -> None:
        match identity.kind:
            case SourceKindV2.MIGRATION_SOURCE:
                if identity.name != UNIFIED_DB_IDENTITY.name:
                    raise UnifiedDbSourceError("canonical unified-db identity is required")
            case SourceKindV2.SOURCE_PROFILE:
                raise UnifiedDbSourceError("canonical unified-db identity is required")
            case unreachable:
                assert_never(unreachable)
        if not export_root.is_absolute():
            raise UnifiedDbSourceError("export root must be absolute")
        self._export_root = export_root
        self._scope_enabled = scope_enabled

    def scan(
        self, source_ref: str, checkpoint_ref: str | None, context: SourceSyncTaskContextV1
    ) -> SourceScanResultV1:
        del source_ref, checkpoint_ref
        if not self._scope_enabled:
            return _failure(SourceSyncAdapterErrorV1.QUARANTINED)
        if context.is_cancelled():
            return _failure(SourceSyncAdapterErrorV1.SYNC_TIMEOUT)
        try:
            return self._scan_export(context)
        except UnsupportedContractVersion:
            return _failure(SourceSyncAdapterErrorV1.FORMAT_UNSUPPORTED)
        except (UnifiedDbExportError, InvalidContractValue, UnknownContractField, OSError, KeyError):
            return _failure(SourceSyncAdapterErrorV1.QUARANTINED)

    def prepare(self, item: SourceWorkItemV1, context: SourceSyncTaskContextV1) -> SourcePrepareResultV1:
        if not self._scope_enabled:
            return _failure(SourceSyncAdapterErrorV1.QUARANTINED)
        if context.is_cancelled():
            return _failure(SourceSyncAdapterErrorV1.SYNC_TIMEOUT)
        return SourceSyncChangeV1(item.item_ref, item.revision_ref, item.tombstone)

    def _scan_export(self, context: SourceSyncTaskContextV1) -> SourceScanResultV1:
        root = os.fspath(self._export_root)
        snapshot, files = _read_signed_export(root)
        if context.is_cancelled():
            return _failure(SourceSyncAdapterErrorV1.SYNC_TIMEOUT)
        receipt = verify_export_package(root)
        if receipt.source_name != UNIFIED_DB_IDENTITY.name or snapshot.source_name != UNIFIED_DB_IDENTITY.name:
            raise UnifiedDbExportError("export source_name must be unified-db")
        items = tuple(_work_item(record, files) for record in snapshot.records)
        return SourceScanV1("checkpoint:" + receipt.package_digest, "0", items)


def _failure(error: SourceSyncAdapterErrorV1) -> SourceSyncAdapterFailureV1:
    return SourceSyncAdapterFailureV1(error)


def _read_signed_export(root: str) -> tuple[BoundedSnapshotV1, dict[str, bytes]]:
    root_fd = open_package_root(root)
    try:
        assert_root_allowlist(root_fd)
        snapshot_raw, budget = read_root_file(root_fd, "bounded-snapshot.json", HARD_CAP)
        opening_raw, budget = read_root_file(root_fd, "opening-proof.json", budget)
        files, _remaining = read_payload_tree_at(root_fd, budget)
    finally:
        os.close(root_fd)
    snapshot = BoundedSnapshotV1.from_mapping(decode_json_object(snapshot_raw.decode("utf-8")))
    opening = UnifiedDbReadSafetyProofV1.from_mapping(decode_json_object(opening_raw.decode("utf-8")))
    if opening.phase != "OPENING":
        raise UnifiedDbExportError("signed catalog is required")
    return snapshot, files


def _work_item(record: SnapshotRecordV1, files: dict[str, bytes]) -> SourceWorkItemV1:
    if record.tombstone:
        return SourceWorkItemV1("item:" + record.native_id, record.revision, True, b"")
    path = record.relative_path
    if path is None:
        raise UnifiedDbExportError("live record is missing payload")
    return SourceWorkItemV1("item:" + record.native_id, record.revision, False, files[path])


__all__ = (
    "UNIFIED_DB_IDENTITY",
    "UnifiedDbMigrationAdapter",
    "UnifiedDbSourceError",
)
