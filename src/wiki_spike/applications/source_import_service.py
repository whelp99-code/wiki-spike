"""Fail-closed non-serving importer for bounded encrypted source snapshots."""
from __future__ import annotations

import os
import stat
from hashlib import sha256
from pathlib import Path

from wiki_spike.applications.snapshot_import_fs import (
    OpenSourceFile,
    SnapshotSourceFsError,
    open_source_file,
    read_exact,
)
from wiki_spike.applications.source_discovery_service import (
    is_allowed_source_suffix,
    is_denied_source_path,
)
from wiki_spike.memory_core.snapshot_import import (
    BoundedSnapshotV1,
    SnapshotImportRequestV1,
    SnapshotRecordV1,
)
from wiki_spike.memory_core.snapshot_import_ports import SnapshotImportStorePort
from wiki_spike.memory_core.snapshot_import_result import (
    ImportedRecordPayloadV1,
    RestoredSnapshotV1,
    SnapshotImportReceiptV1,
)
from wiki_spike.memory_core.source_discovery import (
    SourceDiscoveryEntryV1,
    SourceDiscoveryManifestV1,
)


class SourceImportError(ValueError):
    """Import refused because source safety or reconciliation could not be proven."""


class SourceImportService:
    """Read every source record first, then persist one non-serving encrypted snapshot."""

    def __init__(self, store: SnapshotImportStorePort, max_file_bytes: int) -> None:
        if max_file_bytes < 1:
            raise SourceImportError("max_file_bytes must be positive")
        self._store = store
        self._max_file_bytes = max_file_bytes

    def import_snapshot(
        self,
        request: SnapshotImportRequestV1,
        snapshot: BoundedSnapshotV1,
        discovery: SourceDiscoveryManifestV1,
    ) -> SnapshotImportReceiptV1:
        self._bind(request, snapshot, discovery)
        payloads = self._read_all(request, snapshot, discovery)
        self._store.persist_import(request, payloads)
        return SnapshotImportReceiptV1.create(request, len(payloads))

    def restore_snapshot(self, cohort_id: str) -> RestoredSnapshotV1:
        try:
            return self._store.restore_import(cohort_id)
        except ValueError as exc:
            raise SourceImportError(f"restore mismatch: {exc}") from exc

    def _bind(
        self,
        request: SnapshotImportRequestV1,
        snapshot: BoundedSnapshotV1,
        discovery: SourceDiscoveryManifestV1,
    ) -> None:
        if request.source_name != snapshot.source_name or request.source_name != discovery.source_name:
            raise SourceImportError("unknown or missing source scope")
        if request.source_root != discovery.source_root:
            raise SourceImportError("unknown or missing source scope")
        if request.target_namespace != snapshot.native_namespace:
            raise SourceImportError("path/namespace escape refused")
        if request.snapshot_digest != snapshot.snapshot_digest:
            raise SourceImportError("snapshot digest does not bind the snapshot")
        if request.discovery_manifest_digest != discovery.manifest_digest:
            raise SourceImportError("discovery digest does not bind the manifest")
        discovered = {entry.relative_path for entry in discovery.entries}
        live_paths = {
            record.relative_path
            for record in snapshot.records
            if record.relative_path is not None
        }
        if discovered != live_paths:
            raise SourceImportError(
                "skipped reconciliation: snapshot live paths must equal discovery paths"
            )

    def _read_all(
        self,
        request: SnapshotImportRequestV1,
        snapshot: BoundedSnapshotV1,
        discovery: SourceDiscoveryManifestV1,
    ) -> tuple[ImportedRecordPayloadV1, ...]:
        root = self._locked_root(request.source_root)
        entries = {entry.relative_path: entry for entry in discovery.entries}
        opened: list[tuple[SnapshotRecordV1, SourceDiscoveryEntryV1 | None, OpenSourceFile | None]] = []
        try:
            total = 0
            for record in snapshot.records:
                item = self._admit(root, record, entries.get(record.relative_path or ""))
                opened.append(item)
                if item[2] is not None:
                    total += item[2].metadata.st_size
                    if total > self._max_file_bytes:
                        raise SourceImportError("aggregate source content exceeds the import bound")
            return tuple(self._finish(record, entry, handle) for record, entry, handle in opened)
        except SnapshotSourceFsError as exc:
            raise SourceImportError(str(exc)) from exc
        finally:
            for _record, _entry, handle in opened:
                if handle is not None:
                    handle.close()

    def _locked_root(self, source_root: str) -> Path:
        root = Path(source_root)
        try:
            metadata = os.lstat(root)
        except OSError as exc:
            raise SourceImportError("source root does not exist or is inaccessible") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise SourceImportError("source root symlink refused")
        try:
            resolved = root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise SourceImportError("source root cannot be resolved safely") from exc
        if not stat.S_ISDIR(os.lstat(resolved).st_mode):
            raise SourceImportError("source root must be a directory")
        return resolved

    def _admit(
        self,
        root: Path,
        record: SnapshotRecordV1,
        entry: SourceDiscoveryEntryV1 | None,
    ) -> tuple[SnapshotRecordV1, SourceDiscoveryEntryV1 | None, OpenSourceFile | None]:
        if record.tombstone:
            return record, None, None
        if entry is None or record.relative_path is None:
            raise SourceImportError("unknown or missing source scope")
        if is_denied_source_path(record.relative_path):
            raise SourceImportError(f"deny-class source path refused: {record.relative_path}")
        if not is_allowed_source_suffix(record.relative_path):
            raise SourceImportError(f"unsupported source file suffix: {record.relative_path}")
        handle = open_source_file(root, record.relative_path)
        size = handle.metadata.st_size
        if size > self._max_file_bytes:
            handle.close()
            raise SourceImportError("source content exceeds the import bound")
        if (
            entry.size_bytes != str(size)
            or entry.mtime_ns != str(handle.metadata.st_mtime_ns)
            or entry.mode != str(handle.metadata.st_mode)
        ):
            handle.close()
            raise SourceImportError("source mutation observed before import")
        return record, entry, handle

    def _finish(
        self,
        record: SnapshotRecordV1,
        entry: SourceDiscoveryEntryV1 | None,
        handle: OpenSourceFile | None,
    ) -> ImportedRecordPayloadV1:
        if record.tombstone or handle is None:
            return ImportedRecordPayloadV1(
                record.native_id, record.revision, record.watermark, True, None, None, None
            )
        before = os.fstat(handle.fd)
        if (
            before.st_dev != handle.metadata.st_dev
            or before.st_ino != handle.metadata.st_ino
            or before.st_mtime_ns != handle.metadata.st_mtime_ns
            or before.st_size != handle.metadata.st_size
        ):
            raise SourceImportError("source mutation observed before import")
        content = read_exact(handle, before.st_size, self._max_file_bytes)
        if entry is None or sha256(content).hexdigest() != record.content_digest:
            raise SourceImportError("source mutation observed before import")
        return ImportedRecordPayloadV1(
            record.native_id,
            record.revision,
            record.watermark,
            False,
            record.relative_path,
            record.content_digest,
            content,
        )
