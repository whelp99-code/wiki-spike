"""Fail-closed non-serving importer for bounded encrypted source snapshots."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Protocol, runtime_checkable

from wiki_spike.applications.source_discovery_service import (
    is_allowed_source_suffix,
    is_denied_source_path,
)
from wiki_spike.infrastructure.safe_source_filesystem import (
    PinnedSourceFile,
    SafeSourceFilesystem,
    SafeSourceFilesystemError,
    SourceFilesystemLimits,
)
from wiki_spike.memory_core.second_brain_complete_snapshot import (
    CompleteSnapshotCertificateV1,
    SnapshotReconciliationV1,
    reconcile_snapshot,
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


@dataclass(frozen=True, slots=True)
class ReconciledSnapshotImportV1:
    request: SnapshotImportRequestV1
    previous: BoundedSnapshotV1
    current: BoundedSnapshotV1
    discovery: SourceDiscoveryManifestV1
    certificate: CompleteSnapshotCertificateV1


@dataclass(frozen=True, slots=True)
class _SourceReadAuthority:
    root: Path
    filesystem: SafeSourceFilesystem
    entries: dict[str, SourceDiscoveryEntryV1]


@dataclass(frozen=True, slots=True)
class _ReconciliationPersistenceV1:
    request: SnapshotImportRequestV1
    previous_snapshot_digest: str
    payloads: tuple[ImportedRecordPayloadV1, ...]
    reconciliation: SnapshotReconciliationV1
    certificate: CompleteSnapshotCertificateV1
    receipt: SnapshotImportReceiptV1


@runtime_checkable
class _AtomicReconciliationStorePort(Protocol):
    def persist_reconciliation(
        self,
        command: _ReconciliationPersistenceV1,
    ) -> SnapshotImportReceiptV1: ...


class SourceImportError(ValueError):
    """Import refused because source safety or reconciliation could not be proven."""


class SourceImportService:
    """Read every source record first, then persist one non-serving encrypted snapshot."""

    def __init__(
        self,
        store: SnapshotImportStorePort,
        max_file_bytes: int,
        filesystem: SafeSourceFilesystem | None = None,
    ) -> None:
        if max_file_bytes < 1:
            raise SourceImportError("max_file_bytes must be positive")
        self._store = store
        self._max_file_bytes = max_file_bytes
        self._filesystem = filesystem

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

    def import_reconciled_snapshot(
        self,
        command: ReconciledSnapshotImportV1,
    ) -> SnapshotImportReceiptV1:
        """Verify completeness, reconcile, and persist one atomic lifecycle unit."""
        try:
            command.certificate.assert_manifest(command.discovery)
        except ValueError as exc:
            raise SourceImportError(f"complete-snapshot certificate mismatch: {exc}") from exc
        self._bind(command.request, command.current, command.discovery)
        payloads = self._read_all(command.request, command.current, command.discovery)
        try:
            reconciliation = reconcile_snapshot(
                command.previous,
                command.current,
                command.certificate,
                command.discovery,
            )
        except ValueError as exc:
            raise SourceImportError(f"snapshot reconciliation mismatch: {exc}") from exc
        if not isinstance(self._store, _AtomicReconciliationStorePort):
            raise SourceImportError("snapshot store lacks atomic reconciliation persistence")
        receipt = SnapshotImportReceiptV1.create(command.request, len(payloads))
        return self._store.persist_reconciliation(
            _ReconciliationPersistenceV1(
                command.request,
                command.previous.snapshot_digest,
                payloads,
                reconciliation,
                command.certificate,
                receipt,
            )
        )

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
        root = Path(request.source_root)
        filesystem = self._filesystem or SafeSourceFilesystem(
            (root,),
            SourceFilesystemLimits(max_file_bytes=self._max_file_bytes),
        )
        authority = _SourceReadAuthority(
            root,
            filesystem,
            {entry.relative_path: entry for entry in discovery.entries},
        )
        opened: list[tuple[SnapshotRecordV1, SourceDiscoveryEntryV1 | None, PinnedSourceFile | None]] = []
        try:
            total = 0
            for record in snapshot.records:
                item = self._admit(authority, record)
                opened.append(item)
                if item[2] is not None:
                    total += item[2].metadata.st_size
                    if total > self._max_file_bytes:
                        raise SourceImportError("aggregate source content exceeds the import bound")
            return tuple(self._finish(record, entry, handle) for record, entry, handle in opened)
        except SafeSourceFilesystemError as exc:
            raise SourceImportError(str(exc)) from exc
        finally:
            for _record, _entry, handle in opened:
                if handle is not None:
                    handle.close()

    def _admit(
        self,
        authority: _SourceReadAuthority,
        record: SnapshotRecordV1,
    ) -> tuple[SnapshotRecordV1, SourceDiscoveryEntryV1 | None, PinnedSourceFile | None]:
        entry = authority.entries.get(record.relative_path or "")
        if record.tombstone:
            return record, None, None
        if entry is None or record.relative_path is None:
            raise SourceImportError("unknown or missing source scope")
        if is_denied_source_path(record.relative_path):
            raise SourceImportError(f"deny-class source path refused: {record.relative_path}")
        if not is_allowed_source_suffix(record.relative_path):
            raise SourceImportError(f"unsupported source file suffix: {record.relative_path}")
        handle = authority.filesystem.open_file(authority.root, record.relative_path)
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
        handle: PinnedSourceFile | None,
    ) -> ImportedRecordPayloadV1:
        if record.tombstone or handle is None:
            return ImportedRecordPayloadV1(
                record.native_id, record.revision, record.watermark, True, None, None, None
            )
        content = handle.read()
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
