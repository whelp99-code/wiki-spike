"""Core port for non-serving encrypted snapshot import persistence."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .snapshot_import import SnapshotImportRequestV1
from .snapshot_import_result import ImportedRecordPayloadV1, RestoredSnapshotV1


@runtime_checkable
class SnapshotImportStorePort(Protocol):
    """Exact LifecycleDatabase + encrypted CAS persistence boundary."""

    def persist_import(
        self,
        request: SnapshotImportRequestV1,
        payloads: tuple[ImportedRecordPayloadV1, ...],
    ) -> None: ...

    def restore_import(self, cohort_id: str) -> RestoredSnapshotV1: ...

    def record_count(self, cohort_id: str) -> int: ...
