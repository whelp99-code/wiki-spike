"""Ports for fixture-only unified-db snapshot export."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .unified_db_snapshot_export_profile import UnifiedDbExportPlanV1
from .unified_db_snapshot_export_proof import FixtureReadResultV1


@runtime_checkable
class UnifiedDbFixtureReadPort(Protocol):
    def read_fixture_rows(
        self,
        authority: object,
        plan: UnifiedDbExportPlanV1,
        limit: int,
    ) -> FixtureReadResultV1: ...


@runtime_checkable
class LocalSnapshotPackageWriterPort(Protocol):
    def start(self, destination: str) -> str: ...

    def write_file(
        self, staging_root: str, relative_path: str, content: bytes
    ) -> None: ...

    def commit(
        self,
        staging_root: str,
        destination: str,
        receipt_relative_path: str,
        receipt: bytes,
        receipt_digest: str,
    ) -> None: ...

    def abort(self, staging_root: str) -> None: ...
