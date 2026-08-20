"""Ports for fake-only PostgreSQL identity and catalog capture."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .unified_db_postgres_capture_catalog import CatalogRowV1, PostgresCatalogSnapshotV1
from .unified_db_postgres_capture_plan import PostgresIdentityInputsV1
from .unified_db_postgres_identity import PostgresIdentityReceiptV1


@runtime_checkable
class PostgresIdentityCapturePort(Protocol):
    """Produce a body-free identity receipt from exactly four metadata values."""

    def capture_identity(
        self, inputs: PostgresIdentityInputsV1
    ) -> PostgresIdentityReceiptV1: ...


@runtime_checkable
class PostgresCatalogCapturePort(Protocol):
    """Normalize typed catalog rows into a digest-bound snapshot."""

    def capture_catalog(self, rows: tuple[CatalogRowV1, ...]) -> PostgresCatalogSnapshotV1: ...
