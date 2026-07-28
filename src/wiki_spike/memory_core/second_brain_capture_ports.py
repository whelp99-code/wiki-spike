"""Inert Stage-2 capture port shapes; implementations belong outside memory_core."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .second_brain_capture_contracts import (
    CaptureItemReceiptV1, CaptureReconciliationV1, CaptureScanManifestV1,
    MigrationRegistrationV1, NonServingCaptureCohortV1, ReconciledCheckpointAdvanceV1,
    ScanCheckpointV1, SourceScopeRefV1,
)


@runtime_checkable
class ConnectorSourceReaderPort(Protocol):
    """Connector boundary: source identity is typed; native values stay transient."""
    def read_fixture_ciphertexts(self, scope: SourceScopeRefV1, scan_epoch: str) -> tuple[bytes, ...]: ...


@runtime_checkable
class EncryptedNativeMappingSealerPort(Protocol):
    """Seals transient connector-native mappings before only an opaque ref is retained."""
    def seal_native_mapping(self, scope: SourceScopeRefV1, capture_ref: str, native_mapping: bytes) -> str: ...


@runtime_checkable
class CaptureReaderPort(Protocol):
    def read_capture_receipt(self, capture_ref: str) -> CaptureItemReceiptV1 | None: ...


@runtime_checkable
class CaptureCheckpointPort(Protocol):
    """Checkpoint authority is only available through atomic reconciliation advancement.

    Implementations atomically read the checkpoint stored for
    ``advance.checkpoint.scope.scope_ref`` and persist both embedded contracts.
    A ``None`` previous_checkpoint_ref requires no stored checkpoint; a non-None
    reference requires that exact stored checkpoint ref. Missing or mismatched
    stored state must reject without persisting either contract.
    """
    def read_scan_checkpoint(self, scope_ref: str) -> ScanCheckpointV1 | None: ...
    def reconcile_and_advance_checkpoint(self, advance: ReconciledCheckpointAdvanceV1) -> None: ...

@runtime_checkable
class EncryptedCaptureMappingPort(Protocol):
    def record_capture_receipt(self, receipt: CaptureItemReceiptV1) -> None: ...
    def record_migration_registration(self, registration: MigrationRegistrationV1) -> None: ...


@runtime_checkable
class CaptureManifestPort(Protocol):
    def record_capture_manifest(self, manifest: CaptureScanManifestV1) -> None: ...


@runtime_checkable
class NonServingCaptureCohortPort(Protocol):
    def record_non_serving_capture_cohort(self, cohort: NonServingCaptureCohortV1) -> None: ...


@runtime_checkable
class CaptureFilesystemPort(Protocol):
    """Low-level boundary: only keyed fixture references cross this core port."""
    def read_fixture_ciphertext(self, fixture_ref: str) -> bytes: ...


@runtime_checkable
class CaptureApiPort(Protocol):
    """Low-level boundary with no source URL, native ID, or cursor representation."""
    def read_fixture_payload(self, request_ref: str) -> bytes: ...


@runtime_checkable
class CaptureCredentialPort(Protocol):
    """Low-level credential boundary; capabilities are opaque and non-durable."""
    def resolve_fixture_credential(self, credential_ref: str) -> object: ...


@runtime_checkable
class CaptureScopePort(Protocol):
    def source_scope(self, scope_ref: str) -> SourceScopeRefV1 | None: ...
