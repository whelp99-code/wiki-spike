"""Inert Stage-2 capture port shapes; implementations belong outside memory_core."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .second_brain_capture_contracts import (
    CapturePersistenceAggregateV1,
    CapturedItemV1,
    CaptureItemReceiptV1,
    EncryptedContentRefV1,
    EncryptedNativeMappingRefV1,
    SourceScopeRefV1,
)


@runtime_checkable
class ConnectorSourceReaderPort(Protocol):
    """Connector boundary returning exact capture identity and ciphertext evidence for a scan epoch."""
    def read_fixture_capture_items(self, scope: SourceScopeRefV1, scan_epoch: str) -> tuple[CapturedItemV1, ...]: ...


@runtime_checkable
class EncryptedNativeMappingSealerPort(Protocol):
    """Seals native mappings and returns a ref bound to the supplied capture identity."""
    def seal_native_mapping(self, scope: SourceScopeRefV1, capture_ref: str, native_mapping: bytes) -> EncryptedNativeMappingRefV1: ...
@runtime_checkable
class EncryptedContentSealerPort(Protocol):
    """Seals capture content and returns its authority-issued stable identity ref."""
    def seal_content(self, scope: SourceScopeRefV1, capture_ref: str, content: bytes) -> EncryptedContentRefV1: ...



@runtime_checkable
class CaptureReaderPort(Protocol):
    def read_capture_receipt(self, capture_ref: str) -> CaptureItemReceiptV1 | None: ...


@runtime_checkable
class AtomicCapturePersistencePort(Protocol):
    """The sole application-facing write operation for a complete capture aggregate."""
    def persist_capture_aggregate(self, aggregate: CapturePersistenceAggregateV1) -> None: ...


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
