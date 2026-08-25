"""Inert Stage-2 capture port shapes; implementations belong outside memory_core."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .second_brain_capture_contracts import (
    CapturedItemV1,
    CaptureItemReceiptV1,
    CapturePersistenceAggregateV1,
    EncryptedContentRefV1,
    EncryptedNativeMappingRefV1,
    SourceScopeRefV1,
)
from .second_brain_source_registry_contracts import (
    EncryptedSourceDescriptorV1,
    EncryptedSourceRegistryEntryV1,
    SourceProfileV1,
)


@runtime_checkable
class ConnectorSourceReaderPortV1(Protocol):
    """V1 typed-connector boundary for exact capture evidence."""

    def read_fixture_capture_items(
        self, scope: SourceScopeRefV1, scan_epoch: str
    ) -> tuple[CapturedItemV1, ...]: ...


@runtime_checkable
class ConnectorSourceReaderPort(ConnectorSourceReaderPortV1, Protocol):
    """Compatibility name for the frozen Stage-2 V1 reader boundary."""


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
class SourceDescriptorClientPortV1(Protocol):
    """Low-level descriptor client; only trusted opaque root refs cross Core."""

    def describe_and_seal_root(self, root_ref: str) -> EncryptedSourceDescriptorV1: ...


@runtime_checkable
class SourceCheckpointClientPortV1(Protocol):
    """Reads a checkpoint by opaque source identity without opening a source root."""

    def read_checkpoint_ref(self, source_ref: str) -> str | None: ...


@runtime_checkable
class SourceApiClientPortV1(Protocol):
    """V1 low-level API client with no URL or native identifier surface."""

    def read_fixture_payload(self, request_ref: str) -> bytes: ...


@runtime_checkable
class SourceCredentialClientPortV1(Protocol):
    """V1 low-level credential client returning only an opaque capability."""

    def resolve_credential_capability(self, credential_ref: str) -> bytes: ...


@runtime_checkable
class EncryptedSourceRegistryPortV1(Protocol):
    """Persists only encrypted descriptor references and opaque identities."""

    def read_entry(
        self, workspace_ref: str, profile: SourceProfileV1
    ) -> EncryptedSourceRegistryEntryV1 | None: ...

    def write_entry(self, entry: EncryptedSourceRegistryEntryV1) -> None: ...


@runtime_checkable
class CaptureApiPort(SourceApiClientPortV1, Protocol):
    """Compatibility name for the V1 low-level fixture API client."""


@runtime_checkable
class CaptureCredentialPort(Protocol):
    """Legacy low-level credential boundary; capabilities are opaque and non-durable."""

    def resolve_fixture_credential(self, credential_ref: str) -> bytes: ...


@runtime_checkable
class CaptureScopePort(Protocol):
    def source_scope(self, scope_ref: str) -> SourceScopeRefV1 | None: ...
