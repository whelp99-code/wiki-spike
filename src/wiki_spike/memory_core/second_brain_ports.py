"""Core-owned typed ports for Stage-0 Second Brain contract evaluation."""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class TypedSourceReader(Protocol):
    """Reads a named source profile without exposing an adapter implementation."""

    def read(self, source_profile: str, checkpoint: str | None = None) -> bytes: ...


@runtime_checkable
class SourceCheckpointStore(Protocol):
    """Persists opaque source-reader checkpoints."""

    def load_checkpoint(self, source_profile: str) -> str | None: ...

    def save_checkpoint(self, source_profile: str, checkpoint: str) -> None: ...


@runtime_checkable
class FilesystemClient(Protocol):
    """Low-level filesystem capability required by Core-owned implementations."""

    def read_bytes(self, path: str) -> bytes: ...

    def write_bytes(self, path: str, value: bytes) -> None: ...


@runtime_checkable
class ApiClient(Protocol):
    """Low-level API capability with no application or infrastructure dependency."""

    def request(self, method: str, url: str, body: bytes | None = None) -> bytes: ...


@runtime_checkable
class CredentialClient(Protocol):
    """Resolves a credential by stable reference, never by raw secret value."""

    def resolve(self, credential_ref: str) -> bytes: ...
