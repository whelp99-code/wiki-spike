"""Storage-independent Protocol interfaces for Phase 3 core boundaries."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .contracts import AcceptedChangeSet, CommandEnvelope, CoreResult, OperationalEvent, QueryEnvelope


@runtime_checkable
class MemoryCommandPort(Protocol):
    def execute(self, command: CommandEnvelope) -> CoreResult: ...


@runtime_checkable
class MemoryQueryPort(Protocol):
    def query(self, query: QueryEnvelope) -> CoreResult: ...


@runtime_checkable
class ChangeSetPublicationPort(Protocol):
    def publish(self, changeset: AcceptedChangeSet) -> CoreResult: ...


@runtime_checkable
class OperationalEventSink(Protocol):
    def append(self, event: OperationalEvent) -> None: ...
