"""Pinned Phase 3 Core surface available to the Phase 4 Runtime.

Phase 4 code must import Core contracts through this module.  The frozen G3
release does not expose a general ``ProjectionPort`` in ``memory_core.ports``;
therefore P4-00 defines the narrow runtime-facing projection facade below
without changing the signed Phase 3 contract.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from wiki_spike.memory_core.contracts import (
    AcceptedChangeSet,
    CommandEnvelope,
    CoreResult,
    JsonValue,
    OperationalEvent,
    QueryEnvelope,
)
from wiki_spike.memory_core.ports import (
    ChangeSetPublicationPort,
    MemoryCommandPort,
    MemoryQueryPort,
    OperationalEventSink,
)

PHASE3_CONTRACT_RELEASE = "phase3-core-v1.0.0"
PHASE3_G3_CHECKPOINT_ID = "379297f172ebf60a30dd4bce8b8e1dc139ff249ea72b2561879af5807afed832"
RUNTIME_BOUNDARY_VERSION = "phase4-runtime-boundary-v1"


@runtime_checkable
class ProjectionPort(Protocol):
    """Phase 4 facade for generation-pinned projection reads.

    This is deliberately a Runtime-owned facade.  Implementations may adapt the
    frozen Phase 3 projection contracts, but callers cannot import a projection
    implementation or storage engine directly.
    """

    def query_projection(self, query: QueryEnvelope) -> CoreResult: ...


__all__ = [
    "PHASE3_CONTRACT_RELEASE",
    "PHASE3_G3_CHECKPOINT_ID",
    "RUNTIME_BOUNDARY_VERSION",
    "AcceptedChangeSet",
    "CommandEnvelope",
    "CoreResult",
    "JsonValue",
    "OperationalEvent",
    "QueryEnvelope",
    "ChangeSetPublicationPort",
    "MemoryCommandPort",
    "MemoryQueryPort",
    "OperationalEventSink",
    "ProjectionPort",
]
