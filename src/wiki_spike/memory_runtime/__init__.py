"""Phase 4 Memory Runtime package boundary.

P4-00 intentionally exposes only the pinned Phase 3 Core facade.  Runtime
request/answer contracts and orchestration state machines are introduced by
P4-01 and later PRs.
"""
from .core_api import (
    PHASE3_CONTRACT_RELEASE,
    PHASE3_G3_CHECKPOINT_ID,
    RUNTIME_BOUNDARY_VERSION,
    AcceptedChangeSet,
    ChangeSetPublicationPort,
    CommandEnvelope,
    CoreResult,
    JsonValue,
    MemoryCommandPort,
    MemoryQueryPort,
    OperationalEvent,
    OperationalEventSink,
    ProjectionPort,
    QueryEnvelope,
)

__all__ = [
    "PHASE3_CONTRACT_RELEASE",
    "PHASE3_G3_CHECKPOINT_ID",
    "RUNTIME_BOUNDARY_VERSION",
    "AcceptedChangeSet",
    "ChangeSetPublicationPort",
    "CommandEnvelope",
    "CoreResult",
    "JsonValue",
    "MemoryCommandPort",
    "MemoryQueryPort",
    "OperationalEvent",
    "OperationalEventSink",
    "ProjectionPort",
    "QueryEnvelope",
]
