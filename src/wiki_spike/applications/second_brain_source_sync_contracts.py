"""Typed contracts for bounded source synchronization."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Event
from time import monotonic
from typing import Protocol, assert_never

from wiki_spike.memory_core.second_brain_outcome_contracts import (
    OperationStateV1,
    OutcomeCodeV1,
    SourceItemV1,
)
from wiki_spike.memory_core.second_brain_source_profiles import ParserCapabilityV2, SourceIdentityV2


@dataclass(frozen=True, slots=True)
class SourceSyncRequestError(ValueError):
    detail: str

    def __str__(self) -> str:
        return self.detail


@dataclass(frozen=True, slots=True)
class SourceSyncCheckpointConflict(Exception):
    source_ref: str

    def __str__(self) -> str:
        return f"source checkpoint changed during operation: {self.source_ref}"


@dataclass(frozen=True, slots=True)
class SourceAddRequestV1:
    profile: SourceIdentityV2
    root: Path
    capabilities: tuple[ParserCapabilityV2, ...]

    def __post_init__(self) -> None:
        if not self.root.is_absolute():
            raise SourceSyncRequestError("source root must be absolute")


@dataclass(frozen=True, slots=True)
class SourceListRequestV1:
    enabled: bool | None = None


@dataclass(frozen=True, slots=True)
class SourceRefRequestV1:
    source_ref: str

    def __post_init__(self) -> None:
        if not self.source_ref or len(self.source_ref.encode()) > 128:
            raise SourceSyncRequestError("source_ref must be a bounded opaque reference")


@dataclass(frozen=True, slots=True)
class SourceWorkItemV1:
    item_ref: str
    revision_ref: str
    tombstone: bool
    payload: bytes


@dataclass(frozen=True, slots=True)
class SourceSyncChangeV1:
    item_ref: str
    revision_ref: str
    tombstone: bool


@dataclass(frozen=True, slots=True)
class SourceScanV1:
    checkpoint_ref: str
    lag_seconds: str
    items: tuple[SourceWorkItemV1, ...]

    def __post_init__(self) -> None:
        if len(self.items) > 1_000:
            raise SourceSyncRequestError("source scan exceeds the bounded queue")
        if not self.lag_seconds.isdecimal():
            raise SourceSyncRequestError("source lag must be a canonical decimal")


class SourceSyncAdapterErrorV1(StrEnum):
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    SYNC_TIMEOUT = "SYNC_TIMEOUT"
    FORMAT_UNSUPPORTED = "FORMAT_UNSUPPORTED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    SOURCE_INCOMPLETE = "SOURCE_INCOMPLETE"
    SOURCE_COLLISION = "SOURCE_COLLISION"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True, slots=True)
class SourceSyncAdapterFailureV1:
    error: SourceSyncAdapterErrorV1

    @property
    def retryable(self) -> bool:
        match self.error:
            case SourceSyncAdapterErrorV1.DEPENDENCY_UNAVAILABLE | SourceSyncAdapterErrorV1.SYNC_TIMEOUT | SourceSyncAdapterErrorV1.SOURCE_MUTATED | SourceSyncAdapterErrorV1.SOURCE_INCOMPLETE:
                return True
            case SourceSyncAdapterErrorV1.FORMAT_UNSUPPORTED | SourceSyncAdapterErrorV1.LIMIT_EXCEEDED | SourceSyncAdapterErrorV1.SOURCE_COLLISION | SourceSyncAdapterErrorV1.QUARANTINED:
                return False
            case unreachable:
                assert_never(unreachable)

    def outcome_code(self) -> OutcomeCodeV1:
        match self.error:
            case SourceSyncAdapterErrorV1.DEPENDENCY_UNAVAILABLE:
                return OutcomeCodeV1.DEPENDENCY_UNAVAILABLE
            case SourceSyncAdapterErrorV1.SYNC_TIMEOUT:
                return OutcomeCodeV1.SYNC_TIMEOUT
            case SourceSyncAdapterErrorV1.FORMAT_UNSUPPORTED:
                return OutcomeCodeV1.FORMAT_UNSUPPORTED
            case SourceSyncAdapterErrorV1.LIMIT_EXCEEDED:
                return OutcomeCodeV1.LIMIT_EXCEEDED
            case SourceSyncAdapterErrorV1.SOURCE_MUTATED:
                return OutcomeCodeV1.SOURCE_MUTATED
            case SourceSyncAdapterErrorV1.SOURCE_INCOMPLETE:
                return OutcomeCodeV1.SOURCE_INCOMPLETE
            case SourceSyncAdapterErrorV1.SOURCE_COLLISION:
                return OutcomeCodeV1.SOURCE_COLLISION
            case SourceSyncAdapterErrorV1.QUARANTINED:
                return OutcomeCodeV1.QUARANTINED
            case unreachable:
                assert_never(unreachable)


type SourceScanResultV1 = SourceScanV1 | SourceSyncAdapterFailureV1
type SourcePrepareResultV1 = SourceSyncChangeV1 | SourceSyncAdapterFailureV1


@dataclass(frozen=True, slots=True)
class SourceSyncScheduleSuccessV1:
    scan: SourceScanV1
    changes: tuple[SourceSyncChangeV1, ...]


type SourceSyncScheduleResultV1 = SourceSyncScheduleSuccessV1 | SourceSyncAdapterFailureV1


@dataclass(frozen=True, slots=True)
class SourceSyncLimitsV1:
    file_timeout_seconds: float = 30.0
    source_timeout_seconds: float = 900.0
    workers: int = 4
    queue_size: int = 1_000

    def __post_init__(self) -> None:
        if self.file_timeout_seconds <= 0 or self.source_timeout_seconds <= 0:
            raise SourceSyncRequestError("source sync timeouts must be positive")
        if self.workers < 1 or self.workers > 4 or self.queue_size < 1 or self.queue_size > 1_000:
            raise SourceSyncRequestError("source sync scheduler bounds are invalid")


@dataclass(frozen=True, slots=True)
class SourceSyncTaskContextV1:
    """Cooperative adapter deadline; adapters must return when cancellation is signalled."""

    deadline_monotonic: float
    _cancelled: Event

    @classmethod
    def create(cls, timeout_seconds: float) -> SourceSyncTaskContextV1:
        return cls(monotonic() + timeout_seconds, Event())

    def child(self, timeout_seconds: float) -> SourceSyncTaskContextV1:
        return SourceSyncTaskContextV1(min(self.deadline_monotonic, monotonic() + timeout_seconds), self._cancelled)

    def cancel(self) -> None:
        self._cancelled.set()

    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    def wait_cancelled(self) -> None:
        self._cancelled.wait()

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline_monotonic - monotonic())


@dataclass(frozen=True, slots=True)
class SourceSyncRecordV1:
    source_ref: str
    profile: str
    enabled: bool
    source_state: OperationStateV1
    checkpoint_ref: str | None
    preview_checkpoint_ref: str | None
    lag_seconds: str
    error_code: str | None
    error_retryable: bool | None
    capabilities: tuple[str, ...]

    def public_item(self) -> SourceItemV1:
        visible_checkpoint = self.preview_checkpoint_ref or self.checkpoint_ref
        return SourceItemV1(
            self.source_ref, self.profile, self.enabled, self.source_state,
            visible_checkpoint, self.lag_seconds, self.error_code, self.capabilities,
        )


@dataclass(frozen=True, slots=True)
class SourceSyncStatusUpdateV1:
    source_ref: str
    expected_checkpoint_ref: str | None
    source_state: OperationStateV1
    preview_checkpoint_ref: str | None
    lag_seconds: str
    error_code: str | None
    error_retryable: bool | None


@dataclass(frozen=True, slots=True)
class SourceSyncCommitV1:
    source_ref: str
    previous_checkpoint_ref: str | None
    scan: SourceScanV1
    changes: tuple[SourceSyncChangeV1, ...]


class SourceSyncAdapterPort(Protocol):
    """Adapter contract: observe context cancellation and return before its deadline."""

    def scan(
        self, source_ref: str, checkpoint_ref: str | None, context: SourceSyncTaskContextV1
    ) -> SourceScanResultV1: ...

    def prepare(self, item: SourceWorkItemV1, context: SourceSyncTaskContextV1) -> SourcePrepareResultV1: ...


class SourceSyncRepositoryPort(Protocol):
    def add(self, request: SourceAddRequestV1) -> SourceSyncRecordV1: ...
    def list(self) -> tuple[SourceSyncRecordV1, ...]: ...
    def get(self, source_ref: str) -> SourceSyncRecordV1 | None: ...
    def disable(self, source_ref: str) -> SourceSyncRecordV1: ...
    def update_status(self, command: SourceSyncStatusUpdateV1) -> SourceSyncRecordV1: ...
    def commit(self, command: SourceSyncCommitV1) -> SourceSyncRecordV1: ...
