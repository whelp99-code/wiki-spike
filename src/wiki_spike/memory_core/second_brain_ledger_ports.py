"""Stage-3 ledger and recall ports. Runtime adapters implement these outside Core."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable

from .second_brain_ledger_contracts import (
    LedgerCommandV2,
    LedgerReceiptV2,
    RecallServeSnapshotV2,
    RecallContinuationV2,
    RecallSnapshotRequestV2,
    make_recall_continuation_v2,
    make_recall_snapshot_v2,
    validate_recall_snapshot_acquisition,
)


@runtime_checkable
class LedgerCommandPort(Protocol):
    """Atomic append boundary; capability verification is part of command acceptance."""
    def append_ledger_command(self, command: LedgerCommandV2) -> LedgerReceiptV2: ...


@runtime_checkable
class AtomicRecallSnapshotPort(Protocol):
    """One atomic Runtime boundary returning only a validated acquisition wrapper."""
    def acquire_recall_snapshot(self, request: RecallSnapshotRequestV2) -> "ValidatedRecallSnapshotAcquisitionV2": ...


@dataclass(frozen=True, slots=True, init=False)
class ValidatedRecallSnapshotAcquisitionV2:
    """Core-owned, non-bypassable request/result proof returned by the port."""
    _request: RecallSnapshotRequestV2
    _snapshot: RecallServeSnapshotV2

    def __init__(self, request: RecallSnapshotRequestV2, snapshot: RecallServeSnapshotV2) -> None:
        if not isinstance(request, RecallSnapshotRequestV2):
            raise TypeError("request must be RecallSnapshotRequestV2")
        object.__setattr__(self, "_request", request)
        object.__setattr__(self, "_snapshot", validate_recall_snapshot_acquisition(request, snapshot))

    @property
    def request(self) -> RecallSnapshotRequestV2:
        return self._request

    @property
    def snapshot(self) -> RecallServeSnapshotV2:
        return self._snapshot


@runtime_checkable
class CanonicalRecallSnapshotFactoryV2(Protocol):
    """Core factory: adapters cannot expose an unvalidated acquisition result."""
    def acquire(self, request: RecallSnapshotRequestV2) -> ValidatedRecallSnapshotAcquisitionV2: ...

    @staticmethod
    def validated(request: RecallSnapshotRequestV2, result: RecallServeSnapshotV2) -> ValidatedRecallSnapshotAcquisitionV2:
        return ValidatedRecallSnapshotAcquisitionV2(request, result)

    @staticmethod
    def continuation(body: Mapping[str, Any]) -> RecallContinuationV2:
        return make_recall_continuation_v2(body)

    @staticmethod
    def snapshot(body: Mapping[str, Any]) -> RecallServeSnapshotV2:
        return make_recall_snapshot_v2(body)
