"""Application boundary for the closed Stage-3 ledger ports."""
from __future__ import annotations

from wiki_spike.memory_core.second_brain_ledger_contracts import LedgerCommandV2, LedgerReceiptV2, RecallSnapshotRequestV2
from wiki_spike.memory_core.second_brain_ledger_ports import AtomicRecallSnapshotPort, LedgerCommandPort, ValidatedRecallSnapshotAcquisitionV2


class SecondBrainLedgerService:
    """Thin application facade; no projection or transport write path exists."""
    def __init__(self, ledger: LedgerCommandPort, snapshots: AtomicRecallSnapshotPort) -> None:
        self._ledger = ledger
        self._snapshots = snapshots

    def append(self, command: LedgerCommandV2) -> LedgerReceiptV2:
        return self._ledger.append_ledger_command(command)

    def acquire(self, request: RecallSnapshotRequestV2) -> ValidatedRecallSnapshotAcquisitionV2:
        return self._snapshots.acquire_recall_snapshot(request)
