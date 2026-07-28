"""MCP transport with exactly the same closed V2 semantics as the API."""
from __future__ import annotations

from wiki_spike.composition.api_v2 import CapabilityUseV2, SecondBrainApiV2, V2Result
from wiki_spike.composition.second_brain_product import SecondBrainProductV2
from wiki_spike.memory_core.second_brain_ledger_contracts import LedgerCommandV2, RecallSnapshotRequestV2


class SecondBrainMcpV2:
    """A deliberately thin transport alias, preventing API/MCP policy drift."""
    def __init__(self, product: SecondBrainProductV2) -> None:
        self._api = SecondBrainApiV2(product)

    def command(self, use: CapabilityUseV2, command: LedgerCommandV2) -> V2Result:
        return self._api.command(use, command)

    def recall(self, use: CapabilityUseV2, request: RecallSnapshotRequestV2) -> V2Result:
        return self._api.recall(use, request)

    def citation(self, use: CapabilityUseV2, request: RecallSnapshotRequestV2, candidate_ref: str) -> V2Result:
        return self._api.citation(use, request, candidate_ref)

    def status(self, use: CapabilityUseV2) -> V2Result:
        return self._api.status(use)
