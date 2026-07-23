"""P4-11 WriteProposal gateway through frozen Core command port."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from wiki_spike.memory_runtime.core_api import CommandEnvelope, CoreResult, MemoryCommandPort
from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import canonical_object, content_id, verify_content_id, ensure_no_secret_keys, hex64, nonempty, safe_code, string_tuple

WRITE_PROPOSAL_VERSION = "phase4-write-proposal-v1"


@dataclass(frozen=True)
class WriteProposal:
    write_proposal_version: str
    proposal_id: str
    operation_id: str
    workspace_id: str
    actor_id: str
    expected_generation_id: str | None
    proposal_type: str
    payload: dict[str, object]
    engine_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]

    @classmethod
    def create(cls, **kwargs: object) -> "WriteProposal":
        normalized = canonical_object(kwargs.pop("payload"), "payload")
        ensure_no_secret_keys(normalized, label="write proposal")
        engines = tuple(sorted(set(kwargs.pop("engine_refs"))))
        evidence = tuple(sorted(set(kwargs.pop("evidence_refs"))))
        payload = {
            "write_proposal_version": WRITE_PROPOSAL_VERSION,
            **kwargs,
            "payload": normalized,
            "engine_refs": list(engines),
            "evidence_refs": list(evidence),
        }
        return cls(proposal_id=content_id("wiki.runtime.write-proposal.v1", payload), payload=normalized, engine_refs=engines, evidence_refs=evidence, **{k: v for k, v in payload.items() if k not in {"payload", "engine_refs", "evidence_refs"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.write_proposal_version != WRITE_PROPOSAL_VERSION:
            raise InvalidContractValue("unsupported write proposal version")
        hex64(self.operation_id, "operation_id")
        for field in ("workspace_id", "actor_id"):
            nonempty(getattr(self, field), field)
        safe_code(self.proposal_type, "proposal_type")
        ensure_no_secret_keys(self.payload, label="write proposal")
        string_tuple(self.engine_refs, "engine_refs", allow_empty=False, sorted_unique=True)
        string_tuple(self.evidence_refs, "evidence_refs", sorted_unique=True)
        verify_content_id(self.proposal_id, "wiki.runtime.write-proposal.v1", self.to_mapping(), "proposal_id", "write proposal_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "write_proposal_version": self.write_proposal_version,
            "proposal_id": self.proposal_id,
            "operation_id": self.operation_id,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "expected_generation_id": self.expected_generation_id,
            "proposal_type": self.proposal_type,
            "payload": self.payload,
            "engine_refs": list(self.engine_refs),
            "evidence_refs": list(self.evidence_refs),
        }


class ProposalReceiptStore(Protocol):
    def get(self, workspace_id: str, proposal_id: str) -> CoreResult | None: ...
    def put(self, workspace_id: str, proposal_id: str, result: CoreResult) -> None: ...


class InMemoryProposalReceiptStore:
    def __init__(self) -> None:
        self._values: dict[tuple[str, str], CoreResult] = {}

    def get(self, workspace_id: str, proposal_id: str) -> CoreResult | None:
        return self._values.get((workspace_id, proposal_id))

    def put(self, workspace_id: str, proposal_id: str, result: CoreResult) -> None:
        self._values.setdefault((workspace_id, proposal_id), result)


class WriteProposalGateway:
    def __init__(self, core: MemoryCommandPort, receipts: ProposalReceiptStore | None = None) -> None:
        self.core = core
        self.receipts = receipts or InMemoryProposalReceiptStore()

    def submit(self, proposal: WriteProposal) -> CoreResult:
        existing = self.receipts.get(proposal.workspace_id, proposal.proposal_id)
        if existing is not None:
            return existing
        command = CommandEnvelope.create(
            command_id=proposal.proposal_id,
            idempotency_key=proposal.proposal_id,
            workspace_id=proposal.workspace_id,
            actor_id=proposal.actor_id,
            command_type=f"proposal.{proposal.proposal_type}",
            expected_generation_id=proposal.expected_generation_id,
            payload={
                "operation_id": proposal.operation_id,
                "proposal_id": proposal.proposal_id,
                "proposal": proposal.payload,
                "engine_refs": list(proposal.engine_refs),
                "evidence_refs": list(proposal.evidence_refs),
            },
        )
        result = self.core.execute(command)
        if result.status != "retry_later":
            self.receipts.put(proposal.workspace_id, proposal.proposal_id, result)
        return result


__all__ = [
    "WRITE_PROPOSAL_VERSION", "WriteProposal", "ProposalReceiptStore",
    "InMemoryProposalReceiptStore", "WriteProposalGateway",
]
