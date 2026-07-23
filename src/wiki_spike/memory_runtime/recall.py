"""P4-07 citation-complete Recall Engine."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .evidence_pack import EvidencePack
from .service_contracts import body_digest, content_id, verify_content_id, hex64, modality, nonempty, string_tuple
from .verification import VerificationClaim, VerificationOutcome, VerificationPipeline

RECALL_DRAFT_VERSION = "phase4-recall-draft-v1"
RECALL_STATEMENT_VERSION = "phase4-recall-statement-v1"
RECALL_ANSWER_VERSION = "phase4-recall-answer-v1"


@dataclass(frozen=True)
class RecallDraftStatement:
    text: str
    modality: str
    evidence_atom_ids: tuple[str, ...]
    locator_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        nonempty(self.text, "text", 16000)
        modality(self.modality)
        string_tuple(self.evidence_atom_ids, "evidence_atom_ids", sorted_unique=True)
        string_tuple(self.locator_refs, "locator_refs", sorted_unique=True)


@dataclass(frozen=True)
class RecallStatement:
    recall_statement_version: str
    statement_id: str
    text: str
    text_digest: str
    modality: str
    support_refs: tuple[str, ...]
    locator_refs: tuple[str, ...]
    verification_outcome_id: str
    conflict: bool

    @classmethod
    def create(
        cls,
        *,
        text: str,
        modality: str,
        support_refs: Sequence[str],
        locator_refs: Sequence[str],
        verification_outcome_id: str,
        conflict: bool,
    ) -> "RecallStatement":
        refs = tuple(sorted(set(support_refs)))
        locators = tuple(sorted(set(locator_refs)))
        digest = body_digest("wiki.runtime.recall-statement-text.v1", text)
        payload = {
            "recall_statement_version": RECALL_STATEMENT_VERSION,
            "text": text,
            "text_digest": digest,
            "modality": modality,
            "support_refs": list(refs),
            "locator_refs": list(locators),
            "verification_outcome_id": verification_outcome_id,
            "conflict": conflict,
        }
        return cls(statement_id=content_id("wiki.runtime.recall-statement.v1", payload), text_digest=digest, support_refs=refs, locator_refs=locators, **{k: v for k, v in payload.items() if k not in {"text_digest", "support_refs", "locator_refs"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.recall_statement_version != RECALL_STATEMENT_VERSION:
            raise InvalidContractValue("unsupported recall statement version")
        nonempty(self.text, "text", 16000)
        if self.text_digest != body_digest("wiki.runtime.recall-statement-text.v1", self.text):
            raise InvalidContractValue("recall statement text_digest mismatch")
        modality(self.modality)
        string_tuple(self.support_refs, "support_refs", allow_empty=False, sorted_unique=True)
        string_tuple(self.locator_refs, "locator_refs", allow_empty=False, sorted_unique=True)
        hex64(self.verification_outcome_id, "verification_outcome_id")
        if not isinstance(self.conflict, bool):
            raise InvalidContractValue("conflict must be boolean")
        verify_content_id(self.statement_id, "wiki.runtime.recall-statement.v1", self.to_mapping(), "statement_id", "recall statement_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "recall_statement_version": self.recall_statement_version,
            "statement_id": self.statement_id,
            "text": self.text,
            "text_digest": self.text_digest,
            "modality": self.modality,
            "support_refs": list(self.support_refs),
            "locator_refs": list(self.locator_refs),
            "verification_outcome_id": self.verification_outcome_id,
            "conflict": self.conflict,
        }


@dataclass(frozen=True)
class RecallAnswer:
    recall_answer_version: str
    answer_id: str
    operation_id: str
    generation_id: str
    statements: tuple[RecallStatement, ...]
    stale: bool
    degraded: bool
    abstained: bool
    reason_codes: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        generation_id: str,
        statements: Sequence[RecallStatement],
        stale: bool,
        degraded: bool,
        abstained: bool,
        reason_codes: Sequence[str],
    ) -> "RecallAnswer":
        values = tuple(statements)
        reasons = tuple(sorted(set(reason_codes)))
        payload = {
            "recall_answer_version": RECALL_ANSWER_VERSION,
            "operation_id": operation_id,
            "generation_id": generation_id,
            "statements": [value.to_mapping() for value in values],
            "stale": stale,
            "degraded": degraded,
            "abstained": abstained,
            "reason_codes": list(reasons),
        }
        return cls(answer_id=content_id("wiki.runtime.recall-answer.v1", payload), statements=values, reason_codes=reasons, **{k: v for k, v in payload.items() if k not in {"statements", "reason_codes"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.recall_answer_version != RECALL_ANSWER_VERSION:
            raise InvalidContractValue("unsupported recall answer version")
        hex64(self.operation_id, "operation_id")
        nonempty(self.generation_id, "generation_id")
        if self.abstained and self.statements:
            raise InvalidContractValue("abstained answer must not contain statements")
        if not self.abstained and not self.statements:
            raise InvalidContractValue("non-abstained answer requires statements")
        string_tuple(self.reason_codes, "reason_codes", sorted_unique=True, codes=True)
        verify_content_id(self.answer_id, "wiki.runtime.recall-answer.v1", self.to_mapping(), "answer_id", "recall answer_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "recall_answer_version": self.recall_answer_version,
            "answer_id": self.answer_id,
            "operation_id": self.operation_id,
            "generation_id": self.generation_id,
            "statements": [value.to_mapping() for value in self.statements],
            "stale": self.stale,
            "degraded": self.degraded,
            "abstained": self.abstained,
            "reason_codes": list(self.reason_codes),
        }


class RecallEngine:
    def __init__(self, verification: VerificationPipeline) -> None:
        self.verification = verification

    def answer(
        self,
        *,
        operation_id: str,
        pack: EvidencePack,
        drafts: Sequence[RecallDraftStatement],
        stale: bool = False,
    ) -> RecallAnswer:
        atom_by_id = {atom.atom_id: atom for atom in pack.atoms}
        conflict_atoms = {atom_id for _, atom_ids in pack.conflict_groups for atom_id in atom_ids}
        statements: list[RecallStatement] = []
        reasons: set[str] = set()
        for draft in drafts:
            digest = body_digest("wiki.runtime.recall-statement-text.v1", draft.text)
            claim = VerificationClaim.create(
                operation_id=operation_id,
                statement_digest=digest,
                modality=draft.modality,
                evidence_atom_ids=draft.evidence_atom_ids,
                locator_refs=draft.locator_refs,
            )
            outcome = self.verification.verify(claim, pack)
            if not outcome.accepted:
                reasons.update(outcome.reason_codes or ("statement_not_verified",))
                continue
            referenced = [atom_by_id[item] for item in draft.evidence_atom_ids if item in atom_by_id]
            statements.append(
                RecallStatement.create(
                    text=draft.text,
                    modality=outcome.output_modality,
                    support_refs=draft.evidence_atom_ids,
                    locator_refs=draft.locator_refs,
                    verification_outcome_id=outcome.outcome_id,
                    conflict=any(atom.atom_id in conflict_atoms for atom in referenced),
                )
            )
        if not statements:
            reasons.add("no_verified_statement")
            return RecallAnswer.create(
                operation_id=operation_id,
                generation_id=pack.generation_id,
                statements=(),
                stale=stale,
                degraded=pack.degraded,
                abstained=True,
                reason_codes=sorted(reasons),
            )
        return RecallAnswer.create(
            operation_id=operation_id,
            generation_id=pack.generation_id,
            statements=statements,
            stale=stale,
            degraded=pack.degraded,
            abstained=False,
            reason_codes=sorted(reasons),
        )


__all__ = [
    "RECALL_DRAFT_VERSION", "RECALL_STATEMENT_VERSION", "RECALL_ANSWER_VERSION",
    "RecallDraftStatement", "RecallStatement", "RecallAnswer", "RecallEngine",
]
