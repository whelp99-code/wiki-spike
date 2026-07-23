"""P4-08 Decision Engine with exact source-span and hedge preservation."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import body_digest, canonical_int, content_id, verify_content_id, hex64, modality, nonempty, string_tuple

DECISION_INPUT_VERSION = "phase4-decision-input-v1"
DECISION_CANDIDATE_VERSION = "phase4-decision-candidate-v1"


class DecisionKind(str, Enum):
    EXPLICIT = "explicit"
    PROPOSAL = "proposal"
    PREFERENCE = "preference"
    AMBIGUOUS = "ambiguous"


class ProposedDecisionStatus(str, Enum):
    DECIDED = "decided"
    PROPOSED = "proposed"
    PREFERENCE = "preference"
    NEEDS_CLARIFICATION = "needs_clarification"


@dataclass(frozen=True)
class DecisionInput:
    decision_input_version: str
    input_id: str
    operation_id: str
    source_ref: str
    source_text: str
    start_offset: str
    end_offset: str
    classification_hint: str
    modality: str
    alternative_refs: tuple[str, ...]
    rationale_refs: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        source_ref: str,
        source_text: str,
        start_offset: str,
        end_offset: str,
        classification_hint: str,
        modality: str,
        alternative_refs: Sequence[str] = (),
        rationale_refs: Sequence[str] = (),
    ) -> "DecisionInput":
        alternatives = tuple(sorted(set(alternative_refs)))
        rationale = tuple(sorted(set(rationale_refs)))
        payload = {
            "decision_input_version": DECISION_INPUT_VERSION,
            "operation_id": operation_id,
            "source_ref": source_ref,
            "source_text": source_text,
            "start_offset": start_offset,
            "end_offset": end_offset,
            "classification_hint": classification_hint,
            "modality": modality,
            "alternative_refs": list(alternatives),
            "rationale_refs": list(rationale),
        }
        return cls(input_id=content_id("wiki.runtime.decision-input.v1", payload), alternative_refs=alternatives, rationale_refs=rationale, **{k: v for k, v in payload.items() if k not in {"alternative_refs", "rationale_refs"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.decision_input_version != DECISION_INPUT_VERSION:
            raise InvalidContractValue("unsupported decision input version")
        hex64(self.operation_id, "operation_id")
        nonempty(self.source_ref, "source_ref")
        nonempty(self.source_text, "source_text", 32000)
        start = canonical_int(self.start_offset, "start_offset", maximum=len(self.source_text))
        end = canonical_int(self.end_offset, "end_offset", maximum=len(self.source_text))
        if not start < end:
            raise InvalidContractValue("source span must have start < end")
        try:
            DecisionKind(self.classification_hint)
        except ValueError as exc:
            raise InvalidContractValue("unsupported decision classification") from exc
        modality(self.modality)
        string_tuple(self.alternative_refs, "alternative_refs", sorted_unique=True)
        string_tuple(self.rationale_refs, "rationale_refs", sorted_unique=True)
        verify_content_id(self.input_id, "wiki.runtime.decision-input.v1", self.to_mapping(), "input_id", "decision input_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "decision_input_version": self.decision_input_version,
            "input_id": self.input_id,
            "operation_id": self.operation_id,
            "source_ref": self.source_ref,
            "source_text": self.source_text,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "classification_hint": self.classification_hint,
            "modality": self.modality,
            "alternative_refs": list(self.alternative_refs),
            "rationale_refs": list(self.rationale_refs),
        }

    @property
    def exact_span(self) -> str:
        return self.source_text[int(self.start_offset):int(self.end_offset)]


@dataclass(frozen=True)
class DecisionCandidate:
    decision_candidate_version: str
    candidate_id: str
    operation_id: str
    source_ref: str
    source_span: str
    source_span_digest: str
    start_offset: str
    end_offset: str
    kind: str
    proposed_status: str
    modality: str
    alternative_refs: tuple[str, ...]
    rationale_refs: tuple[str, ...]
    requires_clarification: bool
    reason_codes: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        source_ref: str,
        source_span: str,
        start_offset: str,
        end_offset: str,
        kind: str,
        proposed_status: str,
        modality: str,
        alternative_refs: Sequence[str],
        rationale_refs: Sequence[str],
        requires_clarification: bool,
        reason_codes: Sequence[str],
    ) -> "DecisionCandidate":
        alternatives = tuple(sorted(set(alternative_refs)))
        rationale = tuple(sorted(set(rationale_refs)))
        reasons = tuple(sorted(set(reason_codes)))
        digest = body_digest("wiki.runtime.decision-span.v1", source_span)
        payload = {
            "decision_candidate_version": DECISION_CANDIDATE_VERSION,
            "operation_id": operation_id,
            "source_ref": source_ref,
            "source_span": source_span,
            "source_span_digest": digest,
            "start_offset": start_offset,
            "end_offset": end_offset,
            "kind": kind,
            "proposed_status": proposed_status,
            "modality": modality,
            "alternative_refs": list(alternatives),
            "rationale_refs": list(rationale),
            "requires_clarification": requires_clarification,
            "reason_codes": list(reasons),
        }
        return cls(candidate_id=content_id("wiki.runtime.decision-candidate.v1", payload), source_span_digest=digest, alternative_refs=alternatives, rationale_refs=rationale, reason_codes=reasons, **{k: v for k, v in payload.items() if k not in {"source_span_digest", "alternative_refs", "rationale_refs", "reason_codes"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.decision_candidate_version != DECISION_CANDIDATE_VERSION:
            raise InvalidContractValue("unsupported decision candidate version")
        hex64(self.operation_id, "operation_id")
        nonempty(self.source_ref, "source_ref")
        nonempty(self.source_span, "source_span", 32000)
        if self.source_span_digest != body_digest("wiki.runtime.decision-span.v1", self.source_span):
            raise InvalidContractValue("decision span digest mismatch")
        DecisionKind(self.kind)
        ProposedDecisionStatus(self.proposed_status)
        modality(self.modality)
        if self.proposed_status == ProposedDecisionStatus.DECIDED.value:
            if self.kind != DecisionKind.EXPLICIT.value or self.modality not in {"explicit", "asserted"}:
                raise InvalidContractValue("decided status requires explicit non-hedged evidence")
        if self.kind == DecisionKind.AMBIGUOUS.value and not self.requires_clarification:
            raise InvalidContractValue("ambiguous decision requires clarification")
        if self.kind != DecisionKind.AMBIGUOUS.value and self.requires_clarification:
            raise InvalidContractValue("resolved decision must not require clarification")
        verify_content_id(self.candidate_id, "wiki.runtime.decision-candidate.v1", self.to_mapping(), "candidate_id", "decision candidate_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "decision_candidate_version": self.decision_candidate_version,
            "candidate_id": self.candidate_id,
            "operation_id": self.operation_id,
            "source_ref": self.source_ref,
            "source_span": self.source_span,
            "source_span_digest": self.source_span_digest,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "kind": self.kind,
            "proposed_status": self.proposed_status,
            "modality": self.modality,
            "alternative_refs": list(self.alternative_refs),
            "rationale_refs": list(self.rationale_refs),
            "requires_clarification": self.requires_clarification,
            "reason_codes": list(self.reason_codes),
        }


class DecisionEngine:
    def evaluate(self, value: DecisionInput) -> DecisionCandidate:
        kind = DecisionKind(value.classification_hint)
        reasons: list[str] = []
        if kind is DecisionKind.EXPLICIT:
            if value.modality in {"possible", "likely"}:
                status = ProposedDecisionStatus.NEEDS_CLARIFICATION
                kind = DecisionKind.AMBIGUOUS
                reasons.append("hedged_explicit_statement")
            else:
                status = ProposedDecisionStatus.DECIDED
        elif kind is DecisionKind.PROPOSAL:
            status = ProposedDecisionStatus.PROPOSED
        elif kind is DecisionKind.PREFERENCE:
            status = ProposedDecisionStatus.PREFERENCE
        else:
            status = ProposedDecisionStatus.NEEDS_CLARIFICATION
            reasons.append("decision_ambiguous")
        if kind is DecisionKind.EXPLICIT and not value.rationale_refs:
            reasons.append("rationale_missing")
        return DecisionCandidate.create(
            operation_id=value.operation_id,
            source_ref=value.source_ref,
            source_span=value.exact_span,
            start_offset=value.start_offset,
            end_offset=value.end_offset,
            kind=kind.value,
            proposed_status=status.value,
            modality=value.modality,
            alternative_refs=value.alternative_refs,
            rationale_refs=value.rationale_refs,
            requires_clarification=kind is DecisionKind.AMBIGUOUS,
            reason_codes=reasons,
        )


__all__ = [
    "DECISION_INPUT_VERSION", "DECISION_CANDIDATE_VERSION", "DecisionKind",
    "ProposedDecisionStatus", "DecisionInput", "DecisionCandidate", "DecisionEngine",
]
