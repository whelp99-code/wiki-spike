"""P4-09 bounded Clarification Engine."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import canonical_int, content_id, verify_content_id, hex64, nonempty, safe_code, string_tuple, utc_second

CLARIFICATION_CANDIDATE_VERSION = "phase4-clarification-candidate-v1"
CLARIFICATION_QUESTION_VERSION = "phase4-clarification-question-v1"


@dataclass(frozen=True)
class ClarificationCandidate:
    clarification_candidate_version: str
    candidate_id: str
    operation_id: str
    topic_key: str
    question_text: str
    reason_code: str
    expected_gain_bps: str
    expires_at: str
    safe_default: str

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        topic_key: str,
        question_text: str,
        reason_code: str,
        expected_gain_bps: str,
        expires_at: str,
        safe_default: str,
    ) -> "ClarificationCandidate":
        payload = {
            "clarification_candidate_version": CLARIFICATION_CANDIDATE_VERSION,
            "operation_id": operation_id,
            "topic_key": topic_key,
            "question_text": question_text,
            "reason_code": reason_code,
            "expected_gain_bps": expected_gain_bps,
            "expires_at": expires_at,
            "safe_default": safe_default,
        }
        return cls(candidate_id=content_id("wiki.runtime.clarification-candidate.v1", payload), **payload)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.clarification_candidate_version != CLARIFICATION_CANDIDATE_VERSION:
            raise InvalidContractValue("unsupported clarification candidate version")
        hex64(self.operation_id, "operation_id")
        nonempty(self.topic_key, "topic_key")
        nonempty(self.question_text, "question_text", 2048)
        safe_code(self.reason_code, "reason_code")
        canonical_int(self.expected_gain_bps, "expected_gain_bps", maximum=10000)
        utc_second(self.expires_at, "expires_at")
        if safe_code(self.safe_default, "safe_default") not in {"abstain", "continue_without", "defer"}:
            raise InvalidContractValue("unsupported safe_default")
        verify_content_id(self.candidate_id, "wiki.runtime.clarification-candidate.v1", self.to_mapping(), "candidate_id", "clarification candidate_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "clarification_candidate_version": self.clarification_candidate_version,
            "candidate_id": self.candidate_id,
            "operation_id": self.operation_id,
            "topic_key": self.topic_key,
            "question_text": self.question_text,
            "reason_code": self.reason_code,
            "expected_gain_bps": self.expected_gain_bps,
            "expires_at": self.expires_at,
            "safe_default": self.safe_default,
        }



@dataclass(frozen=True)
class ClarificationQuestion:
    clarification_question_version: str
    question_id: str
    operation_id: str
    topic_key: str
    question_text: str
    reason_code: str
    expected_gain_bps: str
    expires_at: str
    safe_default: str
    dedupe_key: str

    @classmethod
    def from_candidate(cls, candidate: ClarificationCandidate) -> "ClarificationQuestion":
        dedupe_key = content_id("wiki.runtime.clarification-dedupe.v1", {"topic_key": candidate.topic_key, "question_text": candidate.question_text})
        payload = {
            "clarification_question_version": CLARIFICATION_QUESTION_VERSION,
            "operation_id": candidate.operation_id,
            "topic_key": candidate.topic_key,
            "question_text": candidate.question_text,
            "reason_code": candidate.reason_code,
            "expected_gain_bps": candidate.expected_gain_bps,
            "expires_at": candidate.expires_at,
            "safe_default": candidate.safe_default,
            "dedupe_key": dedupe_key,
        }
        return cls(question_id=content_id("wiki.runtime.clarification-question.v1", payload), **payload)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.clarification_question_version != CLARIFICATION_QUESTION_VERSION:
            raise InvalidContractValue("unsupported clarification question version")
        hex64(self.operation_id, "operation_id")
        hex64(self.dedupe_key, "dedupe_key")
        utc_second(self.expires_at, "expires_at")
        verify_content_id(self.question_id, "wiki.runtime.clarification-question.v1", self.to_mapping(), "question_id", "clarification question_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "clarification_question_version": self.clarification_question_version,
            "question_id": self.question_id,
            "operation_id": self.operation_id,
            "topic_key": self.topic_key,
            "question_text": self.question_text,
            "reason_code": self.reason_code,
            "expected_gain_bps": self.expected_gain_bps,
            "expires_at": self.expires_at,
            "safe_default": self.safe_default,
            "dedupe_key": self.dedupe_key,
        }


class ClarificationLedger(Protocol):
    def seen(self, workspace_id: str, dedupe_key: str, now: str) -> bool: ...
    def record(self, workspace_id: str, question: ClarificationQuestion) -> None: ...
    def count_for_operation(self, workspace_id: str, operation_id: str) -> int: ...


class InMemoryClarificationLedger:
    def __init__(self) -> None:
        self._questions: dict[tuple[str, str], ClarificationQuestion] = {}

    def seen(self, workspace_id: str, dedupe_key: str, now: str) -> bool:
        question = self._questions.get((workspace_id, dedupe_key))
        return bool(question and utc_second(question.expires_at, "expires_at") > utc_second(now, "now"))

    def record(self, workspace_id: str, question: ClarificationQuestion) -> None:
        self._questions[(workspace_id, question.dedupe_key)] = question

    def count_for_operation(self, workspace_id: str, operation_id: str) -> int:
        return sum(1 for (ws, _), question in self._questions.items() if ws == workspace_id and question.operation_id == operation_id)


class ClarificationEngine:
    def __init__(self, ledger: ClarificationLedger) -> None:
        self.ledger = ledger

    def select(
        self,
        *,
        workspace_id: str,
        operation_id: str,
        candidates: Sequence[ClarificationCandidate],
        now: str,
        minimum_gain_bps: str = "1000",
        operation_budget: str = "2",
    ) -> ClarificationQuestion | None:
        threshold = canonical_int(minimum_gain_bps, "minimum_gain_bps", maximum=10000)
        budget = canonical_int(operation_budget, "operation_budget", maximum=20)
        if self.ledger.count_for_operation(workspace_id, operation_id) >= budget:
            return None
        for candidate in sorted(candidates, key=lambda value: (-int(value.expected_gain_bps), value.candidate_id)):
            if candidate.operation_id != operation_id:
                continue
            if utc_second(candidate.expires_at, "expires_at") <= utc_second(now, "now"):
                continue
            if int(candidate.expected_gain_bps) < threshold:
                continue
            question = ClarificationQuestion.from_candidate(candidate)
            if self.ledger.seen(workspace_id, question.dedupe_key, now):
                continue
            self.ledger.record(workspace_id, question)
            return question
        return None


__all__ = [
    "CLARIFICATION_CANDIDATE_VERSION", "CLARIFICATION_QUESTION_VERSION",
    "ClarificationCandidate", "ClarificationQuestion", "ClarificationLedger",
    "InMemoryClarificationLedger", "ClarificationEngine",
]
