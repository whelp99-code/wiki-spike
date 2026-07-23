"""P4-13 offline labeled evaluation contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import canonical_int, content_id, hex64, nonempty

OFFLINE_EVAL_REPORT_VERSION = "phase4-offline-eval-report-v1"


@dataclass(frozen=True)
class LabeledOutcome:
    example_id: str
    expected: str
    actual: str
    safety_violation: bool = False


@dataclass(frozen=True)
class OfflineEvalReport:
    offline_eval_report_version: str
    report_id: str
    suite_id: str
    total: str
    correct: str
    safety_violations: str
    accuracy_bps: str
    passed: bool

    @classmethod
    def create(cls, *, suite_id: str, outcomes: Sequence[LabeledOutcome], minimum_accuracy_bps: str, require_zero_safety: bool = True) -> "OfflineEvalReport":
        total = len(outcomes)
        correct = sum(1 for value in outcomes if value.expected == value.actual)
        violations = sum(1 for value in outcomes if value.safety_violation)
        accuracy = 10000 if total == 0 else int(correct * 10000 / total)
        passed = accuracy >= int(minimum_accuracy_bps) and (violations == 0 or not require_zero_safety)
        payload = {
            "offline_eval_report_version": OFFLINE_EVAL_REPORT_VERSION,
            "suite_id": suite_id,
            "total": str(total),
            "correct": str(correct),
            "safety_violations": str(violations),
            "accuracy_bps": str(accuracy),
            "passed": passed,
        }
        return cls(report_id=content_id("wiki.runtime.offline-eval-report.v1", payload), **payload)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.offline_eval_report_version != OFFLINE_EVAL_REPORT_VERSION:
            raise InvalidContractValue("unsupported offline eval report version")
        nonempty(self.suite_id, "suite_id")
        for field in ("total", "correct", "safety_violations", "accuracy_bps"):
            canonical_int(getattr(self, field), field, maximum=100000000)
        total = int(self.total)
        correct = int(self.correct)
        if correct > total or int(self.accuracy_bps) != (10000 if total == 0 else int(correct * 10000 / total)):
            raise InvalidContractValue("offline evaluation arithmetic mismatch")


__all__ = ["OFFLINE_EVAL_REPORT_VERSION", "LabeledOutcome", "OfflineEvalReport"]
