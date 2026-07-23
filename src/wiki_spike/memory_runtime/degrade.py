"""P4-13 deterministic outage degradation policy."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import content_id, verify_content_id, safe_code, string_tuple

DEGRADE_DECISION_VERSION = "phase4-degrade-decision-v1"


class DegradeAction(str, Enum):
    CONTINUE_EXACT = "continue_exact"
    USE_LAST_KNOWN_GOOD = "use_last_known_good"
    ABSTAIN = "abstain"
    RETRY_LATER = "retry_later"


@dataclass(frozen=True)
class DegradeDecision:
    degrade_decision_version: str
    decision_id: str
    unavailable_components: tuple[str, ...]
    action: str
    degraded: bool
    reason_codes: tuple[str, ...]

    @classmethod
    def create(cls, *, unavailable_components, action, degraded, reason_codes) -> "DegradeDecision":
        unavailable = tuple(sorted(set(unavailable_components)))
        reasons = tuple(sorted(set(reason_codes)))
        payload = {
            "degrade_decision_version": DEGRADE_DECISION_VERSION,
            "unavailable_components": list(unavailable),
            "action": action,
            "degraded": degraded,
            "reason_codes": list(reasons),
        }
        return cls(decision_id=content_id("wiki.runtime.degrade-decision.v1", payload), unavailable_components=unavailable, reason_codes=reasons, **{k: v for k, v in payload.items() if k not in {"unavailable_components", "reason_codes"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.degrade_decision_version != DEGRADE_DECISION_VERSION:
            raise InvalidContractValue("unsupported degrade decision version")
        string_tuple(self.unavailable_components, "unavailable_components", sorted_unique=True, codes=True)
        DegradeAction(self.action)
        string_tuple(self.reason_codes, "reason_codes", sorted_unique=True, codes=True)
        verify_content_id(self.decision_id, "wiki.runtime.degrade-decision.v1", self.to_mapping(), "decision_id", "degrade decision_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "degrade_decision_version": self.degrade_decision_version,
            "decision_id": self.decision_id,
            "unavailable_components": list(self.unavailable_components),
            "action": self.action,
            "degraded": self.degraded,
            "reason_codes": list(self.reason_codes),
        }



class DegradePolicy:
    def decide(self, availability: Mapping[str, bool], *, requires_generation: bool, requires_layer_p: bool) -> DegradeDecision:
        unavailable = sorted(key for key, value in availability.items() if not value)
        if not unavailable:
            return DegradeDecision.create(unavailable_components=(), action="continue_exact", degraded=False, reason_codes=())
        if "core" in unavailable or "generation" in unavailable and requires_generation:
            return DegradeDecision.create(unavailable_components=unavailable, action="retry_later", degraded=True, reason_codes=("authoritative_dependency_unavailable",))
        if "layer_p" in unavailable and requires_layer_p:
            return DegradeDecision.create(unavailable_components=unavailable, action="abstain", degraded=True, reason_codes=("required_verifier_unavailable",))
        if "vector" in unavailable or "model" in unavailable:
            return DegradeDecision.create(unavailable_components=unavailable, action="continue_exact", degraded=True, reason_codes=("optional_component_unavailable",))
        return DegradeDecision.create(unavailable_components=unavailable, action="use_last_known_good", degraded=True, reason_codes=("fallback_selected",))


__all__ = ["DEGRADE_DECISION_VERSION", "DegradeAction", "DegradeDecision", "DegradePolicy"]
