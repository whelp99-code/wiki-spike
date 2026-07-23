"""P4-10 Proactive Suggestion generator.  It never performs channel delivery."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Sequence
from zoneinfo import ZoneInfo

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .attention import AttentionLedger, AttentionRecord
from .service_contracts import content_id, verify_content_id, hex64, nonempty, safe_code, string_tuple, utc_second

PROACTIVE_INPUT_VERSION = "phase4-proactive-input-v1"
PROACTIVE_SUGGESTION_VERSION = "phase4-proactive-suggestion-v1"


@dataclass(frozen=True)
class ProactiveInput:
    proactive_input_version: str
    input_id: str
    operation_id: str
    workspace_id: str
    topic_key: str
    suggestion_type: str
    value_score_bps: str
    interruption_score_bps: str
    evidence_refs: tuple[str, ...]
    dedupe_key: str
    created_at: str
    expires_at: str

    @classmethod
    def create(cls, **kwargs: object) -> "ProactiveInput":
        evidence = tuple(sorted(set(kwargs.pop("evidence_refs", ()))))
        payload = {"proactive_input_version": PROACTIVE_INPUT_VERSION, **kwargs, "evidence_refs": list(evidence)}
        return cls(input_id=content_id("wiki.runtime.proactive-input.v1", payload), evidence_refs=evidence, **{k: v for k, v in payload.items() if k != "evidence_refs"})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.proactive_input_version != PROACTIVE_INPUT_VERSION:
            raise InvalidContractValue("unsupported proactive input version")
        hex64(self.operation_id, "operation_id")
        for field in ("workspace_id", "topic_key", "dedupe_key"):
            nonempty(getattr(self, field), field)
        safe_code(self.suggestion_type, "suggestion_type")
        if not self.value_score_bps.isdigit() or not self.interruption_score_bps.isdigit():
            raise InvalidContractValue("proactive scores must be integer strings")
        if not 0 <= int(self.value_score_bps) <= 10000 or not 0 <= int(self.interruption_score_bps) <= 10000:
            raise InvalidContractValue("proactive scores out of range")
        string_tuple(self.evidence_refs, "evidence_refs", allow_empty=False, sorted_unique=True)
        if utc_second(self.expires_at, "expires_at") <= utc_second(self.created_at, "created_at"):
            raise InvalidContractValue("proactive expiry must be after creation")
        verify_content_id(self.input_id, "wiki.runtime.proactive-input.v1", self.to_mapping(), "input_id", "proactive input_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "proactive_input_version": self.proactive_input_version,
            "input_id": self.input_id,
            "operation_id": self.operation_id,
            "workspace_id": self.workspace_id,
            "topic_key": self.topic_key,
            "suggestion_type": self.suggestion_type,
            "value_score_bps": self.value_score_bps,
            "interruption_score_bps": self.interruption_score_bps,
            "evidence_refs": list(self.evidence_refs),
            "dedupe_key": self.dedupe_key,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }



@dataclass(frozen=True)
class ProactiveSuggestion:
    proactive_suggestion_version: str
    suggestion_id: str
    input_id: str
    workspace_id: str
    topic_key: str
    suggestion_type: str
    evidence_refs: tuple[str, ...]
    created_at: str
    expires_at: str
    delivery_state: str

    @classmethod
    def create(cls, value: ProactiveInput) -> "ProactiveSuggestion":
        payload = {
            "proactive_suggestion_version": PROACTIVE_SUGGESTION_VERSION,
            "input_id": value.input_id,
            "workspace_id": value.workspace_id,
            "topic_key": value.topic_key,
            "suggestion_type": value.suggestion_type,
            "evidence_refs": list(value.evidence_refs),
            "created_at": value.created_at,
            "expires_at": value.expires_at,
            "delivery_state": "not_delivered",
        }
        return cls(suggestion_id=content_id("wiki.runtime.proactive-suggestion.v1", payload), evidence_refs=value.evidence_refs, **{k: v for k, v in payload.items() if k != "evidence_refs"})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.proactive_suggestion_version != PROACTIVE_SUGGESTION_VERSION:
            raise InvalidContractValue("unsupported proactive suggestion version")
        if self.delivery_state != "not_delivered":
            raise InvalidContractValue("Runtime proactive suggestion must not execute delivery")
        verify_content_id(self.suggestion_id, "wiki.runtime.proactive-suggestion.v1", self.to_mapping(), "suggestion_id", "proactive suggestion_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "proactive_suggestion_version": self.proactive_suggestion_version,
            "suggestion_id": self.suggestion_id,
            "input_id": self.input_id,
            "workspace_id": self.workspace_id,
            "topic_key": self.topic_key,
            "suggestion_type": self.suggestion_type,
            "evidence_refs": list(self.evidence_refs),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "delivery_state": self.delivery_state,
        }


class ProactiveEngine:
    def __init__(self, ledger: AttentionLedger) -> None:
        self.ledger = ledger

    @staticmethod
    def _in_quiet_hours(now: str, timezone_name: str, quiet_start_hour: int, quiet_end_hour: int) -> bool:
        local = utc_second(now, "now").astimezone(ZoneInfo(timezone_name))
        hour = local.hour
        if quiet_start_hour == quiet_end_hour:
            return False
        if quiet_start_hour < quiet_end_hour:
            return quiet_start_hour <= hour < quiet_end_hour
        return hour >= quiet_start_hour or hour < quiet_end_hour

    def evaluate(
        self,
        value: ProactiveInput,
        *,
        now: str,
        timezone_name: str,
        quiet_start_hour: int = 22,
        quiet_end_hour: int = 8,
        minimum_net_value_bps: int = 1000,
        daily_cap: str = "3",
        topic_cap: str = "1",
    ) -> ProactiveSuggestion | None:
        if utc_second(value.expires_at, "expires_at") <= utc_second(now, "now"):
            return None
        if self._in_quiet_hours(now, timezone_name, quiet_start_hour, quiet_end_hour):
            return None
        if int(value.value_score_bps) - int(value.interruption_score_bps) < minimum_net_value_bps:
            return None
        record = AttentionRecord.create(
            workspace_id=value.workspace_id,
            topic_key=value.topic_key,
            attention_type="proactive_suggestion",
            dedupe_key=value.dedupe_key,
            created_at=value.created_at,
            expires_at=value.expires_at,
            channel="runtime",
        )
        if not self.ledger.admit(record, now=now, daily_cap=daily_cap, topic_cap=topic_cap):
            return None
        return ProactiveSuggestion.create(value)


__all__ = [
    "PROACTIVE_INPUT_VERSION", "PROACTIVE_SUGGESTION_VERSION", "ProactiveInput",
    "ProactiveSuggestion", "ProactiveEngine",
]
