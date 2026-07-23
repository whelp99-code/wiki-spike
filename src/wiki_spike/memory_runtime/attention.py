"""P4-10 workspace-wide attention metadata ledger."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import canonical_int, content_id, verify_content_id, nonempty, safe_code, utc_second

ATTENTION_RECORD_VERSION = "phase4-attention-record-v1"


@dataclass(frozen=True)
class AttentionRecord:
    attention_record_version: str
    record_id: str
    workspace_id: str
    topic_key: str
    attention_type: str
    dedupe_key: str
    created_at: str
    expires_at: str
    channel: str

    @classmethod
    def create(
        cls,
        *,
        workspace_id: str,
        topic_key: str,
        attention_type: str,
        dedupe_key: str,
        created_at: str,
        expires_at: str,
        channel: str,
    ) -> "AttentionRecord":
        payload = {
            "attention_record_version": ATTENTION_RECORD_VERSION,
            "workspace_id": workspace_id,
            "topic_key": topic_key,
            "attention_type": attention_type,
            "dedupe_key": dedupe_key,
            "created_at": created_at,
            "expires_at": expires_at,
            "channel": channel,
        }
        return cls(record_id=content_id("wiki.runtime.attention-record.v1", payload), **payload)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.attention_record_version != ATTENTION_RECORD_VERSION:
            raise InvalidContractValue("unsupported attention record version")
        nonempty(self.workspace_id, "workspace_id")
        nonempty(self.topic_key, "topic_key")
        safe_code(self.attention_type, "attention_type")
        nonempty(self.dedupe_key, "dedupe_key")
        if utc_second(self.expires_at, "expires_at") <= utc_second(self.created_at, "created_at"):
            raise InvalidContractValue("attention expiry must be after creation")
        safe_code(self.channel, "channel")
        verify_content_id(self.record_id, "wiki.runtime.attention-record.v1", self.to_mapping(), "record_id", "attention record_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "attention_record_version": self.attention_record_version,
            "record_id": self.record_id,
            "workspace_id": self.workspace_id,
            "topic_key": self.topic_key,
            "attention_type": self.attention_type,
            "dedupe_key": self.dedupe_key,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "channel": self.channel,
        }



class AttentionLedger(Protocol):
    def admit(
        self,
        record: AttentionRecord,
        *,
        now: str,
        daily_cap: str,
        topic_cap: str,
    ) -> bool: ...


class InMemoryAttentionLedger:
    def __init__(self) -> None:
        self._records: dict[str, AttentionRecord] = {}

    def admit(self, record: AttentionRecord, *, now: str, daily_cap: str, topic_cap: str) -> bool:
        now_dt = utc_second(now, "now")
        daily = canonical_int(daily_cap, "daily_cap", maximum=1000)
        topic = canonical_int(topic_cap, "topic_cap", maximum=100)
        active = [
            value for value in self._records.values()
            if value.workspace_id == record.workspace_id and utc_second(value.expires_at, "expires_at") > now_dt
        ]
        if any(value.dedupe_key == record.dedupe_key for value in active):
            return False
        day = now_dt.date()
        day_count = sum(1 for value in active if utc_second(value.created_at, "created_at").date() == day)
        topic_count = sum(1 for value in active if value.topic_key == record.topic_key)
        if day_count >= daily or topic_count >= topic:
            return False
        self._records[record.record_id] = record
        return True

    def active(self, workspace_id: str, now: str) -> tuple[AttentionRecord, ...]:
        now_dt = utc_second(now, "now")
        return tuple(sorted(
            (
                value for value in self._records.values()
                if value.workspace_id == workspace_id and utc_second(value.expires_at, "expires_at") > now_dt
            ),
            key=lambda value: (value.created_at, value.record_id),
        ))


__all__ = ["ATTENTION_RECORD_VERSION", "AttentionRecord", "AttentionLedger", "InMemoryAttentionLedger"]
