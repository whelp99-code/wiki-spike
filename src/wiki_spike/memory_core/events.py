"""Operational event factory, deduplicating consumer, and checkpoint replay contract.

Operational events are rebuildable notifications, never the source of logical state.
Handlers prepare a deterministic effect; the consumer store commits that effect,
event-id dedupe, and the monotonic checkpoint atomically.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from threading import RLock
from typing import Protocol, Sequence

from .contracts import JsonValue, OperationalEvent, canonical_bytes


@dataclass(frozen=True)
class OutboxEventRecord:
    workspace_id: str
    generation_id: str
    parent_generation_id: str | None
    generation_seq: str
    event_type: str
    causation_id: str
    correlation_id: str
    sensitivity: str
    payload_ref: str | None
    emitted_at: str


class OperationalEventFactory:
    @staticmethod
    def from_outbox(record: OutboxEventRecord) -> OperationalEvent:
        return OperationalEvent.create(
            workspace_id=record.workspace_id,
            generation_id=record.generation_id,
            parent_generation_id=record.parent_generation_id,
            generation_seq=record.generation_seq,
            event_type=record.event_type,
            causation_id=record.causation_id,
            correlation_id=record.correlation_id,
            sensitivity=record.sensitivity,
            payload_ref=record.payload_ref,
            emitted_at=record.emitted_at,
        )


@dataclass(frozen=True)
class ConsumerEffect:
    effect_digest: str
    result_ref: str | None

    @classmethod
    def create(
        cls,
        effect_type: str,
        *,
        result_ref: str | None = None,
        metadata: dict[str, JsonValue] | None = None,
    ) -> "ConsumerEffect":
        if not effect_type:
            raise ValueError("effect_type is required")
        body = {
            "effect_type": effect_type,
            "result_ref": result_ref,
            "metadata": metadata or {},
        }
        return cls(sha256(canonical_bytes(body)).hexdigest(), result_ref)


@dataclass(frozen=True)
class EventCheckpoint:
    workspace_id: str
    consumer_id: str
    generation_seq: str
    generation_id: str
    last_event_id: str


@dataclass(frozen=True)
class EventConsumeResult:
    status: str
    event_id: str
    checkpoint: EventCheckpoint | None
    attempts: str
    error_code: str | None = None


class EventHandler(Protocol):
    def prepare(self, event: OperationalEvent) -> ConsumerEffect: ...


class EventConsumerStore(Protocol):
    def seen(self, workspace_id: str, consumer_id: str, event_id: str) -> bool: ...

    def checkpoint(self, workspace_id: str, consumer_id: str) -> EventCheckpoint | None: ...

    def record_failure(self, workspace_id: str, consumer_id: str, event_id: str) -> int: ...

    def commit(
        self,
        consumer_id: str,
        event: OperationalEvent,
        effect: ConsumerEffect,
        expected: EventCheckpoint | None,
    ) -> bool: ...

    def acknowledge_stale(self, consumer_id: str, event: OperationalEvent) -> None: ...

    def dead_letter_and_advance(
        self,
        consumer_id: str,
        event: OperationalEvent,
        expected: EventCheckpoint | None,
        error_code: str,
    ) -> bool: ...


class InMemoryEventConsumerStore:
    def __init__(self) -> None:
        self._seen: set[tuple[str, str, str]] = set()
        self._checkpoints: dict[tuple[str, str], EventCheckpoint] = {}
        self._failures: dict[tuple[str, str, str], int] = {}
        self._effects: dict[tuple[str, str, str], ConsumerEffect] = {}
        self._dead_letters: dict[tuple[str, str, str], str] = {}
        self._lock = RLock()

    @staticmethod
    def _event_key(workspace_id: str, consumer_id: str, event_id: str) -> tuple[str, str, str]:
        return workspace_id, consumer_id, event_id

    @staticmethod
    def _checkpoint_key(workspace_id: str, consumer_id: str) -> tuple[str, str]:
        return workspace_id, consumer_id

    def seen(self, workspace_id: str, consumer_id: str, event_id: str) -> bool:
        with self._lock:
            return self._event_key(workspace_id, consumer_id, event_id) in self._seen

    def checkpoint(self, workspace_id: str, consumer_id: str) -> EventCheckpoint | None:
        with self._lock:
            return self._checkpoints.get(self._checkpoint_key(workspace_id, consumer_id))

    def record_failure(self, workspace_id: str, consumer_id: str, event_id: str) -> int:
        with self._lock:
            key = self._event_key(workspace_id, consumer_id, event_id)
            value = self._failures.get(key, 0) + 1
            self._failures[key] = value
            return value

    @staticmethod
    def _next_checkpoint(consumer_id: str, event: OperationalEvent) -> EventCheckpoint:
        return EventCheckpoint(
            event.workspace_id,
            consumer_id,
            event.generation_seq,
            event.generation_id,
            event.event_id,
        )

    def commit(
        self,
        consumer_id: str,
        event: OperationalEvent,
        effect: ConsumerEffect,
        expected: EventCheckpoint | None,
    ) -> bool:
        with self._lock:
            event_key = self._event_key(event.workspace_id, consumer_id, event.event_id)
            if event_key in self._seen:
                return True
            checkpoint_key = self._checkpoint_key(event.workspace_id, consumer_id)
            if self._checkpoints.get(checkpoint_key) != expected:
                return False
            self._effects[event_key] = effect
            self._seen.add(event_key)
            self._failures.pop(event_key, None)
            self._checkpoints[checkpoint_key] = self._next_checkpoint(consumer_id, event)
            return True

    def acknowledge_stale(self, consumer_id: str, event: OperationalEvent) -> None:
        with self._lock:
            self._seen.add(self._event_key(event.workspace_id, consumer_id, event.event_id))

    def dead_letter_and_advance(
        self,
        consumer_id: str,
        event: OperationalEvent,
        expected: EventCheckpoint | None,
        error_code: str,
    ) -> bool:
        with self._lock:
            event_key = self._event_key(event.workspace_id, consumer_id, event.event_id)
            checkpoint_key = self._checkpoint_key(event.workspace_id, consumer_id)
            if self._checkpoints.get(checkpoint_key) != expected:
                return False
            self._dead_letters[event_key] = error_code
            self._seen.add(event_key)
            self._checkpoints[checkpoint_key] = self._next_checkpoint(consumer_id, event)
            return True

    def effect(self, workspace_id: str, consumer_id: str, event_id: str) -> ConsumerEffect | None:
        with self._lock:
            return self._effects.get(self._event_key(workspace_id, consumer_id, event_id))

    def dead_letter(self, workspace_id: str, consumer_id: str, event_id: str) -> str | None:
        with self._lock:
            return self._dead_letters.get(self._event_key(workspace_id, consumer_id, event_id))


class OperationalEventConsumer:
    def __init__(
        self,
        consumer_id: str,
        handler: EventHandler,
        store: EventConsumerStore,
        *,
        max_attempts: int = 3,
    ) -> None:
        if not consumer_id or max_attempts < 1:
            raise ValueError("consumer_id and positive max_attempts are required")
        self.consumer_id = consumer_id
        self.handler = handler
        self.store = store
        self.max_attempts = max_attempts

    def consume(self, event: OperationalEvent) -> EventConsumeResult:
        if self.store.seen(event.workspace_id, self.consumer_id, event.event_id):
            return EventConsumeResult(
                "duplicate",
                event.event_id,
                self.store.checkpoint(event.workspace_id, self.consumer_id),
                "0",
                None,
            )

        checkpoint = self.store.checkpoint(event.workspace_id, self.consumer_id)
        sequence = int(event.generation_seq)
        expected_sequence = 1 if checkpoint is None else int(checkpoint.generation_seq) + 1
        if sequence < expected_sequence:
            self.store.acknowledge_stale(self.consumer_id, event)
            return EventConsumeResult(
                "ignored_stale", event.event_id, checkpoint, "0", "event_out_of_order"
            )
        if sequence > expected_sequence:
            return EventConsumeResult(
                "retry_later", event.event_id, checkpoint, "0", "event_sequence_gap"
            )

        expected_parent = None if checkpoint is None else checkpoint.generation_id
        if event.parent_generation_id != expected_parent:
            return EventConsumeResult(
                "retry_later", event.event_id, checkpoint, "0", "event_parent_mismatch"
            )

        try:
            effect = self.handler.prepare(event)
        except Exception:
            attempts = self.store.record_failure(
                event.workspace_id, self.consumer_id, event.event_id
            )
            if attempts < self.max_attempts:
                return EventConsumeResult(
                    "retry_later",
                    event.event_id,
                    checkpoint,
                    str(attempts),
                    "event_handler_failed",
                )
            if not self.store.dead_letter_and_advance(
                self.consumer_id,
                event,
                checkpoint,
                "event_handler_failed",
            ):
                return EventConsumeResult(
                    "retry_later",
                    event.event_id,
                    self.store.checkpoint(event.workspace_id, self.consumer_id),
                    str(attempts),
                    "event_checkpoint_conflict",
                )
            return EventConsumeResult(
                "dead_lettered",
                event.event_id,
                self.store.checkpoint(event.workspace_id, self.consumer_id),
                str(attempts),
                "event_handler_failed",
            )

        if not self.store.commit(self.consumer_id, event, effect, checkpoint):
            return EventConsumeResult(
                "retry_later",
                event.event_id,
                self.store.checkpoint(event.workspace_id, self.consumer_id),
                "0",
                "event_checkpoint_conflict",
            )
        return EventConsumeResult(
            "processed",
            event.event_id,
            self.store.checkpoint(event.workspace_id, self.consumer_id),
            "1",
            None,
        )


class EventReplayLog(Protocol):
    def events_after(self, workspace_id: str, generation_seq: str) -> Sequence[OperationalEvent]: ...


class InMemoryEventLog:
    def __init__(self) -> None:
        self._events: list[OperationalEvent] = []

    def append(self, event: OperationalEvent) -> None:
        self._events.append(event)

    def events_after(self, workspace_id: str, generation_seq: str) -> Sequence[OperationalEvent]:
        floor = int(generation_seq)
        values = [
            item
            for item in self._events
            if item.workspace_id == workspace_id and int(item.generation_seq) > floor
        ]
        values.sort(key=lambda item: (int(item.generation_seq), item.event_id))
        return tuple(values)


class EventReplayCoordinator:
    def __init__(
        self,
        consumer: OperationalEventConsumer,
        store: EventConsumerStore,
        log: EventReplayLog,
    ) -> None:
        self.consumer = consumer
        self.store = store
        self.log = log

    def replay(self, workspace_id: str, *, limit: int = 1000) -> tuple[EventConsumeResult, ...]:
        if limit < 1:
            raise ValueError("limit must be positive")
        checkpoint = self.store.checkpoint(workspace_id, self.consumer.consumer_id)
        floor = "0" if checkpoint is None else checkpoint.generation_seq
        results: list[EventConsumeResult] = []
        for event in self.log.events_after(workspace_id, floor)[:limit]:
            result = self.consumer.consume(event)
            results.append(result)
            if result.status == "retry_later":
                break
        return tuple(results)
