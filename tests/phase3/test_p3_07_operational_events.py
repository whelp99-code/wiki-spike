from __future__ import annotations

from dataclasses import replace

import pytest

from wiki_spike.memory_core import (
    ConsumerEffect,
    EVENT_SCHEMA_VERSION,
    EventReplayCoordinator,
    InMemoryEventConsumerStore,
    InMemoryEventLog,
    InvalidContractValue,
    OperationalEvent,
    OperationalEventConsumer,
    OperationalEventFactory,
    OutboxEventRecord,
    UnknownContractField,
)


def event(
    sequence: str,
    *,
    generation_id: str | None = None,
    parent_generation_id: str | None = None,
    workspace_id: str = "ws-1",
    event_type: str = "generation.published",
    correlation_id: str = "corr-1",
):
    generation = generation_id or f"g{sequence}"
    return OperationalEvent.create(
        workspace_id=workspace_id,
        generation_id=generation,
        parent_generation_id=parent_generation_id,
        generation_seq=sequence,
        event_type=event_type,
        causation_id=f"cause-{sequence}",
        correlation_id=correlation_id,
        sensitivity="internal",
        payload_ref=f"generation:{generation}",
        emitted_at="2026-07-22T00:00:00Z",
    )


class RecordingHandler:
    def __init__(self):
        self.calls = []

    def prepare(self, value):
        self.calls.append(value.event_id)
        return ConsumerEffect.create("projection.invalidate", result_ref=value.payload_ref)


class FailingHandler:
    def __init__(self):
        self.calls = 0

    def prepare(self, value):
        self.calls += 1
        raise RuntimeError("poison")


class CommitConflictStore(InMemoryEventConsumerStore):
    def commit(self, consumer_id, value, effect, expected):
        return False


def consumer(*, handler=None, store=None, max_attempts=3):
    return OperationalEventConsumer(
        "consumer-1",
        handler or RecordingHandler(),
        store or InMemoryEventConsumerStore(),
        max_attempts=max_attempts,
    )


def test_event_id_is_deterministic_and_content_bound():
    first = event("1")
    second = event("1")
    assert first.event_id == second.event_id
    mapping = first.to_mapping()
    mapping["event_type"] = "generation.changed"
    with pytest.raises(InvalidContractValue):
        OperationalEvent.from_mapping(mapping)


def test_event_contract_rejects_unknown_fields_and_bad_version():
    mapping = event("1").to_mapping()
    with pytest.raises(UnknownContractField):
        OperationalEvent.from_mapping({**mapping, "payload": {"body": "forbidden"}})
    with pytest.raises(Exception):
        OperationalEvent.from_mapping({**mapping, "event_schema_version": "event-v999"})


def test_event_sequence_must_be_canonical_and_sensitivity_known():
    with pytest.raises(InvalidContractValue):
        event("01")
    with pytest.raises(InvalidContractValue):
        OperationalEvent.create(
            workspace_id="ws-1",
            generation_id="g1",
            parent_generation_id=None,
            generation_seq="1",
            event_type="generation.published",
            causation_id="cause-1",
            correlation_id="corr-1",
            sensitivity="top-secret",
            payload_ref=None,
            emitted_at="2026-07-22T00:00:00Z",
        )


def test_duplicate_event_calls_handler_once():
    handler = RecordingHandler()
    store = InMemoryEventConsumerStore()
    worker = consumer(handler=handler, store=store)
    value = event("1")
    assert worker.consume(value).status == "processed"
    replay = worker.consume(value)
    assert replay.status == "duplicate"
    assert handler.calls == [value.event_id]
    assert store.effect("ws-1", "consumer-1", value.event_id) is not None


def test_sequence_gap_is_retry_later_without_handler_call():
    handler = RecordingHandler()
    store = InMemoryEventConsumerStore()
    result = consumer(handler=handler, store=store).consume(
        event("2", generation_id="g2", parent_generation_id="g1")
    )
    assert result.status == "retry_later"
    assert result.error_code == "event_sequence_gap"
    assert handler.calls == []
    assert store.checkpoint("ws-1", "consumer-1") is None


def test_parent_chain_mismatch_is_retry_later():
    handler = RecordingHandler()
    store = InMemoryEventConsumerStore()
    result = consumer(handler=handler, store=store).consume(
        event("1", parent_generation_id="unexpected")
    )
    assert result.status == "retry_later"
    assert result.error_code == "event_parent_mismatch"
    assert handler.calls == []


def test_out_of_order_old_event_is_ignored_and_deduped():
    handler = RecordingHandler()
    store = InMemoryEventConsumerStore()
    worker = consumer(handler=handler, store=store)
    g1 = event("1")
    g2 = event("2", parent_generation_id="g1")
    assert worker.consume(g1).status == "processed"
    assert worker.consume(g2).status == "processed"
    late = event("1", event_type="generation.replayed", correlation_id="corr-late")
    result = worker.consume(late)
    assert result.status == "ignored_stale"
    assert worker.consume(late).status == "duplicate"
    assert handler.calls == [g1.event_id, g2.event_id]


def test_checkpoint_conflict_does_not_store_effect_or_advance():
    handler = RecordingHandler()
    store = CommitConflictStore()
    value = event("1")
    result = consumer(handler=handler, store=store).consume(value)
    assert result.status == "retry_later"
    assert result.error_code == "event_checkpoint_conflict"
    assert store.checkpoint("ws-1", "consumer-1") is None
    assert store.effect("ws-1", "consumer-1", value.event_id) is None


def test_poison_event_is_dead_lettered_then_chain_continues():
    handler = FailingHandler()
    store = InMemoryEventConsumerStore()
    worker = consumer(handler=handler, store=store, max_attempts=2)
    g1 = event("1")
    assert worker.consume(g1).status == "retry_later"
    dead = worker.consume(g1)
    assert dead.status == "dead_lettered"
    assert dead.attempts == "2"
    assert store.dead_letter("ws-1", "consumer-1", g1.event_id) == "event_handler_failed"
    assert store.checkpoint("ws-1", "consumer-1").generation_id == "g1"

    good_handler = RecordingHandler()
    next_worker = consumer(handler=good_handler, store=store, max_attempts=2)
    g2 = event("2", parent_generation_id="g1")
    assert next_worker.consume(g2).status == "processed"
    assert store.checkpoint("ws-1", "consumer-1").generation_id == "g2"


def test_replay_resumes_from_checkpoint_and_sorts_events():
    store = InMemoryEventConsumerStore()
    handler = RecordingHandler()
    worker = consumer(handler=handler, store=store)
    g1 = event("1")
    g2 = event("2", parent_generation_id="g1")
    g3 = event("3", parent_generation_id="g2")
    assert worker.consume(g1).status == "processed"

    log = InMemoryEventLog()
    log.append(g3)
    log.append(g1)
    log.append(g2)
    results = EventReplayCoordinator(worker, store, log).replay("ws-1")
    assert [item.status for item in results] == ["processed", "processed"]
    assert store.checkpoint("ws-1", "consumer-1").generation_id == "g3"
    assert handler.calls == [g1.event_id, g2.event_id, g3.event_id]


def test_replay_stops_at_gap():
    store = InMemoryEventConsumerStore()
    handler = RecordingHandler()
    worker = consumer(handler=handler, store=store)
    log = InMemoryEventLog()
    log.append(event("1"))
    log.append(event("3", parent_generation_id="g2"))
    results = EventReplayCoordinator(worker, store, log).replay("ws-1")
    assert [item.status for item in results] == ["processed", "retry_later"]
    assert store.checkpoint("ws-1", "consumer-1").generation_id == "g1"


def test_consumer_checkpoints_are_workspace_scoped():
    store = InMemoryEventConsumerStore()
    worker = consumer(store=store)
    assert worker.consume(event("1", workspace_id="ws-1")).status == "processed"
    assert worker.consume(event("1", workspace_id="ws-2")).status == "processed"
    assert store.checkpoint("ws-1", "consumer-1").workspace_id == "ws-1"
    assert store.checkpoint("ws-2", "consumer-1").workspace_id == "ws-2"


def test_outbox_factory_produces_same_canonical_event():
    row = OutboxEventRecord(
        "ws-1",
        "g1",
        None,
        "1",
        "generation.published",
        "cause-1",
        "corr-1",
        "internal",
        "generation:g1",
        "2026-07-22T00:00:00Z",
    )
    assert OperationalEventFactory.from_outbox(row) == event("1")


def test_consumer_effect_is_deterministic_and_rejects_raw_numbers():
    first = ConsumerEffect.create("projection.invalidate", metadata={"kind": "semantic"})
    second = ConsumerEffect.create("projection.invalidate", metadata={"kind": "semantic"})
    assert first == second
    with pytest.raises(ValueError):
        ConsumerEffect.create("projection.invalidate", metadata={"attempt": 1})


def test_operational_event_schema_is_strict_and_has_no_inline_payload():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas/phase3/operational-event.schema.json").read_text("utf-8"))
    assert schema["additionalProperties"] is False
    assert schema["properties"]["event_schema_version"]["const"] == EVENT_SCHEMA_VERSION
    assert "payload" not in schema["properties"]
    assert "payload_ref" in schema["properties"]


def test_adversarial_report_contains_exactly_20_rounds():
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    text = (root / "docs/adversarial/P3-07_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
    assert rounds == list(range(1, 21))
