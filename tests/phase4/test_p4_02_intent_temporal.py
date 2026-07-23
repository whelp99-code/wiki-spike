from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re

import pytest

from wiki_spike.memory_runtime import (
    INTENT_TEMPORAL_INPUT_VERSION,
    INTENT_TEMPORAL_RESOLUTION_VERSION,
    TEMPORAL_RESOLUTION_VERSION,
    FatalStageError,
    IntentClassification,
    IntentResolution,
    IntentTemporalInput,
    IntentTemporalResolution,
    IntentTemporalResolver,
    IntentTemporalStageHandler,
    RuntimeOperationInput,
    StageExecutionContext,
    TemporalMode,
    TemporalPrecision,
    TemporalResolution,
)
from wiki_spike.memory_runtime.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)

UTC = timezone.utc
OPERATION_ID = "a" * 64


@dataclass
class FixedClock:
    current: datetime = datetime(2026, 7, 23, 3, 0, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.current


def temporal_input(**overrides) -> IntentTemporalInput:
    values = {
        "operation_id": OPERATION_ID,
        "request_type": "memory.ask",
        "query_text": "오늘 매출은?",
        "intent_hint": None,
        "timezone": "Asia/Seoul",
        "as_of_at": "2026-07-23T03:00:00Z",
        "temporal_expression": None,
        "temporal_fold": None,
    }
    values.update(overrides)
    return IntentTemporalInput.create(**values)


def resolve(**overrides) -> IntentTemporalResolution:
    return IntentTemporalResolver().resolve(temporal_input(**overrides))


# --- Contract integrity and intent classification -----------------------


def test_input_and_nested_resolutions_are_content_bound():
    request = temporal_input()
    assert request.intent_temporal_input_version == INTENT_TEMPORAL_INPUT_VERSION
    changed = request.to_mapping()
    changed["timezone"] = "UTC"
    with pytest.raises(InvalidContractValue, match="input_id"):
        IntentTemporalInput.from_mapping(changed)

    resolution = IntentTemporalResolver().resolve(request)
    assert resolution.intent_temporal_resolution_version == INTENT_TEMPORAL_RESOLUTION_VERSION
    assert resolution.temporal.temporal_resolution_version == TEMPORAL_RESOLUTION_VERSION
    changed = resolution.to_mapping()
    changed["requires_clarification"] = not resolution.requires_clarification
    with pytest.raises(InvalidContractValue):
        IntentTemporalResolution.from_mapping(changed)


def test_input_rejects_unknown_version_field_and_noncanonical_fold():
    value = temporal_input().to_mapping()
    value["intent_temporal_input_version"] = "phase4-intent-temporal-input-v999"
    with pytest.raises(UnsupportedContractVersion):
        IntentTemporalInput.from_mapping(value)
    value = temporal_input().to_mapping()
    value["extra"] = "x"
    with pytest.raises(UnknownContractField):
        IntentTemporalInput.from_mapping(value)
    with pytest.raises(InvalidContractValue, match="temporal_fold"):
        temporal_input(temporal_fold="2")


def test_intent_mapping_is_explicit_and_deterministic():
    cases = {
        "memory.recall": IntentClassification.RECALL,
        "memory.ask": IntentClassification.ASK,
        "decision.extract": IntentClassification.EXTRACT_DECISION,
        "memory.clarify": IntentClassification.CLARIFY,
        "proactive.evaluate": IntentClassification.PROACTIVE_EVALUATE,
    }
    for request_type, expected in cases.items():
        query = None if expected is IntentClassification.PROACTIVE_EVALUATE else "x"
        result = resolve(request_type=request_type, query_text=query, temporal_expression="now")
        assert result.intent.classification == expected.value
        assert result.intent.requires_clarification is False


def test_generic_route_requires_hint_or_returns_ambiguous():
    ambiguous = resolve(request_type="runtime.resolve", query_text="무엇을 찾아줘", temporal_expression="now")
    assert ambiguous.intent.classification == "ambiguous"
    assert ambiguous.intent.reason_codes == ("intent_ambiguous",)
    assert ambiguous.requires_clarification is True

    hinted = resolve(
        request_type="runtime.resolve",
        intent_hint="recall",
        query_text="무엇을 찾아줘",
        temporal_expression="now",
    )
    assert hinted.intent.classification == "recall"
    assert hinted.intent.source == "explicit_hint"


def test_hint_cannot_override_known_request_type():
    with pytest.raises(InvalidContractValue, match="conflicts"):
        resolve(request_type="memory.ask", intent_hint="extract_decision")


def test_query_required_intent_without_query_becomes_ambiguous():
    result = resolve(query_text=None, temporal_expression="now")
    assert result.intent.classification == "ambiguous"
    assert result.intent.reason_codes == ("query_text_missing",)


def test_resolution_exposes_query_digest_not_query_text():
    secret = "민감한 고객 이름과 계약 내용을 오늘 찾아줘"
    result = resolve(query_text=secret)
    encoded = result.canonical_bytes().decode("utf-8")
    assert secret not in encoded
    assert result.intent.query_digest is not None
    assert len(result.intent.query_digest) == 64


# --- IANA timezone and relative interval semantics ----------------------


def test_invalid_or_noncanonical_timezone_is_rejected():
    with pytest.raises(InvalidContractValue, match="unknown IANA timezone"):
        resolve(timezone="Mars/Olympus", temporal_expression="today")
    with pytest.raises(InvalidContractValue, match="canonical IANA"):
        resolve(timezone="../UTC", temporal_expression="today")


def test_today_is_resolved_as_absolute_seoul_interval():
    result = resolve(query_text="오늘 매출")
    temporal = result.temporal
    assert temporal.mode == TemporalMode.INTERVAL.value
    assert temporal.precision == TemporalPrecision.DAY.value
    assert temporal.start_at == "2026-07-22T15:00:00Z"
    assert temporal.end_at == "2026-07-23T15:00:00Z"
    assert temporal.duration_seconds == "86400"
    assert temporal.source == "query_text"
    assert temporal.tzdb_version


def test_dst_spring_forward_day_is_23_hours():
    result = resolve(
        timezone="America/New_York",
        as_of_at="2026-03-08T12:00:00Z",
        query_text="today",
    )
    assert result.temporal.start_at == "2026-03-08T05:00:00Z"
    assert result.temporal.end_at == "2026-03-09T04:00:00Z"
    assert result.temporal.duration_seconds == "82800"


def test_dst_fall_back_day_is_25_hours():
    result = resolve(
        timezone="America/New_York",
        as_of_at="2026-11-01T12:00:00Z",
        query_text="today",
    )
    assert result.temporal.start_at == "2026-11-01T04:00:00Z"
    assert result.temporal.end_at == "2026-11-02T05:00:00Z"
    assert result.temporal.duration_seconds == "90000"


def test_last_week_uses_iso_monday_in_local_zone():
    result = resolve(
        timezone="Asia/Seoul",
        as_of_at="2026-07-23T03:00:00Z",  # Thursday local
        query_text="지난주 매출",
    )
    assert result.temporal.expression_kind == "last_week"
    assert result.temporal.precision == "week"
    assert result.temporal.start_at == "2026-07-12T15:00:00Z"
    assert result.temporal.end_at == "2026-07-19T15:00:00Z"


def test_month_and_year_precision_survive_resolution():
    month = resolve(query_text="x", temporal_expression="month:2024-02")
    assert month.temporal.precision == "month"
    assert month.temporal.start_at == "2024-01-31T15:00:00Z"
    assert month.temporal.end_at == "2024-02-29T15:00:00Z"

    year = resolve(query_text="x", temporal_expression="year:2024")
    assert year.temporal.precision == "year"
    assert year.temporal.start_at == "2023-12-31T15:00:00Z"
    assert year.temporal.end_at == "2024-12-31T15:00:00Z"


def test_date_and_inclusive_date_range_are_absolute():
    day = resolve(query_text="x", temporal_expression="date:2024-02-29")
    assert day.temporal.start_at == "2024-02-28T15:00:00Z"
    assert day.temporal.end_at == "2024-02-29T15:00:00Z"

    date_range = resolve(query_text="x", temporal_expression="range:2026-07-01/2026-07-03")
    assert date_range.temporal.start_at == "2026-06-30T15:00:00Z"
    assert date_range.temporal.end_at == "2026-07-03T15:00:00Z"
    assert date_range.temporal.duration_seconds == str(3 * 86400)


def test_invalid_date_and_reversed_range_fail_closed():
    with pytest.raises(InvalidContractValue, match="valid date"):
        resolve(query_text="x", temporal_expression="date:2023-02-29")
    with pytest.raises(InvalidContractValue, match="must not precede"):
        resolve(query_text="x", temporal_expression="range:2026-07-03/2026-07-01")


def test_rolling_intervals_are_elapsed_utc_durations():
    seven = resolve(query_text="x", temporal_expression="rolling:7d")
    assert seven.temporal.start_at == "2026-07-16T03:00:00Z"
    assert seven.temporal.end_at == "2026-07-23T03:00:00Z"
    assert seven.temporal.duration_seconds == str(7 * 86400)
    assert seven.temporal.precision == "rolling"

    hours = resolve(query_text="x", temporal_expression="rolling:24h")
    assert hours.temporal.duration_seconds == "86400"


def test_now_is_as_of_metadata_not_a_naive_interval():
    result = resolve(query_text="현재 상태", temporal_expression=None)
    assert result.temporal.mode == "as_of"
    assert result.temporal.as_of_at == "2026-07-23T03:00:00Z"
    assert result.temporal.start_at is None
    assert result.temporal.end_at is None
    assert result.temporal.precision == "second"


def test_no_temporal_phrase_preserves_none_without_guessing():
    result = resolve(query_text="고객 계약을 찾아줘", temporal_expression=None)
    assert result.temporal.mode == "none"
    assert result.temporal.expression_kind == "none"
    assert result.temporal.precision == "unspecified"
    assert result.temporal.requires_clarification is False


def test_multiple_distinct_query_phrases_require_clarification():
    result = resolve(query_text="오늘과 어제 매출을 비교해줘", temporal_expression=None)
    assert result.temporal.mode == "none"
    assert result.temporal.expression_kind == "ambiguous"
    assert result.temporal.reason_codes == ("temporal_ambiguous",)
    assert result.requires_clarification is True


def test_same_phrase_repetition_is_not_false_ambiguity():
    result = resolve(query_text="오늘 자료, 오늘 결정", temporal_expression=None)
    assert result.temporal.expression_kind == "today"
    assert result.temporal.requires_clarification is False


def test_english_word_boundaries_avoid_nowhere_false_match():
    result = resolve(query_text="find the nowhere project", temporal_expression=None)
    assert result.temporal.expression_kind == "none"


def test_explicit_expression_must_not_silently_override_conflicting_query():
    with pytest.raises(InvalidContractValue, match="conflicts"):
        resolve(query_text="어제 매출", temporal_expression="today")
    same = resolve(query_text="오늘 매출", temporal_expression="today")
    assert same.temporal.expression_kind == "today"
    assert same.temporal.source == "explicit_field"


# --- Ambiguous/nonexistent local timestamps and fold --------------------


def test_ambiguous_local_time_requires_fold_and_resolves_both_occurrences():
    base = dict(
        timezone="America/New_York",
        as_of_at="2026-10-01T00:00:00Z",
        query_text="x",
        temporal_expression="local:2026-11-01T01:30:00",
    )
    with pytest.raises(InvalidContractValue, match="ambiguous"):
        resolve(**base)
    earlier = resolve(**base, temporal_fold="0")
    later = resolve(**base, temporal_fold="1")
    assert earlier.temporal.start_at == "2026-11-01T05:30:00Z"
    assert later.temporal.start_at == "2026-11-01T06:30:00Z"
    assert earlier.temporal.fold == "0"
    assert later.temporal.fold == "1"


def test_nonexistent_spring_forward_local_time_is_rejected():
    with pytest.raises(InvalidContractValue, match="does not exist"):
        resolve(
            timezone="America/New_York",
            as_of_at="2026-03-01T00:00:00Z",
            query_text="x",
            temporal_expression="local:2026-03-08T02:30:00",
        )


def test_fold_is_rejected_for_normal_or_nonlocal_expressions():
    with pytest.raises(InvalidContractValue, match="only valid"):
        resolve(query_text="x", temporal_expression="date:2026-07-23", temporal_fold="0")
    with pytest.raises(InvalidContractValue, match="actual local-time occurrence"):
        resolve(
            timezone="America/New_York",
            query_text="x",
            temporal_expression="local:2026-07-23T12:00:00",
            temporal_fold="1",
        )


def test_explicit_utc_instant_is_one_second_and_fold_free():
    result = resolve(query_text="x", temporal_expression="utc:2026-07-23T03:00:00Z")
    assert result.temporal.mode == "instant"
    assert result.temporal.start_at == "2026-07-23T03:00:00Z"
    assert result.temporal.end_at == "2026-07-23T03:00:01Z"
    assert result.temporal.duration_seconds == "1"


# --- Semantic tamper resistance and stage integration -------------------


def test_temporal_resolution_rejects_duration_and_mode_tampering():
    value = resolve(query_text="오늘").temporal.to_mapping()
    value["duration_seconds"] = "1"
    with pytest.raises(InvalidContractValue, match="duration_seconds"):
        TemporalResolution.from_mapping(value)

    value = resolve(query_text="현재").temporal.to_mapping()
    value["start_at"] = "2026-07-23T03:00:00Z"
    with pytest.raises(InvalidContractValue, match="must not carry"):
        TemporalResolution.from_mapping(value)


def test_intent_resolution_rejects_ambiguous_without_clarification():
    value = resolve(request_type="runtime.resolve", query_text="x", temporal_expression="now").intent.to_mapping()
    value["requires_clarification"] = False
    with pytest.raises(InvalidContractValue, match="ambiguous intent"):
        IntentResolution.from_mapping(value)


def operation_input(**overrides) -> RuntimeOperationInput:
    payload = {
        "intent_temporal": {
            "query_text": "지난주 결정은?",
            "intent_hint": None,
            "timezone": "Asia/Seoul",
            "as_of_at": "2026-07-23T03:00:00Z",
            "temporal_expression": None,
            "temporal_fold": None,
        }
    }
    payload.update(overrides.pop("payload", {}))
    values = {
        "operation_id": OPERATION_ID,
        "idempotency_key": "idem-1",
        "workspace_id": "ws-1",
        "actor_id": "user-1",
        "request_type": "memory.ask",
        "deadline_at": "2026-07-23T03:10:00Z",
        "requested_generation_id": "gen-1",
        "payload": payload,
    }
    values.update(overrides)
    return RuntimeOperationInput(**values)


def stage_context(operation: RuntimeOperationInput) -> StageExecutionContext:
    return StageExecutionContext(
        request=operation,
        stage_name="planned",
        previous_result_refs=(),
        input_digest="b" * 64,
        attempt="1",
        _clock=FixedClock(),
        _cancelled=lambda: False,
    )


def test_stage_handler_returns_metadata_only_planned_result():
    result = IntentTemporalStageHandler().execute(stage_context(operation_input()))
    assert result.stage_name == "planned"
    assert result.schema_id == INTENT_TEMPORAL_RESOLUTION_VERSION
    assert result.payload["intent"]["classification"] == "ask"
    assert result.payload["temporal"]["expression_kind"] == "last_week"
    encoded = json.dumps(result.payload, ensure_ascii=False)
    assert "지난주 결정은?" not in encoded
    assert result.provenance_refs[0].startswith("runtime:intent-temporal:")


def test_stage_handler_fail_closes_on_malformed_payload():
    operation = operation_input(payload={"intent_temporal": {"query_text": "x"}})
    with pytest.raises(FatalStageError, match="intent_temporal_invalid"):
        IntentTemporalStageHandler().execute(stage_context(operation))


def test_stage_handler_enforces_planned_stage():
    context = stage_context(operation_input())
    context = StageExecutionContext(
        request=context.request,
        stage_name="retrieved",
        previous_result_refs=(),
        input_digest=context.input_digest,
        attempt=context.attempt,
        _clock=context._clock,
        _cancelled=lambda: False,
    )
    with pytest.raises(FatalStageError, match="stage_mismatch"):
        IntentTemporalStageHandler().execute(context)


def test_input_from_operation_requires_exact_nested_fields():
    operation = operation_input()
    value = dict(operation.payload["intent_temporal"])
    value["unexpected"] = "x"
    operation = operation_input(payload={"intent_temporal": value})
    with pytest.raises(UnknownContractField):
        IntentTemporalInput.from_operation(operation)


def test_adversarial_report_contains_exactly_20_rounds():
    root = Path(__file__).resolve().parents[2]
    text = (root / "docs/adversarial/P4-02_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
    assert rounds == list(range(1, 21))


def test_input_rejects_non_utc_as_of_and_numeric_fold():
    with pytest.raises(InvalidContractValue, match="canonical UTC"):
        temporal_input(as_of_at="2026-07-23T12:00:00+09:00")
    with pytest.raises(InvalidContractValue, match="temporal_fold"):
        temporal_input(temporal_fold=0)


def test_resolution_rejects_unknown_fields_and_version():
    temporal_value = resolve(query_text="오늘").temporal.to_mapping()
    temporal_value["extra"] = "x"
    with pytest.raises(UnknownContractField):
        TemporalResolution.from_mapping(temporal_value)

    temporal_value = resolve(query_text="오늘").temporal.to_mapping()
    temporal_value["temporal_resolution_version"] = "phase4-temporal-resolution-v999"
    with pytest.raises(UnsupportedContractVersion):
        TemporalResolution.from_mapping(temporal_value)

    combined = resolve(query_text="오늘").to_mapping()
    combined["extra"] = "x"
    with pytest.raises(UnknownContractField):
        IntentTemporalResolution.from_mapping(combined)


def test_whitespace_only_query_and_temporal_expression_are_rejected():
    with pytest.raises(InvalidContractValue, match="bounded non-empty"):
        temporal_input(query_text="   ")
    with pytest.raises(InvalidContractValue, match="bounded non-empty"):
        temporal_input(temporal_expression="\t")


def test_explicit_expression_cannot_select_one_of_multiple_query_ranges():
    with pytest.raises(InvalidContractValue, match="incompletely resolves"):
        resolve(query_text="오늘과 어제 매출", temporal_expression="today")


def test_structured_rolling_alias_matches_equivalent_query_phrase():
    result = resolve(query_text="last 7 days", temporal_expression="rolling:7d")
    assert result.temporal.expression_kind == "rolling_7d"
    assert result.temporal.duration_seconds == str(7 * 86400)


def test_extreme_dates_and_intervals_fail_as_contract_errors_not_runtime_overflow():
    for expression in (
        "date:9999-12-31",
        "range:9999-12-30/9999-12-31",
        "utc:9999-12-31T23:59:59Z",
        "local:9999-12-31T23:59:59",
    ):
        with pytest.raises(InvalidContractValue, match="supported datetime range"):
            resolve(query_text="x", timezone="UTC", temporal_expression=expression)
    with pytest.raises(InvalidContractValue, match="maximum duration"):
        resolve(query_text="x", timezone="UTC", temporal_expression="rolling:3651d")


def test_temporal_contract_rejects_rehashed_mode_precision_source_and_reason_forgery():
    valid = resolve(query_text="오늘").temporal.to_mapping()

    def rehash(value):
        from hashlib import sha256
        from wiki_spike.memory_runtime.contracts import canonical_bytes
        identity = {key: item for key, item in value.items() if key != "resolution_id"}
        value["resolution_id"] = sha256(b"wiki.runtime.temporal-resolution.v1\x00" + canonical_bytes(identity)).hexdigest()
        return value

    forged = dict(valid, precision="week")
    with pytest.raises(InvalidContractValue, match="expression kind and precision"):
        TemporalResolution.from_mapping(rehash(forged))

    forged = dict(valid, source="none")
    with pytest.raises(InvalidContractValue, match="asserted source"):
        TemporalResolution.from_mapping(rehash(forged))

    none_value = resolve(query_text="계약을 찾아줘").temporal.to_mapping()
    forged = dict(none_value, precision="day")
    with pytest.raises(InvalidContractValue, match="none mode"):
        TemporalResolution.from_mapping(rehash(forged))


def test_intent_contract_rejects_rehashed_semantic_forgery():
    valid = resolve(query_text="오늘").intent.to_mapping()

    def rehash(value):
        from hashlib import sha256
        from wiki_spike.memory_runtime.contracts import canonical_bytes
        identity = {key: item for key, item in value.items() if key != "resolution_id"}
        value["resolution_id"] = sha256(b"wiki.runtime.intent-resolution.v1\x00" + canonical_bytes(identity)).hexdigest()
        return value

    forged = dict(valid, source="unresolved")
    with pytest.raises(InvalidContractValue, match="must not use unresolved"):
        IntentResolution.from_mapping(rehash(forged))

    forged = dict(valid, query_digest=None)
    with pytest.raises(InvalidContractValue, match="query_digest"):
        IntentResolution.from_mapping(rehash(forged))

    forged = dict(valid, reason_codes=["intent_ambiguous"])
    with pytest.raises(InvalidContractValue, match="must not carry"):
        IntentResolution.from_mapping(rehash(forged))
