# P4-02 Intent·Temporal Resolver 적대적 검증 20라운드

**대상**: Intent 분류, IANA 시간대, 상대시간 해석, 정밀도·as-of 보존, planned-stage 연결
**기준선**: P4-01 merged main `e5c845934af11658e51b3d2c73a3d7e7fd071e70`
**범위 제한**: 모델 호출·검색·회상·결정 판정·외부 행동은 포함하지 않음

## Round 01 — 전송 재시도로 Intent 의미 변경

- **공격**: 같은 operation에 다른 request type 또는 payload를 끼워 넣는다.
- **방어**: `IntentTemporalInput`은 P4-01의 content-bound `operation_id`와 입력 전체를 다시 결속하며, resolver 진입 시 canonical bytes를 재파싱한다.
- **기계 증거**: `test_input_and_nested_resolutions_are_content_bound`

## Round 02 — 명시적 Hint로 알려진 Route 덮어쓰기

- **공격**: `memory.ask` 요청에 `extract_decision` hint를 붙여 다른 처리 경로로 승격한다.
- **방어**: 알려진 request type과 충돌하는 hint는 fail-closed로 거부한다.
- **기계 증거**: `test_hint_cannot_override_known_request_type`

## Round 03 — Generic Route의 임의 추측

- **공격**: `runtime.resolve`처럼 의미가 넓은 요청을 시스템이 임의로 recall이나 ask로 고른다.
- **방어**: 명시적 hint가 없으면 `ambiguous`와 clarification 요구를 반환한다.
- **기계 증거**: `test_generic_route_requires_hint_or_returns_ambiguous`

## Round 04 — 필요한 Query 없이 확정 Intent 생성

- **공격**: 질의 본문이 없는데 recall/ask/decision intent를 확정한다.
- **방어**: query-required intent는 `query_text_missing`으로 ambiguous 처리한다.
- **기계 증거**: `test_query_required_intent_without_query_becomes_ambiguous`

## Round 05 — 원문 Query의 Runtime Metadata 유출

- **공격**: 민감한 고객명·계약 내용을 resolution 또는 stage 결과에 그대로 담는다.
- **방어**: 공개 Intent 결과에는 domain-separated query digest만 포함하며 원문은 포함하지 않는다.
- **기계 증거**: `test_resolution_exposes_query_digest_not_query_text`, `test_stage_handler_returns_metadata_only_planned_result`

## Round 06 — 알 수 없는·비정규 IANA Timezone

- **공격**: 존재하지 않는 zone, path traversal, alias 변형으로 서로 다른 시간 해석을 만든다.
- **방어**: canonical IANA key만 허용하고 `ZoneInfo.key`와 입력의 정확한 일치를 요구한다.
- **기계 증거**: `test_invalid_or_noncanonical_timezone_is_rejected`

## Round 07 — Naive 또는 Offset Timestamp 저장

- **공격**: timezone 없는 시각이나 임의 offset을 as-of로 사용해 시스템별 해석을 갈라놓는다.
- **방어**: `as_of_at`과 모든 출력 시각은 canonical UTC second(`...Z`)만 허용한다.
- **기계 증거**: `test_input_rejects_non_utc_as_of_and_numeric_fold`

## Round 08 — DST Spring Forward를 24시간으로 고정

- **공격**: 현지의 23시간짜리 날을 무조건 86,400초로 계산한다.
- **방어**: 현지 자정 경계를 각각 IANA zone으로 변환해 실제 UTC 간격을 계산한다.
- **기계 증거**: `test_dst_spring_forward_day_is_23_hours`

## Round 09 — DST Fall Back을 24시간으로 고정

- **공격**: 현지의 25시간짜리 날을 무조건 86,400초로 계산한다.
- **방어**: 다음 현지 자정까지의 실제 elapsed UTC duration을 보존한다.
- **기계 증거**: `test_dst_fall_back_day_is_25_hours`

## Round 10 — 중복되는 Local Time을 임의 선택

- **공격**: DST fall-back의 `01:30`을 fold 없이 첫 번째 또는 두 번째로 추측한다.
- **방어**: 두 실제 시점이 존재하면 `temporal_fold`를 반드시 요구하고 선택을 결과에 결속한다.
- **기계 증거**: `test_ambiguous_local_time_requires_fold_and_resolves_both_occurrences`

## Round 11 — 존재하지 않는 Local Time 보정

- **공격**: DST spring-forward로 사라진 `02:30`을 자동으로 `03:30`으로 이동한다.
- **방어**: UTC round-trip 검증에 실패하면 존재하지 않는 현지시간으로 거부한다.
- **기계 증거**: `test_nonexistent_spring_forward_local_time_is_rejected`

## Round 12 — Fold를 정상 시각·비Local 표현에 주입

- **공격**: 의미 없는 fold를 날짜·UTC 시각·비중복 local time에 붙여 ID를 갈라놓는다.
- **방어**: fold는 실제 중복 local timestamp 선택에만 허용한다.
- **기계 증거**: `test_fold_is_rejected_for_normal_or_nonlocal_expressions`

## Round 13 — 상대 주간 경계의 Locale 오염

- **공격**: 지난주를 실행 환경 locale의 일요일 시작으로 계산한다.
- **방어**: week는 ISO Monday 시작으로 고정하고 사용자 IANA zone에서 경계를 만든다.
- **기계 증거**: `test_last_week_uses_iso_monday_in_local_zone`

## Round 14 — Month·Year·Leap Precision 손실

- **공격**: 2024-02 또는 2024를 임의의 하루로 축소하거나 leap day를 잃는다.
- **방어**: day/week/month/year/rolling precision을 별도 필드로 보존하고 calendar 경계를 계산한다.
- **기계 증거**: `test_month_and_year_precision_survive_resolution`, `test_date_and_inclusive_date_range_are_absolute`

## Round 15 — Date Range 끝점·역전 오류

- **공격**: inclusive end date를 자정 한 점으로 처리하거나 역전 범위를 허용한다.
- **방어**: 사용자 end date 다음 현지 자정을 exclusive UTC end로 만들고 start > end는 거부한다.
- **기계 증거**: `test_date_and_inclusive_date_range_are_absolute`, `test_invalid_date_and_reversed_range_fail_closed`

## Round 16 — 여러 시간 표현 중 임의 하나 선택

- **공격**: “오늘과 어제”처럼 서로 다른 범위를 포함한 요청에서 첫 표현만 사용한다.
- **방어**: 서로 다른 표현이 둘 이상이면 `temporal_ambiguous`와 clarification을 반환한다.
- **기계 증거**: `test_multiple_distinct_query_phrases_require_clarification`, `test_same_phrase_repetition_is_not_false_ambiguity`

## Round 17 — 명시 필드가 Query 의미를 조용히 덮어쓰기

- **공격**: query는 어제를 말하지만 explicit field는 today로 두어 감사 불가능한 해석을 만든다.
- **방어**: 두 표현이 다르면 거부하고 같은 표현일 때만 explicit source를 채택한다.
- **기계 증거**: `test_explicit_expression_must_not_silently_override_conflicting_query`

## Round 18 — 부분 문자열 False Positive

- **공격**: 영어 `nowhere` 안의 `now`를 현재 시각 요청으로 오인한다.
- **방어**: 영어 alias는 word boundary로만 탐지한다.
- **기계 증거**: `test_english_word_boundaries_avoid_nowhere_false_match`

## Round 19 — 결과 Mode·Duration·Clarification 변조

- **공격**: content ID는 유지한 채 interval duration, mode, clarification flag를 바꾼다.
- **방어**: nested resolution의 의미 불변식과 domain-separated resolution ID를 모두 재검증한다.
- **기계 증거**: `test_temporal_resolution_rejects_duration_and_mode_tampering`, `test_intent_resolution_rejects_ambiguous_without_clarification`, `test_resolution_rejects_unknown_fields_and_version`

## Round 20 — Planned Stage가 모델·Storage·외부 행동으로 확장

- **공격**: Intent/Temporal 단계에서 LLM, Storage 구현, connector, 외부 action을 호출한다.
- **방어**: handler는 deterministic resolver만 호출하고 metadata-only `RuntimeStageResult`를 반환한다. Runtime AST 경계와 stage-name 검증이 우회를 차단한다.
- **기계 증거**: `test_stage_handler_returns_metadata_only_planned_result`, `test_stage_handler_enforces_planned_stage`, Phase 4 runtime boundary gate

# 남은 정직한 한계

1. 자연어 시간 표현은 승인된 소수 alias만 지원하며 자유 형식 NLP는 P4-03 이후 별도 검증이 필요하다.
2. 시스템 TZDB version을 기록하지만 모든 배포 노드의 동일 TZDB를 자동 배포하는 기능은 포함하지 않는다.
3. 이 단계는 시간·Intent 계획만 만들며 실제 검색·회상·결정 판정을 수행하지 않는다.
4. Ambiguous 결과를 사용자에게 묻는 Clarification Engine은 후속 PR 범위다.
