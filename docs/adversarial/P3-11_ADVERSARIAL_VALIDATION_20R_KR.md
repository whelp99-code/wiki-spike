# P3-11 적대적 검증 20라운드

**대상**: 감사 개인정보, 텔레메트리 장애, bounded queue/retry/circuit, export request

## Round 01 — Audit 본문 삽입
- 공격: body/prompt/response를 로그에 저장한다.
- 방어: 고정 allowlist 계약만 허용한다.
- 증거: `test_audit_contains_only_hashed_references_and_no_payload_fields`

## Round 02 — 사용자 ID 평문 기록
- 공격: actor/workspace/correlation을 직접 기록한다.
- 방어: namespace-separated HMAC 참조만 직렬화한다.
- 증거: `test_reference_hasher_is_deterministic_and_namespace_separated`

## Round 03 — Audit metadata 변조
- 공격: 정상 audit ID 옆 reason/outcome을 바꾼다.
- 방어: 모든 metadata를 content ID에 결속한다.
- 증거: `test_audit_id_binds_metadata_and_strict_fields`

## Round 04 — Audit 포화 시 조용한 eviction
- 공격: 오래된 기록을 삭제하고 성공한다.
- 방어: bounded append-only sink가 명시적으로 실패한다.
- 증거: `test_audit_sink_is_idempotent_and_never_evicts`

## Round 05 — Telemetry 고카디널리티 원문
- 공격: 이메일·문서명을 label로 전송한다.
- 방어: bounded code와 aggregate count만 허용한다.
- 증거: `test_telemetry_is_aggregate_only_content_bound_and_strict`

## Round 06 — Telemetry 장애 은폐
- 공격: sink 실패를 delivered로 보고한다.
- 방어: local minimal audit 후 audit_only를 반환한다.
- 증거: `test_telemetry_success_and_outage_paths`

## Round 07 — Telemetry/Audit 이중 장애
- 공격: 두 경로 실패도 성공 처리한다.
- 방어: fail-closed 오류를 발생시킨다.
- 증거: `test_telemetry_and_audit_double_outage_fails_closed`

## Round 08 — Queue 길이 무제한
- 공격: producer가 메모리를 소진한다.
- 방어: global/workspace/cost cap을 강제한다.
- 증거: `test_queue_enforces_global_workspace_cost_deadline_and_duplicate_limits`

## Round 09 — Queue에 원문 payload 복제
- 공격: work item을 shadow storage로 쓴다.
- 방어: payload digest만 허용한다.
- 증거: `test_work_item_is_reference_only_content_bound_and_strict`

## Round 10 — Deadline 지난 work 실행
- 공격: 오래된 작업을 실행한다.
- 방어: submit/pop 양쪽에서 만료를 검사한다.
- 증거: `test_queue_pop_discards_expired_and_releases_accounting`

## Round 11 — Duplicate가 retry budget 소모
- 공격: replay로 정상 retry를 고갈시킨다.
- 방어: duplicate/rejection은 budget 전 처리한다.
- 증거: `test_backpressure_does_not_consume_budget_for_duplicate_or_queue_rejection`

## Round 12 — Retry 폭주
- 공격: 무한 attempts/cost를 허용한다.
- 방어: operation/attempt/cost cap을 강제한다.
- 증거: `test_retry_budget_blocks_attempt_cost_and_table_storms`

## Round 13 — Queue 성공·Budget 실패 부분 상태
- 공격: ghost work가 남는다.
- 방어: budget 거부 시 queue를 rollback한다.
- 증거: `test_backpressure_rolls_queue_back_on_budget_denial_and_open_circuit`

## Round 14 — Open circuit 우회
- 공격: 장애 중에도 상태를 늘린다.
- 방어: circuit를 가장 먼저 검사한다.
- 증거: `test_backpressure_rolls_queue_back_on_budget_denial_and_open_circuit`

## Round 15 — Half-open probe 폭주
- 공격: reset 직후 동시 provider 호출을 허용한다.
- 방어: 단일 probe만 허용한다.
- 증거: `test_circuit_breaker_open_half_open_busy_and_recovery`

## Round 16 — Export에 URL/Credential 포함
- 공격: Core가 외부 쓰기 권한을 획득한다.
- 방어: digest-only delivery intent와 strict fields를 사용한다.
- 증거: `test_export_request_content_binding_no_destination_and_forbidden_fields`

## Round 17 — Public target 민감도 하향
- 공격: private 정보를 public bundle로 보낸다.
- 방어: target sensitivity ceiling을 강제한다.
- 증거: `test_export_target_sensitivity_ceiling_and_version_are_enforced`

## Round 18 — Policy 전 job 생성
- 공격: 권한 없는 요청도 queue에 남긴다.
- 방어: policy 성공 후에만 job을 만든다.
- 증거: `test_export_gateway_policy_first_queue_audit_and_non_disclosure`

## Round 19 — Audit 실패 후 orphan export job
- 공격: 추적 불가능한 job이 남는다.
- 방어: audit 실패 시 새 job을 cancel한다.
- 증거: `test_export_queue_full_unavailable_and_audit_failure_paths`

## Round 20 — Core의 외부 destination write
- 공격: projection과 delivery를 합친다.
- 방어: submit/cancel job port만 존재한다.
- 증거: `test_no_external_destination_writer_in_core_module`
