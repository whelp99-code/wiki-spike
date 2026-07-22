# P4-01 Runtime Orchestrator 적대적 검증 20라운드

**대상**: Runtime 계약, stable operation, stage retry, cancellation, deadline, fencing  
**기준선**: P4-00 merged main  
**범위 제한**: P4-02 Intent/Temporal, 모델, 검색, Phase 5 실행은 포함하지 않음

## Round 01 — 전송 재시도가 새 작업을 생성

- **공격**: `request_id`나 수신 시간이 바뀔 때마다 새 operation을 만든다.
- **방어**: transport 필드를 제외한 semantic identity로 `operation_id`를 계산한다.
- **기계 증거**: `test_operation_id_is_stable_across_delivery_request_id_and_received_time`

## Round 02 — 동일 idempotency key에 다른 payload

- **공격**: 같은 key로 내용을 바꾸어 기존 작업을 덮어쓴다.
- **방어**: workspace-scoped key가 다른 operation ID에 결속되면 fail-closed 거부한다.
- **기계 증거**: `test_same_idempotency_key_with_different_payload_is_rejected_without_handler_call`

## Round 03 — operation ID와 계약 필드 변조

- **공격**: payload 또는 deadline을 바꾸고 기존 ID를 유지한다.
- **방어**: canonical semantic identity에서 ID를 재계산하고, Orchestrator 진입 시 계약을 다시 파싱해 생성 후 mutable payload 변조도 차단한다. Handler에는 stage-local request copy를 제공한다.
- **기계 증거**: `test_tampered_operation_id_is_rejected`, `test_post_construction_request_payload_mutation_is_rejected_before_handler`, `test_handler_receives_stage_local_request_copy`

## Round 04 — 알 수 없는 version·field·raw number

- **공격**: producer/consumer가 서로 다르게 해석할 값을 주입한다.
- **방어**: exact allowlist, known version, canonical string number만 허용한다. Runtime은 Core 구현 오류 모듈을 import하지 않고 자체 오류 taxonomy로 Core canonicalizer 실패를 번역한다.
- **기계 증거**: `test_runtime_request_rejects_unknown_version_field_and_raw_number`, `test_repository_runtime_boundary_passes`

## Round 05 — 무시간대 또는 역전된 deadline

- **공격**: local time이나 received 이전 deadline으로 실행 의미를 흐린다.
- **방어**: UTC seconds만 허용하고 `deadline > received`를 강제한다.
- **기계 증거**: `test_runtime_request_requires_canonical_utc_deadline_after_received`

## Round 06 — Stage retry가 handler를 중복 실행

- **공격**: transient 실패 후 완료된 앞 stage까지 다시 실행한다.
- **방어**: stage index와 immutable result refs에서 정확한 stage만 재개한다.
- **기계 증거**: `test_transient_failure_retries_same_stage_without_repeating_completed_stages`

## Round 07 — 저장 후 crash로 provider 작업 반복

- **공격**: result를 저장한 뒤 state commit 전에 죽어 다음 worker가 모델을 다시 호출한다.
- **방어**: operation/stage/input digest로 기존 result를 조회해 handler 없이 채택한다.
- **기계 증거**: `test_preexisting_content_bound_stage_result_recovers_without_handler_execution`

## Round 08 — 같은 stage key에 다른 결과

- **공격**: 재시도마다 다른 결과를 같은 논리 stage로 저장한다.
- **방어**: put-once canonical semantic bytes 비교로 nondeterminism을 거부하고, 저장소 내부에는 caller가 변경할 수 없는 snapshot을 보존한다.
- **기계 증거**: `test_stage_result_store_is_put_once_and_detects_nondeterminism`, `test_stage_result_store_isolated_from_caller_and_reader_mutation`

## Round 09 — 활성 lease 중 동시 delivery

- **공격**: 두 worker가 같은 stage를 동시에 실행한다.
- **방어**: active lease 동안 두 번째 delivery는 `retry_later`이며 handler는 한 번만 실행된다.
- **기계 증거**: `test_concurrent_delivery_observes_busy_claim_and_handler_runs_once`

## Round 10 — 만료 claim의 늦은 commit

- **공격**: lease가 끝난 worker가 결과를 나중에 commit한다.
- **방어**: commit 시 lease와 fencing token을 다시 검증한다.
- **기계 증거**: `test_expired_claim_cannot_commit_without_takeover`

## Round 11 — takeover 뒤 과거 claim commit

- **공격**: 새 worker가 fencing을 획득한 뒤 이전 worker가 commit한다.
- **방어**: active claim token mismatch를 `stale_stage_claim`으로 거부한다.
- **기계 증거**: `test_stale_stage_claim_cannot_commit_after_fencing_takeover`

## Round 12 — 느린 handler가 lease를 잃고 결과 유실

- **공격**: provider 호출은 끝났지만 lease가 만료돼 다시 provider를 호출한다.
- **방어**: immutable result는 남기고 commit만 거부하며 다음 claim이 결과를 재사용한다.
- **기계 증거**: `test_slow_handler_loses_lease_then_reuses_immutable_result_on_retry`

## Round 13 — stage 실행 전 취소

- **공격**: 취소된 operation이 handler를 실행한다.
- **방어**: claim 전에 cancellation을 terminalize한다.
- **기계 증거**: `test_cancellation_before_stage_is_terminal_and_handler_is_not_called`

## Round 14 — 실행 중 취소 뒤 결과 노출

- **공격**: handler가 반환한 결과를 취소 후에도 response에 연결한다.
- **방어**: cooperative checkpoint와 cancellation precedence로 uncommitted result를 참조하지 않는다. 취소와 transient/fatal 오류가 경합해도 취소가 최종 상태를 결정한다.
- **기계 증거**: `test_cooperative_cancellation_during_stage_discards_uncommitted_output`, `test_cancellation_wins_race_with_fatal_and_transient_failure`

## Round 15 — 취소 의미 재작성과 완료 후 취소

- **공격**: 두 번째 signal로 최초 reason을 바꾸거나 완료 기록에 취소를 추가한다.
- **방어**: 첫 signal은 immutable이고 terminal operation은 변경하지 않는다. Operation 생성보다 오래된 signal은 거부한다.
- **기계 증거**: `test_first_cancellation_is_immutable_and_duplicate_is_idempotent`, `test_late_cancellation_does_not_rewrite_terminal_operation`, `test_cancellation_signal_cannot_predate_operation_creation`

## Round 16 — deadline 이후 handler 실행·결과 공개

- **공격**: deadline 전 claim만 했다는 이유로 늦은 결과를 commit한다.
- **방어**: 실행 전후 checkpoint와 commit 시 deadline 검사를 수행한다. Lease가 deadline과 동시에 만료돼도 기존 result를 retry로 노출하지 않고 deadline terminal 상태로 정규화한다.
- **기계 증거**: `test_deadline_before_claim_and_deadline_during_handler_do_not_publish_result`, `test_expired_claim_with_existing_result_terminalizes_deadline_not_retry`

## Round 17 — 잘못된 stage 순서와 handler binding

- **공격**: verification을 건너뛰거나 같은 stage를 반복하거나 다른 handler 결과를 넣는다.
- **방어**: strict pipeline order, generated→verified, proposed-final, stage/result binding을 강제한다. Mutable stage list는 tuple snapshot으로 고정하고 잘못된 disposition/provenance 타입을 거부한다.
- **기계 증거**: `test_invalid_pipeline_and_missing_handler_fail_closed`, `test_wrong_stage_result_fails_terminally`, `test_pipeline_definition_copies_mutable_stage_sequence_and_generator_input`, `test_runtime_stage_result_types_and_mutable_sequences_fail_closed_or_normalize`

## Round 18 — status/state/retryability 조합 위조

- **공격**: failed state를 completed로 표시하거나 terminal response를 retryable로 표시한다.
- **방어**: 상태·응답·result_ref·error_code를 하나의 semantic invariant로 검증한다. Non-terminal state는 마지막 committed stage 및 다음 current stage와도 일치해야 한다.
- **기계 증거**: `test_response_status_state_and_retryability_are_consistent`, `test_runtime_status_rejects_stage_state_not_matching_committed_refs`

## Round 19 — Runtime 응답에 원문 payload 유출

- **공격**: stage/model/source payload를 response에 직접 포함한다.
- **방어**: 공개 계약은 content-bound `StageResultRef` 배열만 노출한다.
- **기계 증거**: `test_happy_path_is_ordered_and_returns_metadata_refs_only`

## Round 20 — 무한 transition과 알려지지 않은 route

- **공격**: handler가 stage를 동적으로 늘리거나 unknown route가 상태를 생성한다.
- **방어**: pipeline 길이 기반 finite loop와 route-before-register 검사를 적용한다.
- **기계 증거**: `test_unknown_request_type_and_missing_status_do_not_create_state`

# 남은 정직한 한계

1. In-memory operation/result store는 단일 프로세스 reference adapter다.
2. 분산 lease, durable queue, provider timeout 강제 종료는 이후 adapter가 필요하다.
3. P4-01은 Intent, Retrieval, Model, Verification 품질을 검증하지 않는다.
4. P4-01 통과는 Phase 4 또는 Production 완료를 의미하지 않는다.
