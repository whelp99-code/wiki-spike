# P3-12 G3 Conformance Gate 적대적 검증 20라운드

**대상**: 요구사항 매트릭스, source root, signed checkpoint, CI evidence, release 경계  
**계약**: `phase3-core-v1.0.0`

## Round 01 — 20개 요구사항 중 하나 누락
- 공격: 구현하기 어려운 requirement를 matrix에서 삭제하고 PASS를 선언한다.
- 방어: `P3-F-001..020`의 정확한 순서와 완전성을 강제한다.
- 증거: `test_requirement_gap_is_rejected`.

## Round 02 — 요구사항 중복으로 개수 맞추기
- 공격: 쉬운 requirement를 두 번 넣어 20개처럼 보이게 한다.
- 방어: exact ID sequence와 중복 금지를 적용한다.
- 증거: `test_duplicate_requirement_is_rejected`.

## Round 03 — 존재하지 않는 구현·테스트 경로
- 공격: 문서상 경로만 적어 자동 증거가 있는 것처럼 꾸민다.
- 방어: 모든 implementation/test/evidence 경로가 repository 내부 regular file인지 검증한다.
- 증거: `test_missing_bound_path_is_rejected`.

## Round 04 — 임의 shell command 주입
- 공격: matrix에 네트워크 전송 또는 항상 성공하는 명령을 넣는다.
- 방어: matrix는 닫힌 `gate_id` catalog만 참조하며 command 문자열을 받지 않는다.
- 증거: `test_unknown_gate_is_rejected`.

## Round 05 — Gate를 제거한 채 PASS
- 공격: boundary lint를 matrix에서 제거한다.
- 방어: negative fixture가 실제 matrix를 변형했을 때 validation이 반드시 실패해야 한다.
- 증거: `test_committed_negative_fixture_blocks_pass`.

## Round 06 — Source inventory 일부만 결속
- 공격: 변경 가능성이 큰 tests/docs를 source root에서 제외한다.
- 방어: 고정 prefix/exact allowlist가 Core, tests, schemas, scripts, ADR, adversarial, workflows를 포괄한다.
- 증거: `test_source_inventory_contains_load_bearing_zones`.

## Round 07 — Source file 변조
- 공격: checkpoint를 유지한 채 Core 파일 한 바이트를 바꾼다.
- 방어: 현재 inventory를 재계산해 byte length·SHA-256·source root를 비교한다.
- 증거: `test_source_tamper_is_rejected`.

## Round 08 — Inventory entry 재정렬·중복
- 공격: parser별 의미 차이를 유도한다.
- 방어: canonical JSON과 strictly sorted unique path를 강제한다.
- 증거: `test_unsorted_inventory_is_rejected`.

## Round 09 — Checkpoint 자기참조
- 공격: checkpoint가 자기 digest나 commit OID를 포함해 재현 불가능해진다.
- 방어: checkpoint/trust/signature/dynamic evidence는 source inventory에서 명시적으로 제외한다.
- 증거: `test_checkpoint_artifacts_are_not_self_inventoried`.

## Round 10 — Checkpoint body 변조 후 ID 유지
- 공격: test floor나 source root를 낮추고 checkpoint ID를 그대로 둔다.
- 방어: canonical checkpoint body의 SHA-256을 재계산한다.
- 증거: `test_checkpoint_id_tamper_is_rejected`.

## Round 11 — Detached signature 변조
- 공격: 임의 signature 또는 다른 protocol signature를 사용한다.
- 방어: strict base64와 Ed25519 domain frame `wiki.phase3.checkpoint.v1`을 검증한다.
- 증거: `test_checkpoint_signature_tamper_is_rejected`.

## Round 12 — 공개키·trust record 치환
- 공격: checkpoint와 공격자 키를 함께 바꾼다.
- 방어: repository trust record가 checkpoint ID, source root, release, key fingerprint를 고정한다.
- 증거: `test_trust_or_public_key_substitution_is_rejected`.

## Round 13 — G2 연결 제거
- 공격: Phase 2 승인 없이 G3만 독립적으로 선언한다.
- 방어: committed G2 checkpoint ID를 G3에 결속한다.
- 증거: `test_g2_binding_is_required`.

## Round 14 — 과거 또는 무관 계보 위 checkpoint
- 공격: 다른 역사에서 복사한 G3 artifact를 사용한다.
- 방어: lineage anchor commit 존재와 HEAD ancestor 관계를 검증한다.
- 증거: `test_lineage_anchor_must_be_ancestor`.

## Round 15 — 테스트 수 하향
- 공격: 소수 smoke만 실행하고 전체 matrix 통과로 표현한다.
- 방어: Phase 3와 전체 repository test collection floor를 checkpoint에 결속한다.
- 증거: `test_test_inventory_floor_is_enforced`.

## Round 16 — 문서만 있는 ADR
- 공격: 핵심 결정의 ADR을 삭제하거나 중복 번호로 대체한다.
- 방어: ADR-0001..0010 각각 정확히 하나를 요구한다.
- 증거: `test_required_adr_registry_is_complete`.

## Round 17 — CI Evidence에 원문 포함
- 공격: 편의를 위해 로그 본문·기억·토큰을 evidence JSON에 복사한다.
- 방어: evidence는 gate, status, count, log path/hash만 저장한다.
- 증거: `test_evidence_contract_contains_hashes_not_log_bodies`.

## Round 18 — Dynamic evidence를 진실원으로 승격
- 공격: 과거 green 로그만으로 현재 source를 승인한다.
- 방어: 매 실행 전에 signed checkpoint와 현재 source root를 검증하고 evidence가 둘을 결속한다.
- 증거: `test_evidence_binds_checkpoint_source_and_matrix`.

## Round 19 — Tag를 checkpoint 대신 사용
- 공격: 이동 가능한 tag 이름만으로 Phase 4 입력을 승인한다.
- 방어: Phase 4는 checkpoint ID·source root·tag commit을 모두 pin해야 한다.
- 증거: release instruction 및 checkpoint verifier.

## Round 20 — P3-12를 Production Ready로 과장
- 공격: Core conformance를 실 LLM, KMS, HA, connector 운영 완료로 표현한다.
- 방어: report와 ADR에 비범위·비주장을 명시하고 G3를 Phase 4 입력 계약으로만 정의한다.
- 증거: `test_report_preserves_non_claims_and_phase_boundary`.

# 남은 정직한 한계

1. G3 bootstrap key/trust는 동일 PR에서 도입되며 독립 조직 신원 증명은 아니다.
2. GitHub branch protection과 tag immutability는 repository 외부 운영 설정이다.
3. CI green은 실제 전원 장애, provider/KMS, active-active 운영 검증을 대체하지 않는다.
4. G3는 Phase 4 Runtime 구현 권한을 열지만 Runtime 품질을 승인하지 않는다.
