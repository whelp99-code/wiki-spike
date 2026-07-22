# P3-10 RecoveryCoordinator 적대적 검증 20라운드

**대상**: Recovery Set inventory, trust anchor, clean-room restore, dry-run CLI  
**기준선**: P3-09 merged main `365c2f15a836c3b1593481e10984566a7e442ae9`  
**판정 기준**: clone 성공이 아니라 서명·state root·pointer·strict query까지 모두 검증

## Round 01 — 서명 없는 Recovery Manifest

- **공격**: 공격자가 item 목록과 publication pointer를 임의로 작성한다.
- **방어**: 별도 trust anchor의 Ed25519 공개키로 purpose/domain-separated Manifest 서명을 검증한다.
- **기계 증거**: `test_manifest_signature_tamper_is_rejected`

## Round 02 — 과거 정상 Manifest로 롤백

- **공격**: 서명이 유효한 오래된 Recovery Set을 최신 백업처럼 복원한다.
- **방어**: 외부 trust anchor가 정확한 `expected_manifest_id`를 고정한다.
- **기계 증거**: `test_trust_anchor_manifest_pin_prevents_rollback_or_substitution`

## Round 03 — Key Registry 자기서명 치환

- **공격**: 공격자 키 registry와 공격자 artifact 서명을 함께 넣는다.
- **방어**: historical key registry의 snapshot digest를 trust anchor가 별도로 고정한다.
- **기계 증거**: `test_historical_key_registry_digest_is_pinned_out_of_band`

## Round 04 — CAS/Git/Checkpoint 객체 누락

- **공격**: manifest에는 있지만 저장 비용을 줄이기 위해 실제 bytes를 누락한다.
- **방어**: 모든 listed item을 읽고 missing item에서 restore target을 열기 전에 실패한다.
- **기계 증거**: `test_missing_required_item_fails_before_target_mutation`

## Round 05 — 동일 길이 객체 변조

- **공격**: byte length를 유지하면서 CAS 또는 manifest 내용을 바꾼다.
- **방어**: 길이와 SHA-256을 독립 검증한다.
- **기계 증거**: `test_corrupt_item_digest_or_length_is_rejected`

## Round 06 — 경로 traversal·비정규 경로

- **공격**: absolute path, `..`, backslash 또는 symlink로 bundle 밖 파일을 읽게 한다.
- **방어**: canonical relative POSIX path만 허용하고 CLI는 item ID 고정 경로와 symlink 금지를 적용한다.
- **기계 증거**: `RecoveryItem` path validation, `FilesystemRecoverySource.read_item`

## Round 07 — Secret sidecar 누락

- **공격**: 공개 artifact만 복원하고 필요한 redaction/secret sidecar를 빼서 의미를 바꾼다.
- **방어**: dependency로 결속된 sidecar도 ordinary required item처럼 검증한다.
- **기계 증거**: `test_missing_secret_sidecar_is_rejected`

## Round 08 — 평문 Secret sidecar

- **공격**: 암호화 metadata 없이 민감 sidecar를 Recovery Set에 넣는다.
- **방어**: `secret_sidecar` category는 `encrypted=true`와 key ID를 강제한다.
- **기계 증거**: `test_secret_sidecar_must_be_encrypted`

## Round 09 — 최소 Recovery Set 축소

- **공격**: Git clone이나 SQLite checkpoint 하나만으로 복구 완료를 주장한다.
- **방어**: CAS, Git object/ref, signed Generation/Release, key/checkpoint/schema/kind registry category를 최소 집합으로 강제한다.
- **기계 증거**: `test_manifest_requires_complete_minimum_recovery_set`

## Round 10 — Dangling dependency·cycle

- **공격**: sidecar 또는 prerequisite item ID를 존재하지 않는 값으로 연결한다.
- **방어**: dependency 존재성과 DAG를 manifest 생성·파싱 시 fail-closed 검증한다.
- **기계 증거**: `test_missing_dependency_is_rejected_by_manifest`

## Round 11 — Historical public key 누락

- **공격**: artifact bytes는 남기고 과거 검증키를 삭제해 검증 불가능한 상태를 복원한다.
- **방어**: 모든 signature binding key ID가 historical registry에 존재하고 유효해야 한다.
- **기계 증거**: `test_missing_historical_verification_key_rejects_signed_artifact`

## Round 12 — 목적·도메인·시간 교차 재사용

- **공격**: Generation 서명을 Release/Export 또는 다른 domain에서 재사용한다.
- **방어**: key purpose/domain/validity와 signature frame을 함께 검증한다.
- **기계 증거**: `test_bad_artifact_signature_is_rejected`, P3-09 key-domain tests

## Round 13 — Registry snapshot 구조·version 변조

- **공격**: digest는 다시 계산하되 알 수 없는 snapshot version이나 field set으로 해석 차이를 만든다.
- **방어**: canonical JSON, exact keys, known version, snapshot digest를 모두 검사한다.
- **기계 증거**: `test_unsupported_registry_snapshot_version_is_rejected`

## Round 14 — Write freeze 없이 복원

- **공격**: 운영 쓰기와 restore가 동시에 진행되어 pointer와 state root가 갈라진다.
- **방어**: 실제 restore는 workspace-scoped freeze token 없이는 session을 시작하지 않는다.
- **기계 증거**: `test_write_freeze_failure_prevents_restore_session`

## Round 15 — Freeze 전후 Manifest TOCTOU

- **공격**: preview 이후 다른 Recovery Manifest로 바꾼다.
- **방어**: freeze 획득 후 signed manifest canonical bytes를 다시 읽어 동일성을 확인한다.
- **기계 증거**: `test_manifest_change_after_freeze_is_rejected`

## Round 16 — 복원 State Root 불일치

- **공격**: adapter가 일부 authoritative item만 적용하고 성공을 반환한다.
- **방어**: restore 반환 root와 target status root를 manifest state root와 각각 비교한다.
- **기계 증거**: `test_post_restore_verification_failures_abort_and_release[state_root-*]`

## Round 17 — Checkpoint·Publication·Release pointer drift

- **공격**: bytes는 복원했지만 SQLite/current Release pointer가 다른 세대를 가리킨다.
- **방어**: control checkpoint digest와 publication generation/Release OID를 exact match한다.
- **기계 증거**: `test_post_restore_verification_failures_abort_and_release`

## Round 18 — Required Projection stale pointer

- **공격**: identity 또는 chronology projection이 이전 generation을 가리키는데 복구 완료를 선언한다.
- **방어**: 최소 projection pointer가 publication generation과 일치해야 commit 가능하다.
- **기계 증거**: `test_post_restore_verification_failures_abort_and_release[projection-*]`

## Round 19 — Strict sample query 의미 불일치

- **공격**: state root와 pointer는 맞지만 실제 query materialization이 다른 결과를 반환한다.
- **방어**: authoritative as-of sample query의 canonical result digest를 검증한다.
- **기계 증거**: `test_post_restore_verification_failures_abort_and_release[query-*]`

## Round 20 — Adapter crash·증거 유출·freeze 해제 실패

- **공격**: stage/rebuild/commit 중 crash, 또는 RecoveryEvidence에 원문·secret을 포함한다.
- **방어**: 실패 시 abort와 freeze release를 수행하고, evidence는 ID/digest/count/pointer만 기록한다. 성공 후 freeze release 실패도 숨기지 않는다.
- **기계 증거**: `test_adapter_failures_never_leave_freeze_held`, `test_freeze_release_failure_is_reported_even_after_successful_restore`, `test_valid_dry_run_verifies_all_items_signatures_and_queries`

# 남은 정직한 한계

1. Filesystem dry-run은 production object store/KMS/remote Git adapter가 아니다.
2. Secret sidecar decryption key escrow와 실제 decrypt 검증은 배포 계층 작업이다.
3. 물리 장애·다중 노드 failover·RPO/RTO 측정은 별도 운영 drill이 필요하다.
4. P3-10은 Recovery Core 계약이며 Phase 3 전체 G3 완료를 의미하지 않는다.
