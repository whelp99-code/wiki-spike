# Round 6 대응 — 코드 레벨 결함 수정 요약
**대상**: Codex Round 6 검증 (실제 git·sqlite 실행, 종합 5.2/10)  
**결과**: 9개 치명적 결함 + 고우선 결함 전부 코드로 수정. **61개 테스트 통과** (기존 53 + Round-6 계약 8·정정 반영).

---

## 치명적 결함 9건 수정

| # | 결함 | 수정 | 검증 테스트 |
|---|---|---|---|
| 1 | **새 소스가 기존 지식을 전부 삭제** (교체형) | `claim` 테이블에 claim 영속화 + 발행 시 `parent_accepted ∪ new − revokes`로 **누적**. drop-기반 supersession 제거, 명시적 REVOKE만 retract. | `test_knowledge_accumulates` |
| 2 | **claim 0개 소스가 위키를 비움** | 누적 결과가 parent와 같고 revoke 없으면 **no-op**(포인터 불변, 빈 generation 발행 안 함). | `test_zero_claim_source_is_noop` |
| 3 | **서명이 실제 wiki 파일을 보호 못 함** | `verify_manifest`가 commit의 실제 `wiki/**`·citation index를 재해시해 descriptor의 `inline_artifacts`와 대조. 변조 commit은 검증 실패. | `test_signature_binds_actual_content` |
| 4 | **activation 검증을 호출자가 우회** (`required=[]`) | control-plane이 **등록된 signed manifest에서** 필수 artifact·digest를 직접 읽음. release commit 등록·일치도 검증. | `test_activation_cannot_be_bypassed_with_empty_manifest` |
| 5 | **release commit이 git gc로 삭제** | create-only 보존 ref `refs/wiki/release-objects/<gen>` 추가. | `test_git_gc_retention_keeps_candidate_and_release` |
| 6 | **lease가 배타적이지 않음** (모두 "cli") | Workspace holder = **프로세스별 UUID** + fencing token 증가. 서로 다른 holder는 재획득 불가. | `test_two_workspaces_have_distinct_holders` |
| 7 | **mirror 실패 시 outbox 이벤트 유실** | generation ref + release pointer push가 **모두 성공한 뒤에만** processed 처리. 이벤트 없어도 DB↔remote reconcile. | `test_mirror_pushes_and_is_idempotent` |
| 8 | **한국어 페이지가 모두 untitled.md 충돌** | 경로 = slug + subject 해시 suffix. 비ASCII도 고유 파일. | `test_korean_subjects_do_not_collide` |
| 9 | **CAS 동시 쓰기 깨짐** (공유 .tmp) | writer별 `mkstemp` + fsync + 원자적 create-only `os.link`. race는 idempotent. | `test_cas_concurrent_writers` |

## 고우선 결함 수정

| 결함 | 수정 |
|---|---|
| 동일 소스 재수집 시 예외 | compile idempotent(staged/validated), 재수집은 no-op | `test_reingest_same_source_is_noop` |
| cross-process `status` KeyError traceback | 깨끗한 메시지 + exit 1 |
| 동일 gen ID 다른 키로 ref 이동 | generation retention ref **create-only**(불변) |
| 존재하지 않는 parent → 조용히 root commit | `ValueError` raise | `test_missing_parent_raises` |
| `Evidence.source_object_hash` 빈 값 | source_id로 채움 + locator `offset_unit=unicode_codepoint` 명시 | `test_evidence_has_source_object_hash` |
| NFC 정규화 후 키 충돌 무시 | canonicalization에서 충돌 감지 → 오류 | `test_nfc_key_collision_rejected` |
| ReleaseManifest에 signer_key_id 없음 | 추가 |
| pip install 시 `wiki` 명령 없음 | `[project.scripts]` 추가 (검증: `which wiki`) |
| SQLite ResourceWarning | `ControlPlane.__del__`로 close (검증: `-W error::ResourceWarning`) |
| 문서 모듈/테스트 수 불일치 | 실제 17 모듈·9 테스트 파일·61 테스트로 정정 |

---

## 지식 누적 데모 (CLI)

```
ingest normal.md            → Product A,B 발행,  search "Product A" = 2 hits
ingest instruction_data.md  → 무관한 Product D 추가
search "Product A"          → 여전히 2 hits  ← 누적 성립 (교체 아님)
re-ingest normal.md         → noop (포인터 불변)
zero-claim prose            → noop (위키 안 비워짐)
```

---

## 여전히 남긴 것 (정직하게)

- **확률적 NarrativeDraft render** — pinned LLM 필요, 현재 결정론 assembler(대안 A).
- **실제 전원장애 crash-matrix** — WAL/synchronous=FULL 계약은 있으나 물리 전원장애 테스트는 범위 밖.
- **exact model ID** — PENDING(MOCK). selection eval로 확정 필요.
- **fencing token 실제 활용** — 토큰을 발급·증가시키지만, activation이 토큰을 강제 검사하는 완전한 fence는 후속 과제.
- **remote CAS(force-with-lease) 경합** — 단일 노드 mirror만 검증.

이 수정은 Round-6가 지적한 **통합 지식 누적 의미론과 발행 코어의 실제 결함**을 코드로 잡은 것이다. 스키마는 여전히 spike 단계이며 production contract로 동결 대상이 아니다.
