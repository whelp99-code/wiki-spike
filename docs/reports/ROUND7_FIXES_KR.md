# Round 7 델타 재구현 — 정본 통일 요약
**목적**: Codex Round 7 리포트의 개선을 내 61-test spike에 재구현해 **단일 정본(canonical)** 으로 통일.  
**결과**: **68개 테스트 통과** (기존 61 + Round 7 계약 7). 실 git·sqlite 기반.

> ⚠️ 이 재구현은 Codex의 96-test 검증본과 **미세하게 갈릴 수 있습니다.** 리포트에 기술된 계약을 내 코드로 직접 이해·구현한 것이며, 재검증으로 좁혀야 합니다.

---

## 반영한 Round 7 델타

| Codex # | 내용 | 재구현 | 검증 |
|---|---|---|---|
| **#3.10** | **무권한 REVOKE 차단** (내가 Round 6에 만든 보안 구멍) | raw source의 `REVOKE`는 실행 안 됨 → 소스 격리(quarantine), 발행 안 함, 포인터 불변. retract는 **trusted 정책 경로**(`admin_revoke`)로만. | `test_source_revoke_is_quarantined`, `test_admin_revoke_retracts` |
| **#3.1** | **다출처 assertion 보존** | claim/assertion 분리: 전역 불변 dedup store(`claim_identity`+`assertion`) + generation 멤버십(`generation_assertion`). 같은 claim에 두 독립 소스 → assertion 2개 모두 citation에 보존, 페이지엔 1줄. 두 번째 소스는 no-op 아님. | `test_second_independent_source_is_not_noop_and_preserved` |
| **#3.4** | **미발행 assertion 격리** | 멤버십을 generation_assertion으로 관리 → 발행 안 된 generation의 assertion이 누출되지 않음. | (구조적) |
| **#3.3** | **부모 상태를 서명 스냅샷에서 복원** | 각 generation이 `knowledge/snapshot.json`(서명·digest 바인딩)을 commit에 포함. 다음 generation은 DB가 아니라 **검증된 부모 스냅샷**에서 accepted assertion 집합을 복원. | (parent 복원 경로) |
| **#3.5** | **서명 manifest 강화** | verify_manifest가 wiki_files_root + citation digest + **snapshot digest** + **파일 allowlist**(예상 외 파일 거부)까지 검사. | `test_extra_file_breaks_verification` |
| **#3.6** | **release manifest 서명·검증** | ReleaseManifest에 signer_key_id + **별도 서명 도메인**(`wiki.release.v1`) + `verify_release` 경로. | `test_release_manifest_verifies` |
| **#3.17** | **출력 sanitization** | 렌더 시 source 유래 텍스트의 markdown/HTML 메타문자 escape. `<script>`·`**`·링크 스킴 무력화. | `test_sanitize_*`, `test_rendered_page_escapes_injection` |
| #3.18 | 패키지 버전/명령 | `0.0.3a0`, `[project.scripts] wiki`, `admin-revoke` CLI 추가. | (수동) |

---

## 내가 소유하는 정정

**#3.10은 내가 Round 6에서 새로 만든 결함이었다.** staleness 테스트를 통과시키려 extractor에 `REVOKE` 지시를 넣었는데, 이건 raw source가 기존 지식을 직접 삭제하게 만든 보안 구멍이었다. Round 7에서 이를 바로잡아, **untrusted source의 REVOKE는 격리**하고 **trusted `admin_revoke`만 retract**하도록 분리했다.

---

## 데이터 모델 변경 (핵심)

```
[변경 전] claim 테이블 하나 (claim_id PK) → 같은 claim의 2번째 소스 assertion이 DROP됨 (버그)
[변경 후]
  claim_identity(claim_id PK, subject, predicate, object, polarity, scope)   # 불변 dedup
  assertion(assertion_id PK, claim_id, source_id, evidence, modality)        # 다출처
  generation_assertion(generation_id, assertion_id)                          # 멤버십
누적 단위 = ASSERTION:
  다음 세대 = 부모 accepted assertions ∪ 새 소스 assertions − 승인된 revoke(claim)
```

---

## CLI

```bash
wiki ingest <src>            # 소스에 REVOKE 있으면 exit 3(격리)
wiki search <term>           # 전체 claim_id 출력(admin-revoke에 사용)
wiki admin-revoke <claim_id> # trusted 정책 retract
```

---

## 여전히 남긴 것 (Production NO-GO, spike 범위 밖)

실 LLM 통합, source trust/provenance 신뢰 모델, parser 보안(악성 파일/압축폭탄), 네트워크 git·다중 노드, production 스키마 마이그레이션. 이것들이 §5의 P0이며 별개의 큰 작업이다.

이 정본은 **검증된 Phase 1 reference spike**로서, 다음 단계(실 LLM 어댑터 골격)의 기반이다.
