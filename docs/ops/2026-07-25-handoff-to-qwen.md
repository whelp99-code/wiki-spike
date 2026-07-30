# Encrypted Single-Memory Lifecycle — qwen Code 핸드오프 문서

> 작성일: 2026-07-25 22:30 (최종 갱신: 2026-07-25 23:55)
> 현재 HEAD: `42a456c` (G7 complete)
> 전체 테스트: **1117 passed**, boundary PASS, secret PASS, validator 121 PASS

---

## 1. 프로젝트 전체 진행 상태

| 게이트 | 상태 | 설명 |
|---|---|---|
| G001 (Gate 0+1) | ✅ complete | Governance pin, ADR, 스키마, fixture |
| G002 | superseded | G010으로 흡수 |
| G003 | ✅ complete | 결정론적 수직 파이프라인 |
| G004 | ✅ complete | 리뷰/정정/멀티소스/재동의 |
| G005 | ✅ complete | 삭제 및 선택적 복원 |
| G006 | ✅ complete | Extraction value |
| G007 | ✅ complete | Read-only MCP |
| G008 | **🔴 active** | **Conformance, canary, review — 최종** |
| Gate 9 | ❌ out of scope | Agent-Blackbox (새 ADR 없으면 범위 밖) |

---

## 2. Gate 6 (Extraction Value) — ✅ 완료

**완전히 구현·커밋·close-out 완료**
- `src/wiki_spike/infrastructure/extraction.py` (596 lines)
- `tests/encrypted_lifecycle/test_gate6_extraction.py` (33 tests)
- Architect CLEAR/APPROVE · Critic OKAY
- 커밋: `ec9dad4` (G6-01)

---

## 3. Gate 7 (Read-only MCP) — 🔜 qwen Code 작업

### 범위
Plan 기준 (stage-08):
- 두 개의 scoped authenticated MCP tool: `memory_recall`(아티팩트 recall), `memory_source`(소스 컨텍스트 조회)
- 64 KiB response bound (base64-encoded response 크기 ≤ 64 KiB 또는 item count 제한)
- Shared checked-snapshot primitive (Gate 3 `lifecycle_db.checked_snapshot_read()` 재사용)
- No write path, no caller trust beyond authentication
- 인증 방식: Ed25519 서명된 요청 + nonce replay guard

### 해야 할 일
1. **MCP 스펙 정의**: tool 이름, input JSON schema, output schema, 인증 프로토콜
2. **`memory_recall`**: artifact recall (encrypted_cas.get → 복호화 → plaintext 반환, 64 KiB bound, veto/floor 게이트 통과)
3. **`memory_source`**: source context 조회 (locator/source digest 기준)
4. **Shared checked-snapshot read**: Gateway 3 `checked_snapshot_read` 공유 primitive
5. **Auth**: Ed25519 서명 검증 + nonce replay guard (`consumed_nonces`)
6. **테스트 + architect + critic + red-team review**
7. **Checkpoint G007 complete**

### 재사용 가능한 기존 인프라
- `lifecycle_db.checked_snapshot_read()` — WAL checked-snapshot read linearization
- `encrypted_cas.get()` / `exists()` / `is_tombstoned()` — opaque CAS read
- `crypto.verify()` / `crypto.signature_input()` — Ed25519 서명 검증
- `pipeline.is_object_vetoed()` — deletion veto check
- `floor_protocol.serve_gate_allows_serving()` — freshness serve gate
- `binding_registry._consumed_nonces` — nonce replay guard (참고 패턴)
- `locators.py` — evidence-fragment locator 추출 (source context 용)
- `deletion.is_vetoed()` — veto 확인

### 중요: MCP 모듈 위치
- 신규 모듈: `src/wiki_spike/connectors/mcp.py` (connectors 레이어 — infrastructure에 의존 가능)
- 또는 `src/wiki_spike/infrastructure/mcp.py` (인프라 레이어 — 권장, architecture-boundary simpler)
- 테스트: `tests/encrypted_lifecycle/test_gate7_mcp.py`

---

## 4. Gate 8 (Conformance, canary, review) — 이후

- Same-commit conformance run (Gate 1 + Gate 3~7 통합 검증)
- 24-hour canary on self-hosted macOS runners
- 세 가지 strict immutable tuple import (gate1, conformance, canary)
- Verdict-free pre-review manifest + 두 independent attestation
- 30-query recall corpus (15/5/5/5)
- **이월 항목들 최종 처리**:
  - G4-CORRECTION-CONTINUITY (logical-object continuity)
  - G4-NEW-CONSENT-SUBJECT-BINDING (same-subject binding + receipt validation)
  - F4 (§9 checked-snapshot reads)
  - F5 (atomic event append)
  - Gate 7 완료 후 Gate 8 진행

---

## 5. 명령어 치트시트

```sh
# 기본
cd ~/orca/Wiki-spike/wiki-spike
python3.12 -m pytest -q                                          # 전체 테스트
python3.12 -m pytest tests/encrypted_lifecycle/ -q              # 게이트 테스트만
python3.12 scripts/check_architecture_boundaries.py             # 경계 검사
python3.12 scripts/validate_encrypted_lifecycle_vectors.py      # oracle 검증

# Ultragoal
S=019f8ebe-012e-7000-b140-8e9aced136fc
GJC_SESSION_ID=$S gjc ultragoal status                          # 목표 상태
GJC_SESSION_ID=$S gjc ultragoal checkpoint --goal-id G007 ...   # 체크포인트
GJC_SESSION_ID=$S gjc ultragoal complete-goals                  # 다음 목표로 이동
GJC_SESSION_ID=$S gjc ultragoal steer --kind annotate_ledger    # 로그 기록
```

---

## 6. 중요 규칙

1. **Python 버전**: `python3.12` ONLY (`python3`는 3.11)
2. **Session ID 고정**: `019f8ebe-012e-7000-b140-8e9aced136fc`
3. **절대 수정 금지** (never-parallel-edit authorities):
   - `crypto.py` (identity/KDF)
   - `keystore.py` (ARK/custody)
   - `binding_registry.py` (binding authority)
   - `floor_protocol.py` (floor state machine)
   - `recovery.py` (recovery modes)
4. **Escalation/Risk Gate**: 스키마/enum/key/provider 변경 시 architect+critic 리뷰 필수
5. **모든 수치**: durable/canonical 영역에서는 canonical decimal STRING (raw JSON number 금지)
6. **Frozen Core**: `canonical_bytes()` 단일 경로만 사용 (병렬 인코더 금지)
7. **테스트 추가 시**: `tests/encrypted_lifecycle/` 디렉토리에 추가
8. **모듈 추가 시**:
   - `src/wiki_spike/infrastructure/` — infrastructure 레이어 (stdlib + memory_core만 import 가능)
   - `src/wiki_spike/applications/` — application 레이어 (infrastructure + memory_core import 가능)
