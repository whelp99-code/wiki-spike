# P0 1단계 — API 없이 mock으로 검증한 계약 (완료)
**기준선**: Round 8 정본 (`ebcf047c…`, 77 tests)  
**결과**: **90개 테스트 통과** (77 + P0 stage-1 13), `warnings-as-errors` **완전 클린**  
**원칙**: 실 API 연결 전에 런타임·품질 계약을 먼저 못박아, 나중에 모델 품질 문제와 런타임 문제가 섞이지 않게 함.

---

## 구현한 6개 계약

| # | 계약 | 모듈 | 핵심 불변식 | 검증 |
|---|---|---|---|---|
| 1 | **hedge/modality 보존** | `verify.py`, `extraction.py` | `may/likely/possible` → `asserted` 승격 **금지**. hedged span은 추출 시 `likely`로 강등. | `test_hedged_span_not_promoted_to_asserted`, `test_extractor_preserves_hedge_end_to_end` |
| 2 | **retry 정책** | `runtime.py` | transient(timeout/429/5xx)만 재시도, fatal(4xx/schema)은 즉시 실패. | `test_retry_recovers_after_transient`, `test_fatal_error_not_retried` |
| 3 | **rate-limit** | `runtime.py` | token-bucket, 주입 clock으로 결정론 검증. 초과 시 transient로 처리→재시도. | `test_rate_limiter_deterministic_clock` |
| 4 | **토큰·비용 추적** | `runtime.py` | 입출력 토큰 누적·가격표로 비용 계산. `max_cost_per_source` 초과 시 fatal. | `test_cost_tracking_and_budget`, `test_budget_exceeded_is_fatal_via_managed_client` |
| 5 | **golden 라벨셋** | `verify.py`, `tests/golden/dataset.json` | precision/recall/abstention + **hedge_preservation** + **unsupported_acceptance** 측정, 통과 기준 고정. | `test_golden_meets_stage1_acceptance` |
| 6 | **Layer P 인터페이스+mock** | `verify.py` | 3-state 결정(ENTAILED/UNRESOLVED/CONTRADICTED). 근거 불충분 → UNRESOLVED. | `test_layer_p_unresolved_when_unsupported` |

추가 핵심 불변식:
- **근거 없는 claim → DROP** (Layer D REFUSE-TO-WRITE, 기존)
- **API timeout/429/5xx → publication pointer 불변** — 추출이 발행 전에 실패하므로 포인터가 안 움직임. `test_api_failure_leaves_pointer_unchanged`로 실증(항상 503 클라이언트 → ingest 예외 → 포인터 그대로).

---

## 초기 통과 기준 (stage-1, 실 canary 전 튜닝 대상)

```
structured_output_success   >= 0.99
unsupported_claim_acceptance == 0.0
hedge_preservation          == 1.0
min_precision               >= 0.95
```
`verify.passes_acceptance(report)`로 게이트. mock golden set에서 현재 전부 충족.

---

## 새 런타임 구조

```
ManagedLLMClient(inner, retry, limiter, tracker, max_cost_per_source)
  ├─ RetryPolicy         : transient만 재시도(backoff)
  ├─ TokenBucketRateLimiter : 결정론 clock
  └─ CostTracker         : 토큰·비용 + 예산 게이트
→ LLMExtractor(managed_client, config)  # 그대로 Workspace(extractor=...)에 주입
```
mock↔실 LLM은 동일 인터페이스라 테스트는 결정론 유지, 실 경로만 교체.

---

## 아직 안 한 것 (다음 단계, 사용자 결정 선행)

- **2단계 모델 선택 평가** — extraction/verification/render 각 exact model ID를 JSON 준수율·entailment precision·citation coverage 기준으로 선정·고정 (계열 alias/`latest` 금지).
- **3단계 실 API canary** — golden 10~20개로 소규모 실행, 위 통과 기준 충족 확인.
- **4단계 제한 발행** — 실 LLM 결과는 candidate까지만, 자동 canary gate 통과 시 발행(인간 승인 아님, AI-First 유지).

### API 키 처리 (합의)
`ANTHROPIC_API_KEY`는 채팅에 붙이지 않음. 실행 환경 secret/env로만.
```
export ANTHROPIC_API_KEY="..."
```
저장소엔 값 없는 키 이름만(.env는 Git 제외):
```
ANTHROPIC_API_KEY=
EXTRACTION_MODEL_ID=
VERIFICATION_MODEL_ID=
RENDER_MODEL_ID=
```

---

## 확률적 NarrativeDraft 관련 (기록 유지)
현재 결정론 assembler 기준 byte-for-byte 검증 유지. 실 LLM Narrative 도입 시 semantic invariant(claim/evidence coverage, citation entailment, unsupported 부재, modality/hedge 보존, 결정론 입력과 구조적 일치)로 전환.
