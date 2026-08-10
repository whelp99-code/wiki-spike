# P0 보완 — per-source 누적 비용 상한 (완료)
**기준선**: Round 9 (`aa4bd76e…`, 99 tests)  
**결과**: **104개 테스트 통과** (99 + cost-context 5), `warnings-as-errors` 완전 클린(config 경고 제거)

---

## 닫은 계약 공백

Round 9는 `max_cost_per_source`가 사실상 **per-call 상한**만이었습니다. 한 소스가
extraction + verification + render로 **여러 번 LLM을 호출**하면, 각 호출이 상한 이하라도
소스 전체 비용이 새어나갈 수 있었습니다. 이제 두 상한을 분리합니다.

```
max_cost_per_call          : 단일 호출 상한 (Round 9의 per-call)
max_cost_per_source_total  : 한 소스의 모든 호출 누적 상한  ← 신규
```

---

## 구현

`runtime.py`:
- `CallBudgetExceededError`, `SourceBudgetExceededError` (둘 다 `BudgetExceededError` → Fatal)
- **`SourceCostContext`** — 한 소스 실행 동안 모든 LLM 호출 비용을 누적. 각 호출마다:
  1. `call_cost > max_cost_per_call` → `CallBudgetExceededError`
  2. `total_cost > max_cost_per_source_total` → `SourceBudgetExceededError`
- `ManagedLLMClient(cost_context=...)` — 컨텍스트를 주입하면 호출 후 `record(call_cost)`.
  기존 `max_cost_per_source`(per-call) 파라미터는 그대로 유지(하위호환).

핵심 사용 패턴 (다중 호출 파이프라인):
```python
ctx = SourceCostContext(max_cost_per_call=1.0, max_cost_per_source_total=3.0)
extraction   = ManagedLLMClient(inner_e, tracker=T, cost_context=ctx)
verification = ManagedLLMClient(inner_v, tracker=T, cost_context=ctx)
render       = ManagedLLMClient(inner_r, tracker=T, cost_context=ctx)
# 세 클라이언트가 같은 ctx를 공유 → 소스 전체 비용이 누적·차단됨
```
**하나의 컨텍스트를 소스(ingest)마다 생성**해 extraction/verification/render 클라이언트가
공유하는 것이 계약입니다.

---

## 비용 발생 시점 의미 (중요)

per-source-total 초과는 **호출이 이미 실행된 뒤** 감지됩니다(호출 전엔 비용을 알 수 없음).
따라서 초과를 유발한 호출의 비용도 `total_cost`에 포함되며(실제 지출 반영), 그 시점에
예외를 던져 **이후 호출을 중단**합니다. 즉 "이미 쓴 돈은 계상하고, 더는 안 쓰게 막는다".

발행 영향: 예외는 추출 단계에서 발생 → publish 호출 전 → **publication pointer 불변**
(Round 9의 API 실패 불변식과 동일 경로).

---

## 검증 테스트 (`test_p0_cost_context.py`)

| 테스트 | 확인 |
|---|---|
| `test_per_source_total_accumulates_across_calls` | 각 호출 $0.30(<per-call $1.0), 누적 $0.90 > per-source-total $0.80 → 3번째 차단 |
| `test_per_call_cap_independent_of_source_total` | 단일 $0.90 호출이 per-call $0.5 초과 → 차단(누적 여유와 무관) |
| `test_under_both_caps_passes` | 4×$0.30=$1.20 ≤ $2.0 → 전부 통과 |
| `test_legacy_per_call_param_still_works` | Round 9 per-call 파라미터 불변 |
| `test_shared_context_models_extraction_verification_render` | 3-스테이지 공유 컨텍스트 누적 차단 |

---

## 다음 단계

- **wiring**: 현재 실 LLM 호출은 extraction 하나뿐이라, 컨텍스트 계약은 runtime 계층에서
  검증했습니다. verification/render가 실 LLM이 되는 시점에 Workspace/publish가 소스마다
  `SourceCostContext`를 생성해 세 클라이언트에 주입하면 됩니다(주입 지점 문서화 완료).
- 이후 **exact model ID 결정 → 실 API canary** 단계로 진행(사용자 결정 선행).
