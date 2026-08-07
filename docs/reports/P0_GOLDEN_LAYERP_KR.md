# P0 보완 — Golden 확대 + Layer P 검증 경계 확정 (완료)
**기준선**: Round 9 (`aa4bd76e…`, 99 tests) + per-source 비용(104) 위에 진행  
**결과**: **110개 테스트 통과** (104 + Layer P/golden 6), warnings-as-errors 클린  
**성격**: API 키 없이 mock으로 검증. Round 9 보고서가 지목한 "golden 확대 + Layer P 실 구현 계약을 별도 모델/서비스 경계로 확정" 단계.

---

## (A) Extraction golden 확대: 4 → 12 예제

`tests/golden/dataset.json` — 고유 source 12개로 다음을 커버:

| 케이스 | 검증 |
|---|---|
| supported-asserted | 기본 지원 claim |
| hedge-may-possible | `may` → **possible**(승격 금지) |
| hedge-likely | `likely` → likely |
| capability-can | `can`은 hedge 아님 → asserted 유지 |
| negative-polarity | 부정 극성 |
| scoped-claim | scope(version) |
| korean-claim / korean-hedge | 한국어 + `수 있다` → possible |
| multi-claim | 한 소스 2 claim |
| explicit-possible | 모델이 possible 명시 → 보존 |
| unsupported-dropped | 근거 없는 claim → DROP |
| abstain-no-claims | 추출 없음 → abstain |

전 지표 통과: `precision=1.0, recall=1.0, hedge_preservation=1.0, unsupported_acceptance=0.0, structured_output_success=1.0`.

> 구현 중 발견: 두 예제가 동일 source를 쓰면 mock client 키가 충돌해 recall이 떨어짐 → **모든 golden source를 고유하게** 유지하는 것이 harness 계약임을 명시(테스트로 강제).

---

## (B) Layer P 검증 경계 확정

### 실 구현 계약 — `LLMEntailmentChecker`
extraction과 **분리된 verification 모델 경계**:
- `config.verification_model_id` 사용 (extraction 모델과 다름).
- 3-state 반환(ENTAILED / UNRESOLVED / CONTRADICTED).
- **fail-closed**: malformed/unknown 응답 또는 client 예외 → **UNRESOLVED** (절대 자동 accept 안 함). 판정기가 깨져도 미지원 claim을 통과시키지 못함.
- 게이트: 키/`verification_model_id` 없으면 하부 client가 실행 거부 → UNRESOLVED.

### Layer P golden 하니스
`tests/golden/layerp.json` (8 예제: entailed/contradicted/unresolved + 한국어 + 부정극성), 지표:
- **entailment_precision**: ENTAILED 판정 중 실제 entailed 비율
- **false_acceptance_rate**: 실제 non-entailed 중 잘못 ENTAILED된 비율 (**0 목표**)

통과 기준(`LAYER_P_ACCEPTANCE`): `entailment_precision ≥ 0.95`, `false_acceptance_rate ≤ 0.0`.

검증:
- 정상 판정기 → FAR=0, precision≥0.95, acceptance 통과.
- **깨진 판정기**(모두 entailed) → FAR>0, acceptance **실패** (계약이 실제로 나쁜 판정기를 걸러냄).
- malformed 응답 → UNRESOLVED (fail-closed).
- 모델 ID 없는 실 client → UNRESOLVED (게이트).

---

## 왜 별도 경계인가

Extraction(무엇을 뽑나)과 Verification(그게 근거로 뒷받침되나)은 **다른 실패 모드·다른 모델·다른 지표**를 가집니다. Round 9 보고서 지적대로, verification 품질(entailment precision, false acceptance)은 extraction 품질(JSON 준수, recall)과 **독립적으로** 측정·게이트되어야 합니다. 이번에 두 경계와 각각의 golden·acceptance를 분리해 확정했습니다.

---

## 남은 것 (당신 결정 선행)

- **exact model ID 3종** (extraction / verification / render) — selection eval로 고정.
- **실 API canary** — extraction golden(12) + Layer P golden(8)을 실제 모델로 실행해 두 경계의 acceptance 충족 확인.
- verification/render가 실 LLM이 되는 시점에 `SourceCostContext` 주입(비용 경계 wiring).

이제 mock 계약은 촘촘합니다. 실 API를 켜는 순간, 두 경계(extraction·verification) 각각의 golden에 대해 실제 품질을 분리 측정할 수 있습니다.
