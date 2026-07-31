# Wiki Spike Round 9 — P0 계약 보강

## 검증 결과

- 업로드 원본: `wiki-spike-p0stage1.zip`
- 원본 주장: 90 tests
- 원본 재현: 90 passed
- Round 9 보강 후: 99 passed
- warnings-as-errors: PASS

## 원본에서 발견한 계약 공백

1. 실 Anthropic HTTP/network 오류가 `TransientLLMError`/`FatalLLMError`로 변환되지 않아 실제 retry가 동작하지 않음.
2. `LayerPDecision`은 테스트용 객체만 존재하고 extraction/publish gate에 연결되지 않음.
3. `max_cost_per_source`가 누적 tracker 총액과 비교되어 두 번째 이후 정상 source가 오탐 차단될 수 있음.
4. Token bucket 고갈을 retry 실패로 소비해, 대기하면 성공할 요청도 즉시 실패할 수 있음.
5. `may`를 `likely`로 바꿔 확신도를 오히려 올림.
6. `can`을 hedge로 분류해 capability 문장을 불확실성 문장으로 오탐.
7. malformed claim을 조용히 drop하면서 `structured_output_success`는 성공으로 집계.
8. 잘못된 offset을 첫 번째 동일 quote로 자동 보정해 중복 문장에서는 잘못된 evidence에 연결 가능.

## Round 9 수정

### Provider 오류 분류
- Anthropic 429/5xx/network timeout → `TransientLLMError`
- Anthropic 기타 4xx/JSON schema failure → `FatalLLMError`
- 실제 retry wrapper가 provider path에도 적용됨.
- provider usage를 `last_usage`로 수집.

### 비용 계약
- tracker는 누적 비용을 유지하되 `last_call_cost`를 별도 기록.
- `max_cost_per_source`는 현재 호출 비용과만 비교.
- 두 source의 합산 비용이 예산보다 커도 각각의 source 비용이 한도 이하면 허용.

### Rate limit
- token 부족 시 retry attempt를 소비하지 않고 필요한 시간만 대기.
- `max_wait` 초과 시에만 transient failure.
- rate/capacity 입력 검증 추가.

### Modality 보존
- certainty order: `asserted > likely > possible`.
- source와 model proposal 중 더 낮은 확신도를 선택.
- `may/might/could` → `possible` 유지.
- `likely/probably` → `likely` 유지.
- capability `can`은 자동 hedge 처리하지 않음.

### Structured output
- top-level response와 claims list 타입 검증.
- malformed claim이 있으면 `last_structured_output_ok=False`.
- golden `structured_output_success`가 실제 schema 품질을 반영.

### Evidence locator
- offset이 틀린 경우 quote가 source에 정확히 한 번만 있을 때만 복구.
- 동일 quote가 여러 번 나타나면 ambiguous evidence로 DROP.

### Layer P gate
- `LLMExtractor(..., entailment_checker=...)` 지원.
- `ENTAILED`만 accepted claim으로 전달.
- `UNRESOLVED`와 `CONTRADICTED`는 publish path 전에 DROP.
- 판정은 `last_layer_p_decisions`에 기록.

## 신규 회귀 테스트

- per-source budget 비누적
- rate limiter 대기 후 단일 호출 성공
- possible/likely exact modality preservation
- capability can 오탐 방지
- ambiguous quote 거부
- malformed claim structured-output 실패 집계
- Layer P unresolved/contradicted gate
- Anthropic 503 retry 및 usage 수집
- Anthropic 400 fatal 분류

## 최종 판정

- P0 mock runtime contracts: PASS
- Real provider error/retry wiring: PASS (mocked HTTP boundary)
- Real API quality: 미검증
- Exact model ID: PENDING
- Production schema freeze: NO-GO

다음 단계는 exact model 후보를 고정하기 전, 실제 golden dataset을 확대하고 Layer P checker의 실 구현 계약을 별도 모델/서비스 경계로 확정하는 것이다.
