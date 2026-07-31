# P0 착수 — 실 LLM 어댑터 골격 (첫 조각)
**목적**: 결정론 mock 위에 서 있던 파이프라인을 **실 LLM으로 교체 가능한 구조**로 전환.  
**결과**: **75개 테스트 통과** (68 + P0 슬라이스 7). 실 API 호출 없이 mock 클라이언트로 전 경로 검증.

---

## 이번 슬라이스 범위

| 모듈 | 내용 |
|---|---|
| `llm.py` | `LLMClient` 인터페이스 + `AnthropicClient`(실, 게이트됨) + `MockLLMClient`(결정론). exact model id는 **PENDING**(빈 값이면 실 경로가 실행을 거부). |
| `extraction.py` | `LLMExtractor`: 구조화 JSON 출력 → **Layer D(결정론)** 로 evidence quote가 소스에 실제 존재하는지 검증 → 미지원 claim **DROP(REFUSE-TO-WRITE)**. `DeterministicMockExtractor`와 동일한 `ExtractResult` 반환(드롭인 교체). |
| `verify.py` | Layer D(결정론 quote_hash 검사) + Layer P(entailment 인터페이스 + mock/실 impl) + **golden eval 하니스**(precision/recall/abstention). |
| `workspace.py` | `extractor=` 주입 가능 → 기본은 mock, 실 LLM 교체 가능. |

---

## 핵심 설계 결정

1. **mock과 실 LLM이 같은 인터페이스** → 테스트는 결정론(mock) 유지, 실제 경로만 LLM 검증. golden eval은 캐시 우회로 드리프트 탐지.
2. **Layer D는 결정론, Layer P는 확률적** — 명확히 분리. Layer D는 "quote가 소스 span에 verbatim 존재"를 해시로 검증(무료·재현). Layer P(entailment)는 정밀도/재현율로 관리하는 확률 계층.
3. **REFUSE-TO-WRITE** — LLM이 소스에 없는 사실을 넣으면 Layer D가 DROP. 테스트로 입증(`test_llm_extract_keeps_supported_drops_unsupported`).
4. **실 경로 게이트** — API 키 없거나 exact model id 미지정이면 `AnthropicClient`가 실행 거부(`test_real_client_refuses_*`).

---

## 남은 P0 작업 (사용자 결정 필요)

- **exact model id 확정** — selection eval로 extraction/verification/render 각 정확 id 고정. 현재 PENDING(빈 값).
- **API 키 연결** — `ANTHROPIC_API_KEY` 환경변수. 컨테이너는 `api.anthropic.com` 접근 가능하나 실제 호출·비용은 사용자 몫.
- **Layer P 실 LLM impl** — 인터페이스는 있음. 실 entailment 판정은 model id 확정 후.
- **golden 라벨셋 구축** — dev/audit 활동(런타임 게이트 아님, 뼈대 불변1 준수).

나머지 P0 축(source trust, parser 보안, 운영 안정성)은 이 LLM 관문 위에서 이어서 진행.

---

## 실 LLM 교체 예시

```python
from wiki_spike.workspace import Workspace
from wiki_spike.extraction import LLMExtractor
from wiki_spike.llm import AnthropicClient, LLMConfig

cfg = LLMConfig(extraction_model_id="<selection-eval로 확정한 exact id>")
ws = Workspace("/data/wiki", extractor=LLMExtractor(AnthropicClient(), cfg))
ws.ingest_and_publish("some_source.pdf.md")   # 실 LLM 추출 → Layer D 검증 → 발행
```
(위는 exact id + 키가 있을 때만 동작. 테스트/데모는 `MockLLMClient` 사용.)
