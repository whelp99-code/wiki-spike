# RALPLAN pass-three "교착" 트리아지 보고서

- 조사 시각: 2026-07-28 22:01~22:05 KST
- 대상 체크아웃: `/Users/jmpark/orca/Wiki-spike/wiki-spike` (branch `main`, 조사 시점 tip `edbb920`)
- 대상 터미널: `term_48b73d39-3806-4c70-ba23-7eb06921b275` ("GJC: Build Status and Final Path")
- 원본: `/tmp/p4-wiki-spike-deadlock-report.md` — `/tmp` 는 재부팅 시 소실되므로 리포지터리로 이관
- 관련 작업: Orca task `task_ae43f74d373e` (진단), `task_f72e2b3da55d` (보존)

---

## 1. 무엇을 기다리고 있었는가

**결론: 교착이 아니다. 그 터미널은 자기 자신이 만들 산출물을 만드는 중이었다.**

터미널은 GPT-5.6-Sol 을 돌리는 GJC 에이전트이며, `gjc ralplan` (consensus planning) 워크플로의
stage 3 을 실행 중이다.

- 세션 ID: `019f945b-5d94-7000-b6e9-534d890b35af`
- 산출물 디렉터리:
  `.gjc/_session-019f945b-5d94-7000-b6e9-534d890b35af/plans/ralplan/019f945b-5d94-7000-b6e9-534d890b35af/`
- 실행 중인 명령 (스크롤백에서 스트리밍 중):
  `gjc ralplan --write --stage final --stage_n 3 --artifact-env GJC_RALPLAN_ARTIFACT --json`

"pass three artifact" = ralplan **stage 3 (final pass)** 산출물이다. 다른 워커의 결과물이 아니라,
이 터미널 자신이 생성하는 계획 문서다. 화면의 `Awaiting pass three artifact` / `Finalizing pending
plan` 은 외부 대기 표시가 아니라 자체 생성 진행 표시였다.

### 생존 증거 (읽기 전용 관측)

| 시각 | latestCursor | 상태 |
|---|---|---|
| 22:00 경 | 19687 | running |
| 22:01 | 22437 | running |
| 22:02 (45초 후) | 23423 | running |

약 45초에 986행이 늘었다. 출력이 정지된 적이 없다.

### 산출물은 이미 생성 완료됨

`index.jsonl` 기준:

| stage | stage_n | created_at (UTC) | 파일 |
|---|---|---|---|
| post-interview | 3 | 2026-07-28T13:01:09.963Z | `stage-03-post-interview.md` (33,836 B) |
| final | 3 | 2026-07-28T13:01:32.929Z | `stage-03-final.md` (36,538 B) |

`state/ralplan-state.json` → `current_phase: "final"`, `active: true`,
`updated_at: 2026-07-28T13:01:32.926Z`, receipt `status: "fresh"`.
`state/active/ralplan.json` HUD → `summary: "persisted final stage 3"`, chip `pending=approval (warning)`.

즉 pass-three 산출물은 **조사 시점 기준 약 10초 전에 이미 디스크에 기록**되었다. 조사 당시 터미널은
그 위에 ADR 부록(`ADR_SUFFIX`)을 덧붙여 final 을 한 번 더 write 하는 반복 중이었다.

---

## 2. 자력 생성 가능 여부 판정 → **생성 불필요 · 생성 금지**

- **불필요**: 위와 같이 산출물이 이미 존재하고 인덱스·해시(`sha256`)까지 기록되었다.
- **금지 사유**: `.gjc/_session-019f945b-.../` 는 살아 있는 GJC 런타임이 쓰고 있는 상태
  디렉터리다. 외부에서 파일을 만들면 `index.jsonl` 의 sha256 체인과 `ralplan-state.json`
  의 `state_revision` / `content_sha256` receipt 를 깨뜨린다. 또한 `gjc ralplan --write` 는
  세션 소유 명령이라 다른 프로세스가 호출하면 revision 충돌이 난다.
- 따라서 **아무 파일도 생성하지 않았다.** 진단 작업은 전량 읽기 전용이었다.

### 외부에서 실제로 필요한 것 (유일한 진짜 게이트)

산출물 대기가 아니라 **사람의 승인 대기**가 남아 있다.

- `pending-approval.md` (36,538 B, `stage-03-final.md` 와 동일 내용)
- 문서 첫 줄: `**Status: BLOCKED FOR CONSENSUS; planning only.**`
- HUD chip: `pending = approval` (severity warning)

내용은 "RALPLAN-DR Revision 3 — Sole User-Facing Second-Brain Product" 이며, Option A
(adapter-led encrypted canonical ledger) 채택을 제안한다. 코드·테스트·CI·마이그레이션·릴리스를
일절 승인하지 않는 planning-only 문서다.

**필요한 외부 조치**: 오너가 `pending-approval.md` 를 읽고 승인/반려를 그 터미널에 직접
입력해야 한다. 이 승인은 제품 전체 방향(단일 serving authority, connectors 레이어 소유권,
Gate 8 증거의 제품 증거 전용 금지)을 확정하므로 워커가 대신 결정할 수 없다.

---

## 3. 미커밋 항목 분류 및 유실 위험

진단 시점(2026-07-28 22:0x)의 미커밋 11건 기준.

| # | 경로 | 성격 | 유실 위험 |
|---|---|---|---|
| 1 | `artifacts/conformance/encrypted-lifecycle/gate5/redteam/red-team-report.json` (M) | **작업 중 — 실제 산출물** | **높음** |
| 2 | `HANDOFF_TO_QWEN.md` (??) | 잔여물 (내용 진부화) | 낮음 |
| 3 | `.gjc/` (??) | 잔여물 — 단, **활성 세션 상태** | 낮음(커밋 대상 아님) / **삭제 절대 금지** |
| 4 | `.omo/` (??) | 잔여물 (폐기된 툴체인) | 없음 |
| 5-11 | `.DS_Store` × 7 (root, `artifacts/`, `artifacts/conformance/`, `docs/`, `schemas/`, `src/`, `tests/`) | 잔여물 (macOS 부산물) | 없음 |

### #1 red-team-report.json — 유일하게 보존이 필요한 변경

커밋된 버전과 워킹트리 버전의 차이가 **일관성 버그 수정**이다.

| | `adversarial_case_count` | `cases` 배열 실제 길이 |
|---|---|---|
| `edbb920` | 58 | **7** ← 불일치 |
| 워킹트리 | 58 | **58** ← 일치 |

커밋본은 58건이라고 선언해놓고 요약 7건만 나열한 상태였다. 워킹트리 변경은 `a-1`~ 형식의
개별 케이스 58건을 모두 채워 선언값과 맞춘다 (`+60 / -44`). mtime 2026-07-25 22:17 — Gate 5
red-team 정리 작업의 산출물이며, 3일간 커밋되지 않은 채 남아 있었다.

### #2 HANDOFF_TO_QWEN.md — 진부화된 잔여물

2026-07-25 23:52 작성. `현재 HEAD: 42a456c (G7 complete)`, `G008 🔴 active` 로 적혀 있으나
실제로는 그 뒤 Gate 8 이 완료되어 `GATE8_COMPLETION_KR.md` 가 `16eee5d` (2026-07-26)로
커밋되었다. 즉 이미 소임을 다한 문서다. 명령어 치트시트와 never-parallel-edit authority
목록(§6)만 재사용 가치가 있다. 남기면 후속 에이전트가 "Gate 8 미완"으로 오독할 위험이 있으나,
처분은 오너 판단 사항이므로 손대지 않았다.

### #3 `.gjc/` — 커밋하지 말고 무시 처리, 삭제 절대 금지

5.5 MB, `_session-*` 60여 개. 그중 `_session-019f945b-5d94-7000-b6e9-534d890b35af` 는
**진단 시점에 돌고 있던 터미널의 라이브 상태**이며 22:01 에도 쓰이고 있었다. 여기에 위 stage-03
산출물과 승인 대기 문서가 들어 있으므로, 지우면 pass-three 결과물이 통째로 사라진다.

### #4 `.omo/` — 안전한 잔여물

`run-continuation/ses_07133f121ffewGmAdmvwGUo6yf.json` 1개 파일, 4 KB, 2026-07-23.
OMA/OMO 스킬은 2026-07-22 제거되었으므로 죽은 툴체인의 잔여물이다.

### #5-11 `.DS_Store` × 7 — 순수 잔여물

Finder 부산물. `docs/`·`schemas/`·`src/`·`tests/` 는 07-24 01:33, 루트·`artifacts/` 계열은
07-27 14:28 생성. 가치 없음.

---

## 4. 후속 보존 조치 (2026-07-28 실행)

### 4.1 red-team-report.json 커밋 — `ce6e8b1`

커밋 전 검증:

| 검사 | 명령 | 결과 |
|---|---|---|
| JSON 파싱 | `json.load()` | OK |
| 선언/실제 일치 | `adversarial_case_count` vs `len(cases)` | 58 == 58 |
| id 중복 없음 | `len(set(ids))` | 58 |
| verdict 누락 없음 | 전 케이스 `verdict` 존재 | True |
| 비-PASS verdict | `{verdicts} - {"PASS"}` | 없음 |

digest pin 부재 근거:

- `edbb920` 판 sha256 `94d65bc0...` 문자열이 리포 어디에도 등장하지 않음.
- tracked 파일 중 `gate5/redteam` 을 참조하는 것이 없음 (`git grep -l`).
- 코드가 참조하는 conformance 하위 경로는 `artifacts/conformance/phase3` 와
  `artifacts/conformance/phase4` 뿐이며, `encrypted-lifecycle/` 은 어떤 테스트·스크립트·
  워크플로에서도 읽지 않는다.

따라서 이 변경은 Gate 8 artifact pin assertion 을 포함해 어떤 검증도 깨뜨리지 않는다.

### 4.2 `.gitignore` 보강

`.DS_Store` 를 무시 목록에 추가했다. 삭제가 아니라 무시 처리이므로 가역적이다.
`.gjc/` 와 `.omo/` 는 활성 세션 소유이므로 이번 범위에서 손대지 않았다.

### 4.3 미실행으로 남긴 항목

- `HANDOFF_TO_QWEN.md`: §3 #2 의 진부화 판정은 그대로 유효하나, 삭제·이관 여부는 오너 판단
  사항이므로 손대지 않았다. 처리한다면 삭제보다 헤더에 superseded 표기 후 `docs/` 이관을 권한다.
- `.omo/`: 죽은 툴체인 잔여물이지만 `.gitignore` 보강 범위 밖이라 미추적 상태로 남겼다.
- ralplan `pending-approval.md` 승인: §2 의 오너 결정 대기 건으로, 워커가 대신 처리할 수 없다.
