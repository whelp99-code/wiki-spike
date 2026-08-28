# Wiki Memory 운영 원칙

## 1. 고정된 제품 방향

이 프로젝트의 방향은 다음 문장으로 고정한다.

> **일반 사용자는 `Wiki Memory.app`을 공부 없이 사용하고, 사람과 AI는 기존 암호화 Second Brain 코어 하나의 기억만 공유한다.**

기능은 이 방향 위에 추가한다. 구현 편의를 이유로 제품 방향을 다시 정의하지 않는다.

## 2. 역할 분리

```text
일반 사용자
   ↓
Wiki Memory.app
   ↓
얇은 제품 Facade
   ↓
기존 암호화 Second Brain / Encrypted Lifecycle Core
   ├─ LifecycleDatabase
   ├─ EncryptedContentStore
   ├─ dual per-artifact key custody
   ├─ signed generation
   ├─ revision / deletion / freshness authority
   └─ checked recall

AI 클라이언트
   ↓
read-only memory_recall / memory_source
   ↓
같은 Facade와 같은 Core
```

- 앱은 사용성을 담당한다.
- `composition/local_second_brain.py`는 화면의 간단한 동작을 기존 Core 명령으로 번역한다.
- 기존 Core만 저장·수정·삭제·회상 권한을 가진다.
- AI 도구는 같은 기억을 읽기만 한다.

## 3. 첫 운영 버전의 범위

지원한다.

- 앱 더블클릭 실행
- 첫 실행 자동 초기화
- 제목 없이 직접 메모 작성
- 첫 줄 기반 제목 자동 생성
- 입력 중 자동 저장
- 명시적으로 선택한 UTF-8 TXT/Markdown 파일 추가
- 최근 메모 및 로컬 검색
- 최초 원본 파일명·종류·전체 파일 범위·다이제스트 확인
- 같은 논리 메모 아래 revision 수정
- 전체 revision에 대한 명시적 삭제 및 키 폐기
- 패스프레이즈 암호화 백업과 검증된 복구
- AI용 읽기 전용 `memory_recall`, `memory_source`

지원하지 않는다.

- 외부 AI 모델 호출
- Vector DB 또는 Graph DB
- 폴더·메일·채팅 자동 수집
- 외부 네트워크 서버
- 외부 export 또는 발행
- 다중 사용자
- 자동 승인·자동 프로모션
- 영구 federation, query-time merge, legacy fallback

## 4. 절대 금지되는 구조

다음 구조는 다시 만들지 않는다.

```text
Wiki Memory.app
   ↓
별도 memory.sqlite3 / 별도 memory table / 별도 암호화 엔진
```

구체적으로 금지한다.

- `src/wiki_spike/operational/`에 SQLite 스키마를 만든다.
- 앱 전용 `memory`, `memory_token`, `memory_version` 같은 테이블을 만든다.
- 기존 Lifecycle DB와 앱 DB에 dual-write한다.
- 앱과 AI가 서로 다른 recall 경로를 사용한다.
- 기존 Core가 어렵다는 이유로 우회 저장소를 만든다.
- 과거 시스템을 fallback으로 제공한다.
- 새 구현에 맞춰 이 운영 원칙을 변경한다.

필요한 사용성 기능은 앱 또는 Facade에 추가하고, durable state 변화는 기존 Core 계약을 통해서만 수행한다.

## 5. 유일한 저장·회상 권한

현재 durable truth는 다음 기존 구조에만 존재한다.

- `canonical_artifact`
- `object_binding`
- `key_state`
- `state_delta`
- `accepted_changeset`
- `generation`
- `deletion_state`
- hash-chained `event_log`
- encrypted CAS
- platform / recovery ARK custody

수정 시:

- 논리 메모 ID는 유지한다.
- 새 revision을 생성한다.
- 새 revision만 `ACTIVE`가 된다.
- 이전 revision은 `SUPERSEDED`가 된다.
- 불변 암호문과 변경 증거는 보존한다.

삭제 시:

- 현재 및 이전 revision 전체에 deletion veto를 적용한다.
- CAS blob을 tombstone 처리한다.
- platform 및 recovery의 artifact key를 폐기한다.
- AI와 앱 모두 같은 checked read에서 즉시 거부한다.

## 6. 일반 사용자 사용 원칙

기본 기능에 다음 지식을 요구하지 않는다.

- 터미널
- Python, pip, uv, 가상환경
- JSON
- memory ID, artifact ID, revision ID
- SQLite, CAS, ARK, generation
- 해시 또는 서명 체계

일반 사용자는 다음만 알면 된다.

```text
앱 열기
→ 쓰기
→ 자동 저장
→ 단어로 찾기
→ 필요하면 수정·삭제·백업·복구
```

기술 정보는 `메모 근거`와 `Wiki Memory 정보`에 필요할 때만 표시한다.

## 7. AI 사용 원칙

AI에게 제공하는 기본 표면은 읽기 전용이다.

- `memory_recall`: 검색어로 현재 ACTIVE 기억을 찾는다.
- `memory_source`: 선택한 기억의 내용과 실제 최초 출처를 확인한다.

쓰기, 수정, 삭제, 백업, 복구 도구는 AI 표면에 노출하지 않는다. AI의 응답은 앱과 동일한 Core의 ACTIVE revision, deletion veto, freshness gate, CAS 무결성, ARK 존재, AES-GCM 인증을 통과해야 한다.

## 8. 유지해야 할 최소 검증

일상 운영 게이트에는 실제 장애를 막는 검증만 남긴다.

- Finder에서 앱 실행 및 GUI 이벤트 루프
- 첫 실행 자동 초기화
- autosave와 재시작 후 회상
- 기존 Core 테이블만 사용하고 병렬 memory table이 없음
- 앱과 AI가 같은 기억과 출처를 읽음
- AI 표면에 write tool이 없음
- ACTIVE revision만 제공되고 SUPERSEDED revision은 거부됨
- 삭제 후 모든 revision의 ARK 폐기 및 recall 거부
- CAS 변조와 잘못된 키·암호 거부
- SQLite와 CAS 무결성
- 파일·키·디렉터리 권한
- 입력·복구 경로 symlink 거부
- 암호화 백업과 빈 환경 복구
- 설치된 wheel의 V2 CLI, 앱, 지원 CLI, read-only 도구
- Mac `.app`의 bundled runtime, 서명, 실제 사용자 수명주기
- Secret scan

과거 Phase/Gate의 서명된 증거는 수정하거나 현재 제품 증명으로 재라벨하지 않는다. 필요한 경우 해당 release ref에서 별도로 검증한다.

## 9. 완료 정의

다음이 모두 사실일 때 현재 운영 버전이 완료다.

1. `Wiki Memory.app`을 더블클릭하면 별도 설치 지식 없이 열린다.
2. 첫 실행에서 기존 Core workspace가 자동으로 준비된다.
3. 제목 없이 입력하면 자동 저장된다.
4. TXT/Markdown 파일을 명시적으로 추가할 수 있다.
5. 재실행 후 단어로 찾을 수 있다.
6. 최초 출처와 현재 revision의 무결성을 확인할 수 있다.
7. 수정 후 같은 논리 메모 ID 아래 새 revision만 ACTIVE다.
8. 삭제 후 앱과 AI 모두 모든 revision을 회상하지 못한다.
9. 버튼으로 암호화 백업과 복구를 수행한다.
10. AI는 같은 기억을 read-only로 회상하고 출처를 확인한다.
11. 별도 memory DB, dual-write, fallback이 없다.
12. 운영 게이트와 설치 산출물 검증이 위 사실을 증명한다.

## 10. 변경 판단 질문

모든 다음 작업은 아래 순서로 판단한다.

1. 이 변경은 고정된 제품 방향에 직접 필요한가?
2. 기존 Core 위에 추가할 수 있는가?
3. 새 durable authority를 만들지는 않는가?
4. 일반 사용자 기본 흐름을 더 어렵게 만들지는 않는가?
5. 운영을 막는 실제 문제인가, 단지 미래 가능성인가?

하나라도 기준을 만족하지 않으면 구현하지 않거나 제거한다.
