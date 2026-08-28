# Wiki Memory 0.1.0

**앱을 열고 바로 쓰는, 내 Mac 전용 암호화 Second Brain**

`Wiki Memory`는 일반 사용자가 명령어를 배우지 않고 사용할 수 있는 Mac 앱입니다. 화면은 단순하지만, 저장·수정·삭제·회상은 프로젝트에 이미 구현된 Encrypted Lifecycle / Second Brain Core 하나가 담당합니다.

```text
Wiki Memory.app                         AI read-only tools
      │                                        │
      └────────── 같은 제품 Facade ───────────┘
                          │
         기존 암호화 Second Brain Core
 Lifecycle DB + encrypted CAS + dual ARK + signed generation
```

별도의 앱 전용 메모 DB, dual-write, legacy fallback은 없습니다.

## 일반 사용자 사용법

빌드된 `Wiki Memory.app`을 Finder에서 더블클릭합니다.

### 첫 실행

앱이 자동으로 다음 작업을 수행합니다.

- 기존 암호화 Core workspace 생성
- identity·fallback·서명 키 생성
- platform/recovery 이중 artifact-key 보관소 생성
- Lifecycle SQLite와 encrypted CAS 초기화
- 파일 권한과 무결성 확인

계정, 클라우드 연결, 터미널 설정은 필요하지 않습니다.

### 메모 작성

앱이 열리면 오른쪽 내용 칸에 바로 입력합니다.

- 제목은 비워도 됩니다.
- 첫 번째 의미 있는 줄이 자동 제목이 됩니다.
- 입력을 잠시 멈추면 자동 저장됩니다.
- 다른 메모를 선택하거나 앱을 닫을 때도 먼저 저장합니다.
- 평문 임시 파일을 만들지 않습니다.

### TXT·Markdown 파일 추가

`파일 추가…` 버튼으로 사용자가 직접 선택한 UTF-8 파일만 가져옵니다.

현재 지원 형식:

- `.txt`
- `.md`
- `.markdown`

폴더 감시, 이메일·채팅·Git 자동 수집은 현재 운영 범위가 아닙니다.

### 찾기

왼쪽 `메모 검색`에 기억나는 단어를 입력합니다.

- 검색어가 없으면 최근 메모를 표시합니다.
- 현재 `ACTIVE` revision만 검색합니다.
- 검색과 복호화는 이 Mac 안에서 수행합니다.
- 검색어와 본문을 외부 AI나 서버로 전송하지 않습니다.

현재 버전은 저장된 ACTIVE 메모를 로컬에서 복호화해 검색합니다. 별도의 평문 검색 인덱스나 Vector DB를 만들지 않습니다.

### 수정

메모 내용을 바꾸면 같은 논리 메모 아래 새 revision으로 자동 저장됩니다.

```text
논리 메모 ID 유지
기존 revision → SUPERSEDED
새 revision   → ACTIVE
```

기존 암호문과 변경 증거는 불변 이력으로 남지만, 앱과 AI는 새 ACTIVE revision만 제공합니다.

### 실제 출처 확인

`메모 근거`에서 다음을 확인할 수 있습니다.

- 최초 출처 이름
- 직접 메모인지 TXT/Markdown 파일인지
- 출처 범위 `WHOLE_SOURCE`
- 최초 원본 SHA-256
- 현재 내용 SHA-256
- 저장·수정 시각
- 이전 revision 수
- 현재 artifact/revision의 기존 Core 권한

파일을 수정한 뒤에도 최초 origin은 유지되고, 이번 수정의 revision source가 별도로 기록됩니다.

### 삭제

`삭제`를 누르고 확인하면 같은 논리 메모에 속한 현재 및 이전 revision 전체를 삭제 경로에 넣습니다.

- 즉시 deletion veto
- 모든 관련 CAS blob tombstone
- platform ARK 폐기
- recovery ARK 폐기
- 앱과 AI recall 거부
- hash-chained 삭제 이벤트 기록

삭제된 암호문 바이트가 보관 매체에 남아 있더라도 해당 artifact key가 양쪽 보관소에서 폐기되므로 복호화할 수 없습니다.

### 백업

`백업` 버튼에서 저장 위치와 12자 이상의 백업 암호를 정합니다.

백업은 다음 기존 Core 전체를 일관된 snapshot으로 묶습니다.

- Lifecycle SQLite
- encrypted CAS objects와 tombstones
- identity·서명·fallback key
- platform/recovery artifact-key custody
- manifest와 각 파일 digest

그 뒤 Scrypt로 백업 키를 만들고 AES-256-GCM으로 하나의 `.wkbak` 파일을 암호화합니다. 백업 암호는 앱에 저장하지 않습니다.

### 복구

`복구` 버튼에서 `.wkbak` 파일과 암호를 입력합니다.

복구 시 다음을 확인합니다.

- Scrypt/AES-GCM 인증
- archive 경로 안전성
- manifest에 기록된 파일만 존재하는지
- 각 파일 SHA-256
- CAS object `0444`, 키·DB `0600`, 디렉터리 `0700`
- SQLite integrity check
- encrypted CAS integrity scan
- 복구 후 기존 Core 운영 상태
- 병렬 memory table이 없는지

기존 workspace를 교체할 때는 이전 workspace를 별도 `pre-restore` 폴더에 보존합니다.

## AI가 같은 기억을 읽는 방법

AI용 표면은 읽기 전용이며 앱과 같은 Core를 사용합니다.

지원 도구는 정확히 두 개입니다.

```text
memory_recall  검색어로 ACTIVE 기억 찾기
memory_source  선택한 기억과 최초 출처 확인
```

쓰기, 수정, 삭제, 백업, 복구 도구는 AI 표면에 없습니다. 응답은 64KiB로 제한됩니다.

지원·연동 테스트용 예시:

```bash
printf '%s\n' '{"tool":"memory_recall","params":{"query":"복구 일정","limit":10}}' \
  | wiki-memory-read
```

일반 사용자는 이 명령을 사용할 필요가 없습니다.

## 왜 이 앱을 사용하는가

일반 메모 앱의 편리함과 기존 개인 메모리 Core의 권한·무결성 구조를 함께 제공합니다.

- Mac 앱으로 바로 작성하고 자동 저장합니다.
- 특정 AI 서비스에 기억을 종속하지 않습니다.
- 민감한 본문을 로컬에 암호화합니다.
- 기억의 최초 출처와 변경 revision을 확인합니다.
- 수정 후 과거 revision이 실수로 다시 제공되지 않습니다.
- 명시적 삭제가 앱과 AI에 동시에 적용됩니다.
- 백업과 복구를 직접 통제합니다.
- 앞으로 기능을 추가해도 저장 권한은 하나로 유지됩니다.

## 고정된 제품 경계

다음 구조는 변경하지 않습니다.

```text
일반 사용자 UI = Wiki Memory.app
Durable authority = 기존 Encrypted Lifecycle / Second Brain Core
AI access = 같은 Core의 read-only recall/source
```

현재 추가하지 않는 기능:

- 외부 모델 호출
- Vector DB / Graph DB
- 자동 수집 Connector
- 외부 export·발행
- 다중 사용자
- 자율 승인·프로모션
- federation·query-time merge
- legacy read-through fallback

자세한 원칙은 [`docs/OPERATING-PRINCIPLES.md`](docs/OPERATING-PRINCIPLES.md)에 고정되어 있습니다.

## 데이터 위치

기본 Mac 데이터 경로:

```text
~/Library/Application Support/Wiki Memory/data/
├── lifecycle.sqlite3
├── cas/
│   ├── objects/
│   └── tombstones/
├── keys/
│   ├── identity.key
│   ├── fallback-dek.key
│   ├── signing.key
│   ├── platform/
│   └── recovery/
└── .lock
```

앱 전용 `memory.sqlite3`, `memory`, `memory_token`, `memory_version` 테이블은 만들지 않습니다.

## 개발·지원 명령

일반 사용자는 아래 명령을 알 필요가 없습니다.

```bash
uv sync --extra dev --frozen

# 기존 authenticated V2 제품 경계
uv run wiki --help

# 같은 Core를 사용하는 지원 CLI
uv run wiki-memory-support --root /tmp/wiki-memory init
uv run wiki-memory-support --root /tmp/wiki-memory remember \
  --text "테스트 기억" --title "테스트"
uv run wiki-memory-support --root /tmp/wiki-memory recall "테스트"

# 데스크톱 headless 점검
uv run wiki-memory --check --root /tmp/wiki-memory-ui

# AI read-only 점검
printf '%s\n' '{"tool":"memory_recall","params":{"query":"테스트"}}' \
  | uv run wiki-memory-read --root /tmp/wiki-memory
```

## Mac 앱 빌드

독립 실행형 앱에는 Python 3.12, Tk, cryptography와 필요한 `wiki_spike` 코드를 포함합니다.

```bash
uv run python scripts/build_mac_app.py \
  --output "dist/Wiki Memory.app" \
  --json
```

빌드 검증은 다음을 수행합니다.

- bundled runtime 확인
- 앱 코드 서명 확인
- 기존 Core workspace 자동 초기화
- GUI 이벤트 루프 smoke
- 앱 작성 → AI read-only recall의 동일 권한 확인

## 검증

현재 운영 게이트:

```bash
bash scripts/run_operational_gate.sh
```

핵심 검증 범위:

- 기존 Core만 durable state로 사용
- parallel memory DB 재도입 차단
- 직접 입력·파일 추가·autosave
- 재시작 후 검색·회상
- 실제 origin citation
- ACTIVE/SUPERSEDED revision 분리
- 모든 revision 삭제·dual ARK 폐기
- 앱과 AI의 동일 checked read
- AI write tool 부재
- CAS/DB/권한/경로 경계
- 암호화 백업·복구
- 설치된 wheel과 Mac 앱
- Secret scan

과거 G3/G4/Gate 1~8 증거는 역사적 release evidence입니다. 현재 운영 성공으로 재라벨하지 않으며, 필요한 경우 해당 release ref에서 별도로 검증합니다.
