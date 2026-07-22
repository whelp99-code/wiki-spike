# P3-09 적대적 검증 20라운드

## Round 01 — Unknown schema를 최신으로 추정
공격: 미등록 version 999를 현재 schema와 비슷하다는 이유로 읽는다.  
강화: family/version의 정확한 registry entry가 없으면 fail-closed한다.  
불변식: unknown schema는 migration이나 write 경로에 들어오지 못한다.

## Round 02 — 구버전 bytes를 제자리 수정
공격: v1 artifact를 읽으며 payload와 version을 덮어쓴다.  
강화: read_latest는 새 in-memory artifact를 만들고 원본 canonical bytes를 보존한다.  
불변식: historical artifact identity는 migration으로 바뀌지 않는다.

## Round 03 — 구버전으로 신규 write
공격: 호환성 핑계로 v1 payload를 계속 생성한다.  
강화: family별 current write version 하나만 선택한다.  
불변식: write API는 항상 current version을 발행한다.

## Round 04 — Write version downgrade
공격: 설정 오류로 v2에서 v1으로 active writer를 되돌린다.  
강화: write version은 숫자상 단조 증가만 허용한다.  
불변식: registry가 구 schema 재도입을 자동 허용하지 않는다.

## Round 05 — Migration path 누락을 무시
공격: v1→v2 함수가 없는데 payload를 그대로 v2로 표시한다.  
강화: 모든 단계에 explicit migration이 없으면 MigrationPathError다.  
불변식: version label만 바꾸는 암묵 migration은 없다.

## Round 06 — Migration cycle·overshoot
공격: v1→v2→v1 또는 v1→v3로 current v2를 넘는다.  
강화: visited set, 증가 방향, target overshoot 검사를 수행한다.  
불변식: migration은 유한하고 current write version에서 정확히 끝난다.

## Round 07 — Validator가 canonical fixture를 변경
공격: 같은 schema version의 validator가 기본값을 몰래 추가한다.  
강화: 등록 시 fixture를 검증하고 결과가 fixture와 byte 의미상 동일한지 확인한다.  
불변식: schema code drift가 startup에서 드러난다.

## Round 08 — Fixture digest 바꿔치기
공격: schema 문서와 다른 fixture를 등록한다.  
강화: fixture artifact digest와 definition의 fixture digest를 정확히 대조한다.  
불변식: canonical test vector가 registry 정의에 결속된다.

## Round 09 — 미등록 kind 수용
공격: connector가 임의 `customer_secret_note` kind를 생성한다.  
강화: KindRegistry resolve/assert_creatable를 통과한 정의만 허용한다.  
불변식: 자유 문자열은 Memory kind가 아니다.

## Round 10 — Extension kind의 namespace 충돌
공격: 플러그인이 `note` 같은 built-in 이름을 재정의한다.  
강화: built-in set을 예약하고 extension에는 namespace를 요구한다.  
불변식: extension이 built-in 의미를 가로채지 못한다.

## Round 11 — 같은 kind의 다른 정의 재등록
공격: lifecycle states나 schema를 바꾼 정의를 동일 kind로 덮는다.  
강화: 동일 definition은 idempotent, 다른 definition은 거부한다.  
불변식: kind semantics는 registry lifecycle 안에서 명시적으로 버전된다.

## Round 12 — Creatable kind가 old schema 사용
공격: retired payload schema로 새 기억을 계속 만든다.  
강화: creatable kind는 family의 current write version에만 결속된다.  
불변식: 신규 object가 구 schema로 생성되지 않는다.

## Round 13 — Retired kind의 역사 삭제
공격: kind를 retire하며 과거 artifact도 읽지 못하게 한다.  
강화: retire는 creatable만 false로 바꾸고 schema read path는 유지한다.  
불변식: 더 이상 생성하지 않는 kind도 역사적으로 해독 가능하다.

## Round 14 — Key rotation 시 구 공개키 삭제
공격: active key를 바꾸며 old key record를 제거한다.  
강화: activation mapping만 교체하고 historical record는 immutable하게 보존한다.  
불변식: 회전 뒤에도 과거 signed_at의 서명을 검증한다.

## Round 15 — Wrong-domain signature replay
공격: generation 서명을 release 또는 checkpoint 검증에 사용한다.  
강화: signature frame에 purpose와 domain을 모두 포함한다.  
불변식: 같은 payload/key라도 다른 purpose/domain에서는 검증 실패한다.

## Round 16 — Key usage 범위 확대
공격: generation-only key를 plugin-manifest signing에도 사용한다.  
강화: key record의 purposes와 domains allowlist를 signed_at 검증 전에 확인한다.  
불변식: key material의 사용 범위는 registry policy를 넘지 못한다.

## Round 17 — 유효기간 밖 서명 수용
공격: 만료 후 생성된 서명을 old key라는 이유로 허용한다.  
강화: historical verify는 signature의 signed_at과 validity interval을 비교한다.  
불변식: 과거 검증 보존은 무기한 신규 서명 권한이 아니다.

## Round 18 — Unknown predecessor로 신뢰 체인 생성
공격: 존재하지 않는 key를 predecessor로 선언해 rotation lineage를 위조한다.  
강화: predecessor가 registry에 먼저 존재해야 새 record를 등록한다.  
불변식: key lineage는 끊어진 참조를 허용하지 않는다.

## Round 19 — Registry snapshot 비결정성·비밀 유출
공격: 등록 순서에 따라 digest가 달라지거나 private key bytes가 snapshot에 포함된다.  
강화: definitions/keys/active mapping을 안정 정렬하고 public material만 직렬화한다.  
불변식: 같은 registry 상태는 같은 snapshot digest이며 private material이 없다.

## Round 20 — Unit helper와 실제 계약 괴리
공격: migration/key helper만 테스트하고 public Core import·fixtures·strict schema에는 연결하지 않는다.  
강화: fixture 파일, registry APIs, cryptographic verify, kind validation, JSON Schema, boundary import를 함께 테스트한다.  
불변식: 전체 phase3-preflight Green 전에는 P3-09 Complete를 선언하지 않는다.
