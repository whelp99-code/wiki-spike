# P3-06 적대적 검증 20라운드

## Round 01 — 선택 projection 실패가 Core를 차단
공격: semantic builder 오류가 identity/chronology 전환까지 취소한다.  
강화: 필수 profile과 선택 profile의 성공 조건을 분리한다.  
불변식: 선택 실패에도 필수 두 포인터는 새 generation으로 전진한다.

## Round 02 — 필수 projection 절반만 전환
공격: identity CAS 성공 후 chronology CAS가 실패해 혼합 generation이 노출된다.  
강화: 두 필수 포인터를 단일 원자적 CAS 메서드로 갱신한다.  
불변식: identity와 chronology는 함께 전진하거나 둘 다 유지된다.

## Round 03 — Optional LKG 손실
공격: graph 재빌드 실패 시 기존 정상 포인터를 null로 바꾼다.  
강화: 실패는 현재·LKG 포인터를 변경하지 않는다.  
불변식: 선택 projection 실패 뒤에도 마지막 정상 generation을 조회할 수 있다.

## Round 04 — Staging 없이 포인터 갱신
공격: digest만 받은 consumer가 검증되지 않은 artifact를 publish한다.  
강화: 모든 pointer CAS는 등록된 staging manifest와 artifact equality를 검사한다.  
불변식: staged manifest에 결속되지 않은 artifact는 발행할 수 없다.

## Round 05 — Staging artifact 바꿔치기
공격: 같은 projection 이름에 다른 digest를 넣는다.  
강화: manifest의 전체 artifact dataclass와 publish 인자를 대조한다.  
불변식: 이름만 같은 artifact는 거부한다.

## Round 06 — Workspace 포인터 혼합
공격: ws-1의 semantic 포인터가 ws-2의 rebuild로 덮인다.  
강화: artifact, manifest, pointer key를 모두 workspace 범위로 고정한다.  
불변식: 같은 generation 이름과 빈 record 집합이어도 workspace artifact digest가 다르다.

## Round 07 — Source workspace 오염
공격: source adapter가 다른 workspace record를 반환한다.  
강화: coordinator와 builder가 record workspace를 이중 검증한다.  
불변식: 교차 workspace record가 projection root에 포함되지 않는다.

## Round 08 — 입력 순서로 digest 변동
공격: 동일 record 집합의 순서만 바꿔 다른 artifact를 만든다.  
강화: identity·chronology·optional record를 안정 키로 정렬한다.  
불변식: 논리적으로 같은 입력은 같은 records root를 갖는다.

## Round 09 — Spec 순서로 manifest 변동
공격: builder 등록 순서에 따라 manifest digest가 달라진다.  
강화: spec과 artifact를 projection name으로 정렬한다.  
불변식: spec 순서는 staging identity에 영향을 주지 않는다.

## Round 10 — 같은 generation 재빌드 churn
공격: 재시도가 새 pointer·digest를 계속 만든다.  
강화: 모든 artifact와 manifest identity를 canonical content로 계산한다.  
불변식: 동일 generation 재빌드는 pointer 값이 바뀌지 않는 idempotent 작업이다.

## Round 11 — 필수 builder 하나의 오류 은폐
공격: identity 실패를 optional 실패처럼 취급하고 chronology만 발행한다.  
강화: spec의 required 플래그와 정확한 minimum set을 검증한다.  
불변식: 필수 build 실패는 staging·pointer publication 이전에 retry_later다.

## Round 12 — Required set 확장으로 은밀한 결합
공격: semantic을 required로 표시해 Core publication을 다시 모델 공급자에 종속시킨다.  
강화: Phase 3 최소 profile은 identity와 chronology로 정확히 고정한다.  
불변식: 추가 required spec은 계약 오류다.

## Round 13 — Required CAS stale expected
공격: 두 포인터 중 하나의 expected 값만 오래됐는데 identity를 먼저 갱신한다.  
강화: store가 모든 expected pointer를 확인한 뒤 updates를 적용한다.  
불변식: CAS conflict에서 필수 포인터는 부분 변경되지 않는다.

## Round 14 — Optional CAS 경쟁
공격: 늦은 semantic build가 최신 semantic pointer를 덮는다.  
강화: 선택 projection도 독립 expected-pointer CAS를 사용한다.  
불변식: CAS 패자는 실패 목록에 기록되고 최신 LKG를 보존한다.

## Round 15 — Raw number와 비정규 데이터
공격: float·NaN·provider별 숫자 표현이 digest를 비결정적으로 만든다.  
강화: ProjectionRecord data를 Core canonicalizer로 검사하고 raw number를 금지한다.  
불변식: digest 입력은 null/bool/string/array/object canonical value만 허용한다.

## Round 16 — 빈 generation의 workspace 충돌
공격: record가 없으면 모든 workspace의 artifact가 같은 digest가 된다.  
강화: workspace_id를 records root와 artifact digest 양쪽에 포함한다.  
불변식: 빈 projection도 tenant identity를 잃지 않는다.

## Round 17 — Stale 결과에서 철회된 기억 노출
공격: semantic pointer가 과거 generation이라 현재 retracted object를 반환한다.  
강화: QueryGateway가 requested as-of generation의 authoritative lifecycle로 후처리한다.  
불변식: stale projection은 철회·tombstone을 우회하지 못한다.

## Round 18 — Source generation 부재를 빈 결과로 오인
공격: snapshot을 찾지 못했는데 빈 projection을 정상 발행한다.  
강화: source adapter 오류를 retry_later로 분리한다.  
불변식: 부재와 빈 generation은 서로 다른 상태다.

## Round 19 — Projection 모듈의 Storage 결합
공격: coordinator가 SQLite/Git/CAS를 직접 import해 Core 경계를 무너뜨린다.  
강화: Protocol과 순수 reference implementation만 `memory_core`에 둔다.  
불변식: public Core import는 storage implementation module을 로드하지 않는다.

## Round 20 — 기계 증거 없는 완료 선언
공격: 문서에 LKG·CAS·결정론을 적고 실제 테스트는 단순 happy path만 본다.  
강화: required/optional 실패, atomic CAS, workspace 격리, replay, staging tamper, stale post-filter를 자동 테스트한다.  
불변식: 전체 phase3-preflight Green 전에는 P3-06 Complete를 선언하지 않는다.
