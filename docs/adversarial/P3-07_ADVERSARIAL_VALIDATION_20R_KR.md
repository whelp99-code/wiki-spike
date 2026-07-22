# P3-07 적대적 검증 20라운드

## Round 01 — Event를 논리 진실원으로 사용
공격: consumer DB의 이벤트만으로 다음 기억 상태를 만든다.  
강화: 이벤트는 signed Generation을 가리키는 파생 알림으로만 정의한다.  
불변식: event log만으로 authoritative generation을 만들 수 없다.

## Round 02 — Command와 Event 재사용
공격: 요청 envelope를 그대로 이벤트로 발행해 미승인 요청이 사실처럼 보인다.  
강화: 이벤트에는 승인된 generation 정보만 담고 Command payload를 포함하지 않는다.  
불변식: 요청은 이벤트도 상태 변화도 아니다.

## Round 03 — Inline 개인 데이터 유출
공격: event payload에 노트·이메일 본문을 넣어 로그와 broker로 확산한다.  
강화: strict schema는 `payload_ref`만 허용하고 unknown `payload`를 거부한다.  
불변식: OperationalEvent는 기억 본문을 운반하지 않는다.

## Round 04 — Event ID 위조
공격: 기존 event_id를 다른 generation·type에 붙인다.  
강화: event_id를 immutable field의 canonical hash로 재검증한다.  
불변식: ID와 본문 불일치는 생성·파싱 단계에서 거부된다.

## Round 05 — Duplicate 전달
공격: broker retry가 같은 projection invalidation을 여러 번 적용한다.  
강화: workspace+consumer+event_id dedupe를 checkpoint store에 결속한다.  
불변식: 성공한 event replay는 handler를 다시 호출하지 않는다.

## Round 06 — Sequence gap 무시
공격: seq 1을 못 받은 consumer가 seq 2부터 처리한다.  
강화: expected next sequence보다 큰 이벤트는 retry_later다.  
불변식: gap에서 checkpoint와 effect는 변하지 않는다.

## Round 07 — Parent chain 바꿔치기
공격: seq는 연속이지만 다른 branch의 parent를 연결한다.  
강화: event.parent_generation_id를 checkpoint generation과 대조한다.  
불변식: sequence와 parent chain이 모두 일치해야 처리한다.

## Round 08 — 늦게 도착한 과거 이벤트
공격: 이미 seq 3인 consumer에 새로운 seq 2 ID가 도착해 오래된 작업을 재수행한다.  
강화: checkpoint보다 낮은 seq는 handler 없이 stale-acknowledge한다.  
불변식: 과거 이벤트는 현재 effect를 되돌리지 않는다.

## Round 09 — Handler 성공 후 checkpoint crash
공격: 외부 side effect 뒤 checkpoint 저장이 실패해 replay에서 중복된다.  
강화: Phase 3 handler는 side effect를 실행하지 않고 deterministic ConsumerEffect만 준비한다.  
불변식: effect와 dedupe·checkpoint는 store에서 원자적으로 커밋된다.

## Round 10 — Checkpoint CAS 경쟁
공격: 두 worker가 같은 다음 이벤트를 동시에 처리한다.  
강화: commit은 예상 checkpoint equality를 검사한다.  
불변식: CAS 패자는 retry_later이며 effect가 저장되지 않는다.

## Round 11 — Poison event 무한 재시도
공격: 항상 실패하는 이벤트가 queue를 영구 정지시킨다.  
강화: bounded attempt 후 dead-letter와 checkpoint를 원자적으로 기록한다.  
불변식: poison event는 감사 가능하게 격리되고 다음 sequence가 진행된다.

## Round 12 — Dead-letter가 상태 손실을 숨김
공격: skipped 이벤트 때문에 consumer projection이 영구 틀어진다.  
강화: event가 비권위임을 고정하고 consumer는 signed generation에서 rebuild 가능해야 한다.  
불변식: dead-letter는 source artifact를 삭제하거나 변경하지 않는다.

## Round 13 — Replay 시작점 오류
공격: checkpoint seq 자체를 다시 읽거나 한 칸 건너뛴다.  
강화: log contract는 strictly-after checkpoint를 반환한다.  
불변식: replay는 마지막 성공 sequence 다음부터 시작한다.

## Round 14 — Replay 정렬 비결정성
공격: broker 반환 순서에 따라 gap 오판과 effect 순서가 달라진다.  
강화: replay log는 generation sequence와 event_id로 안정 정렬한다.  
불변식: 같은 log와 checkpoint는 같은 처리 순서를 만든다.

## Round 15 — Replay가 gap 뒤 이벤트도 처리
공격: seq 2 누락 뒤 seq 3·4를 계속 적용한다.  
강화: ReplayCoordinator는 첫 retry_later에서 중단한다.  
불변식: gap 이후 effect는 생성되지 않는다.

## Round 16 — Workspace checkpoint 혼합
공격: ws-1 seq 10이 ws-2의 첫 이벤트를 stale로 만든다.  
강화: checkpoint, seen, effect, dead-letter key에 workspace를 포함한다.  
불변식: consumer ID가 같아도 workspace 진행상태는 독립이다.

## Round 17 — 비정규 sequence 표현
공격: `01`, float, 음수 표현이 정렬·ID 계산을 교란한다.  
강화: generation_seq는 canonical non-negative integer string만 허용한다.  
불변식: sequence의 직렬화와 수치 순서가 일의적이다.

## Round 18 — Sensitivity 우회
공격: 임의 sensitivity 문자열로 downstream 정책을 우회한다.  
강화: event schema는 public/internal/private/secret만 허용한다.  
불변식: 알 수 없는 sensitivity는 fail-closed다.

## Round 19 — Outbox adapter의 비결정성
공격: 같은 outbox row가 실행 시각이나 random ID 때문에 다른 event가 된다.  
강화: factory는 row의 canonical immutable fields만 사용한다.  
불변식: 같은 outbox record는 같은 event_id를 만든다.

## Round 20 — 테스트 이름과 실제 배선 괴리
공격: dedupe helper만 단위 테스트하고 ReplayCoordinator·checkpoint store에는 연결하지 않는다.  
강화: duplicate, gap, chain, poison, CAS, replay, workspace를 end-to-end consumer 테스트로 검증한다.  
불변식: 전체 phase3-preflight Green 전에는 P3-07 Complete를 선언하지 않는다.
