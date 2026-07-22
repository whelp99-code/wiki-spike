# P3-05 적대적 검증 20라운드

## Round 01 — 일부 object ref만 해석
공격: 목록 일부만 존재해도 나머지를 무시하고 발행한다.  
강화: 모든 ref 해석을 선행하고 하나라도 없으면 prepare 이전에 거부한다.  
불변식: 부분 ChangeSet은 generation을 만들지 않는다.

## Round 02 — changes_root 위조
공격: 유효한 object ref와 임의 root를 결합한다.  
강화: 해석된 revision을 canonical 정렬해 root를 다시 계산한다.  
불변식: root mismatch에서 pointer와 orphan 목록은 불변이다.

## Round 03 — 중복 object ref
공격: 같은 revision을 반복해 root·비용·감사를 교란한다.  
강화: object_refs와 command_ids는 unique·sorted 형식만 허용한다.  
불변식: 중복 입력은 fail-closed다.

## Round 04 — 순서 비결정성
공격: 같은 집합을 다른 순서로 보내 서로 다른 결과를 만든다.  
강화: builder는 정렬하고 adapter는 비정규 순서를 거부한다.  
불변식: 동일 의미는 동일 root와 changeset_id를 갖는다.

## Round 05 — revision 내용 교체
공격: object_ref는 유지하고 resolver 내용만 바꾼다.  
강화: claim 전체의 canonical revision hash와 self-authenticating ref를 대조한다.  
불변식: mutable resolver row가 서명 generation에 침투하지 못한다.

## Round 06 — changeset_id 재사용
공격: 같은 ID에 다른 root·payload를 붙인다.  
강화: ID를 canonical ChangeSet 본문에서 재계산한다.  
불변식: ID와 본문 불일치는 거부한다.

## Round 07 — prepare 전 stale parent
공격: 오래된 parent에서 새 generation을 자동 rebase한다.  
강화: ChangeSet adapter는 parent를 엄격 비교하고 retry_later로 반환한다.  
불변식: AcceptedChangeSet은 자동 rebase되지 않는다.

## Round 08 — prepare와 activate 사이 pointer 이동
공격: 준비 후 다른 publisher가 먼저 활성화한다.  
강화: SQLite activate CAS가 패자를 거부한다.  
불변식: 패자 candidate는 현 pointer를 덮어쓰지 못한다.

## Round 09 — prepare 직후 crash
공격: Git/DB prepare만 끝나고 프로세스가 죽는다.  
강화: prepare는 pointer를 이동하지 않으며 candidate는 retention ref로 보존된다.  
불변식: orphan은 비공개·미발행 상태다.

## Round 10 — activate 직후 crash
공격: pointer는 이동했지만 mandatory materialization 전 죽는다.  
강화: 같은 prepared activation 또는 replay가 signed snapshot에서 idempotent repair한다.  
불변식: 재시도는 동일 generation을 복구하며 새 generation을 만들지 않는다.

## Round 11 — 동일 ChangeSet 재전송
공격: timeout 뒤 같은 요청이 중복 generation을 만든다.  
강화: 현재 signed descriptor의 changeset_id를 확인해 기존 결과를 replay한다.  
불변식: 같은 changeset은 같은 generation 결과를 반환한다.

## Round 12 — descriptor에서 ChangeSet 누락
공격: 검증했지만 signed generation에는 결속하지 않는다.  
강화: `accepted_changeset` 전체를 descriptor에 포함하고 activate 전에 재확인한다.  
불변식: 서명된 descriptor가 정확한 root·refs·commands를 포함한다.

## Round 13 — manifest 복사·artifact 변조
공격: 정상 binding manifest를 변조 commit에 복사한다.  
강화: 기존 manifest verifier의 allowlist·artifact digest·재렌더 검증을 유지한다.  
불변식: descriptor 서명만이 아니라 실제 snapshot/wiki/citation이 결속된다.

## Round 14 — read-model digest 불일치
공격: candidate와 다른 index를 ready로 표시한다.  
강화: SQLite activate가 registered manifest의 digest와 DB status를 같은 트랜잭션에서 검사한다.  
불변식: mismatch에서 pointer는 불변이다.

## Round 15 — release commit 바꿔치기
공격: 다른 release OID를 activate 인자로 넣는다.  
강화: 등록된 release_commit_oid와 정확히 일치해야 한다.  
불변식: caller가 release binding을 우회하지 못한다.

## Round 16 — candidate retention 손실
공격: prepare orphan을 GC로 제거해 recovery를 막는다.  
강화: 기존 generation retention ref 생성 규칙을 그대로 사용한다.  
불변식: prepare candidate는 활성화 여부와 무관하게 검증 가능하다.

## Round 17 — workspace 교차 참조
공격: 다른 workspace resolver object를 참조한다.  
강화: resolver lookup key에 workspace_id를 포함한다.  
불변식: object ref는 workspace 경계를 넘지 않는다.

## Round 18 — 오류 세부정보 유출
공격: storage 예외에 경로·본문·키를 노출한다.  
강화: public CoreResult는 안정적인 error_code만 반환한다.  
불변식: 내부 예외는 외부 payload가 아니다.

## Round 19 — no-op을 새 generation으로 발행
공격: 기존 assertion만 담은 ChangeSet으로 churn을 만든다.  
강화: surviving assertion 집합이 parent와 같으면 pointer를 움직이지 않는다.  
불변식: no-op 결과는 `ok + noop=true`이며 generation churn이 없다.

## Round 20 — 기존 ingest 회귀
공격: prepare/activate 분리로 기존 자동 인제스트와 CAS retry가 깨진다.  
강화: legacy `publish()`는 동일 public signature와 bounded retry를 유지한다.  
불변식: 기존 전체 회귀와 신규 P3-05 계약 테스트를 함께 통과해야 한다.
