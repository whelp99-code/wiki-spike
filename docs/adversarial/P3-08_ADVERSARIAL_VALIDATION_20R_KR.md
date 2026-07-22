# P3-08 적대적 검증 20라운드

## Round 01 — In-process plugin의 Core 침해
공격: plugin이 같은 프로세스에서 DB·CAS·서명키 객체를 import한다.  
강화: manifest runner_mode를 out_of_process로 고정하고 runner에는 canonical bytes만 전달한다.  
불변식: plugin contract는 Storage 구현 객체를 노출하지 않는다.

## Round 02 — Manifest ID 바꿔치기
공격: 정상 manifest_id에 더 넓은 egress·quota를 붙인다.  
강화: manifest ID를 전체 canonical manifest에서 재계산한다.  
불변식: ID와 manifest 본문 불일치는 로드 단계에서 거부된다.

## Round 03 — 알 수 없는 Manifest 필드
공격: `network_admin=true` 같은 구현별 필드로 권한을 우회한다.  
강화: strict field allowlist와 JSON Schema additionalProperties=false를 사용한다.  
불변식: 미지원 manifest 확장은 fail-closed다.

## Round 04 — 문자열을 capability 배열로 오인
공격: `memory.read` 문자열이 문자별 capability tuple로 변환된다.  
강화: 역직렬화 시 list/tuple of non-empty strings만 허용한다.  
불변식: 배열 타입 혼동으로 capability가 생성되지 않는다.

## Round 05 — Workspace·Actor 토큰 재사용
공격: 다른 workspace 또는 사용자 토큰으로 plugin을 호출한다.  
강화: 기존 PolicyEngine의 workspace/actor scope를 호출 전에 적용한다.  
불변식: scope mismatch에서는 runner가 호출되지 않는다.

## Round 06 — Plugin invoke capability 누락
공격: 일반 memory.read 토큰만으로 임의 plugin을 실행한다.  
강화: `plugin.invoke:<plugin_id>` action을 별도 capability로 요구한다.  
불변식: plugin별 실행 권한이 없으면 실행되지 않는다.

## Round 07 — Manifest required capability 누락
공격: plugin이 memory.write가 필요한데 token에는 read만 있다.  
강화: manifest의 required_capabilities가 token actions의 부분집합인지 확인한다.  
불변식: plugin 자체 요구권한도 명시적으로 충족해야 한다.

## Round 08 — 민감도 Egress 초과
공격: internal-only plugin에 private/secret payload를 전달한다.  
강화: request sensitivity와 manifest egress lattice를 비교한다.  
불변식: 허용 egress보다 높은 데이터는 runner 직전에 차단된다.

## Round 09 — Egress none 우회
공격: network 없음 manifest에 payload를 넣고 로컬 plugin이 파일로 유출한다.  
강화: egress none은 payload가 완전히 빈 경우만 허용한다.  
불변식: 데이터 전달이 없는 호출만 no-egress로 분류된다.

## Round 10 — Oversized 요청 DoS
공격: 수백 MB payload로 worker memory를 고갈시킨다.  
강화: canonical request bytes를 계산해 manifest 상한 전에 검사한다.  
불변식: 초과 요청은 runner 호출 횟수를 증가시키지 않는다.

## Round 11 — 무제한 호출 비용 폭주
공격: 한 operation에서 같은 plugin을 반복 호출한다.  
강화: workspace+operation+plugin 단위 원자 quota를 사용한다.  
불변식: 상한 이후 호출은 runner에 도달하지 않는다.

## Round 12 — Deadline 경과 호출
공격: queue에 오래 머문 요청이 뒤늦게 실행된다.  
강화: gateway now와 request.deadline_at을 호출 전에 비교한다.  
불변식: 만료 요청은 실행되지 않는다.

## Round 13 — Runner timeout의 Core 정지
공격: plugin이 응답하지 않아 Core thread를 영구 점유한다.  
강화: manifest timeout을 bounded canonical integer로 제한하고 TimeoutError를 격리한다.  
불변식: timeout은 Core crash가 아니라 retry_later 결과다.

## Round 14 — Runner crash 전파
공격: subprocess/container 오류가 Core 예외로 전파된다.  
강화: runner 예외를 stable `plugin_crashed` 코드로 변환한다.  
불변식: plugin crash가 publication pointer나 Core 프로세스를 변경하지 않는다.

## Round 15 — Oversized 응답 DoS
공격: 작은 요청에 거대한 응답을 반환한다.  
강화: JSON decode 전에 raw response bytes 상한을 검사한다.  
불변식: 응답 상한 초과는 schema validator에 도달하지 않는다.

## Round 16 — Malformed·추가 필드 응답
공격: invalid UTF-8, JSON array, unknown control field를 반환한다.  
강화: UTF-8 JSON object와 정확한 response field set을 요구한다.  
불변식: 자유 형식 출력은 Core 계약이 아니다.

## Round 17 — 응답 Identity Confusion
공격: 다른 request/plugin/version/schema 결과를 현재 호출에 재사용한다.  
강화: request_id, plugin_id, plugin_version, output_schema_id를 모두 대조한다.  
불변식: response는 하나의 manifest와 request에만 결속된다.

## Round 18 — Output Schema와 Canonicalization 우회
공격: raw number·NaN·잘못된 구조를 output으로 반환한다.  
강화: Core canonicalizer 적용 후 allowlisted schema validator를 실행한다.  
불변식: plugin output은 검증 전에는 Memory나 ChangeSet이 아니다.

## Round 19 — Plugin이 Authority를 스스로 승격
공격: output에 `evidence_backed`, `declassify`, `approved`를 넣어 직접 반영한다.  
강화: PluginGateway 결과는 proposal/result이며 Command·Policy·ChangeSet 경계를 우회하지 않는다.  
불변식: plugin 문자열이 provenance·sensitivity·capability를 변경하지 못한다.

## Round 20 — Helper 테스트와 실제 Gateway 배선 괴리
공격: size·quota 함수만 단위 테스트하고 invoke 순서에는 연결하지 않는다.  
강화: runner 호출 횟수와 실제 Gateway 결과로 pre-invoke/post-invoke 차단을 검증한다.  
불변식: 전체 phase3-preflight Green 전에는 P3-08 Complete를 선언하지 않는다.
