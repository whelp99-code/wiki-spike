# P3-00 적대적 검증 50라운드

**대상**: CI·경계·G2 checkpoint·비밀정보·패키징 게이트  
**기준선**: `026bc351020661cd91dc44b79e1d250d21e89a84`  
**판정**: 로컬 코드·기계 검증 PASS; branch-protection required-check는 외부 운영 확인 필요.

## Round 01 — 문서상의 G2 주장만 신뢰

- **공격**: 116개 테스트 문구만으로 Phase 3를 시작하면 기준선 변경을 탐지하지 못한다.
- **최종 방어**: commit/tree/ls-tree digest/test evidence를 결속한 canonical checkpoint와 detached Ed25519 signature를 추가했다.
- **기계 증거**: `test_committed_checkpoint_verifies`

## Round 02 — Baseline commit 치환

- **공격**: manifest의 baseline commit을 다른 정상 commit으로 바꾼다.
- **최종 방어**: checkpoint id, signature, trust record, local ancestor 검사를 모두 통과해야 한다.
- **기계 증거**: `test_trust_record_mismatch_rejected`

## Round 03 — Git tree 치환

- **공격**: commit 표기만 유지하고 tree 기대값을 바꾼다.
- **최종 방어**: 실제 commit tree SHA와 manifest 값을 비교한다.
- **기계 증거**: `test_tree_sha_mismatch_rejected`

## Round 04 — Tree listing 은닉 변경

- **공격**: blob/mode/path 구성을 바꾼 evidence를 제출한다.
- **최종 방어**: raw git ls-tree -r -z digest를 결속한다.
- **기계 증거**: `test_tree_listing_digest_mismatch_rejected`

## Round 05 — Tracked file count 불일치

- **공격**: listing 일부를 누락한다.
- **최종 방어**: listing digest 외에 파일 개수도 독립 검증한다.
- **기계 증거**: `test_tracked_file_count_mismatch_rejected`

## Round 06 — Manifest 확장 필드 주입

- **공격**: 검증기가 무시하는 필드로 의미를 바꾼다.
- **최종 방어**: top-level과 checkpoint 내부를 exact-key allowlist로 검증한다.
- **기계 증거**: `test_unknown_manifest_field_rejected`

## Round 07 — 중복 JSON key

- **공격**: 동일 key를 두 번 넣어 parser별 해석 차이를 유도한다.
- **최종 방어**: duplicate key를 fail-closed 처리한다.
- **기계 증거**: `test_duplicate_json_key_rejected`

## Round 08 — 비정규 JSON 표현

- **공격**: 공백·key order·Unicode 표현 차이로 서명 해석을 갈라놓는다.
- **최종 방어**: canonical UTF-8 byte와 정확히 일치해야 한다.
- **기계 증거**: `test_noncanonical_json_rejected`

## Round 09 — Raw number 모호성

- **공격**: JSON number로 언어별 정밀도 차이를 유발한다.
- **최종 방어**: checkpoint payload의 count·숫자는 canonical string만 허용한다.
- **기계 증거**: `test_raw_number_rejected`

## Round 10 — Checkpoint ID 위조

- **공격**: 내용과 무관한 임의 checkpoint id를 제시한다.
- **최종 방어**: canonical payload SHA-256을 재계산한다.
- **기계 증거**: `test_checkpoint_id_mismatch_rejected`

## Round 11 — Detached signature 변조

- **공격**: signature bytes를 교체한다.
- **최종 방어**: Ed25519 domain-separated verification 실패 시 중단한다.
- **기계 증거**: `test_corrupt_signature_rejected`

## Round 12 — Base64 관대한 파싱

- **공격**: garbage 문자를 signature에 섞는다.
- **최종 방어**: validate=True strict base64만 허용한다.
- **기계 증거**: `test_non_base64_signature_rejected`

## Round 13 — Public key 파일 손상

- **공격**: PEM을 비키 데이터로 교체한다.
- **최종 방어**: Ed25519 public key type과 파싱을 검사한다.
- **기계 증거**: `test_corrupt_public_key_rejected`

## Round 14 — Public key substitution

- **공격**: manifest와 다른 공개키를 제시한다.
- **최종 방어**: raw public key SHA-256 fingerprint를 manifest/trust에 고정한다.
- **기계 증거**: `test_public_key_fingerprint_mismatch_rejected`

## Round 15 — Trust record substitution

- **공격**: 유효 서명 세트를 공격자 repository 의미로 재포장한다.
- **최종 방어**: repository/commit/checkpoint/key fingerprint를 trust record와 대조한다.
- **기계 증거**: `test_trust_record_mismatch_rejected`

## Round 16 — Signing domain 재사용

- **공격**: 다른 protocol signature를 checkpoint에 재사용한다.
- **최종 방어**: wiki.phase2.checkpoint.v1 domain frame을 고정한다.
- **기계 증거**: `test_corrupt_signature_rejected`

## Round 17 — Evidence 파일 변조

- **공격**: manifest는 유지하고 test evidence만 바꾼다.
- **최종 방어**: evidence file SHA-256을 checkpoint에 결속한다.
- **기계 증거**: `test_evidence_digest_mismatch_rejected`

## Round 18 — Evidence path traversal

- **공격**: ../../ 경로로 repository 밖 evidence를 읽게 한다.
- **최종 방어**: 모든 sidecar 경로는 repository root 내부로 resolve한다.
- **기계 증거**: `test_evidence_path_escape_rejected`

## Round 19 — Regression 수 축소

- **공격**: 1개 테스트만 통과한 evidence를 PASS로 제출한다.
- **최종 방어**: G2 minimum 116과 evidence test_count를 비교한다.
- **기계 증거**: `test_regression_count_below_minimum_rejected`

## Round 20 — Baseline history 분리

- **공격**: 현재 HEAD와 무관한 commit evidence를 재사용한다.
- **최종 방어**: baseline commit이 HEAD ancestor인지 검사한다.
- **기계 증거**: `test_baseline_not_ancestor_rejected`

## Round 21 — Runtime의 SQLite 직접 import

- **공격**: Runtime이 Core port를 우회한다.
- **최종 방어**: AST lint가 controlplane 직접 import를 차단한다.
- **기계 증거**: `test_forbidden_imports_are_detected[controlplane]`

## Round 22 — Runtime의 CAS 직접 import

- **공격**: from-import 문법으로 storage를 우회한다.
- **최종 방어**: ImportFrom도 module prefix rule로 차단한다.
- **기계 증거**: `test_forbidden_imports_are_detected[cas]`

## Round 23 — Application의 signing 접근

- **공격**: Application이 signing authority를 획득한다.
- **최종 방어**: application layer의 signing import를 금지한다.
- **기계 증거**: `test_forbidden_imports_are_detected[signing]`

## Round 24 — Connector의 Git plumbing 접근

- **공격**: Connector가 refs/commit을 직접 조작한다.
- **최종 방어**: connector를 application layer로 분류해 gitrepo import를 차단한다.
- **기계 증거**: `test_forbidden_imports_are_detected[gitrepo]`

## Round 25 — UI의 Workspace 우회

- **공격**: UI가 CommandGateway 없이 Workspace를 호출한다.
- **최종 방어**: ui path에서 workspace import를 차단한다.
- **기계 증거**: `test_forbidden_imports_are_detected[workspace]`

## Round 26 — importlib 동적 우회

- **공격**: constant string import_module로 storage를 로드한다.
- **최종 방어**: AST Call 분석으로 constant dynamic import도 검사한다.
- **기계 증거**: `test_forbidden_imports_are_detected[importlib]`

## Round 27 — __import__ 우회

- **공격**: built-in dynamic import로 generation을 로드한다.
- **최종 방어**: __import__ constant argument를 검사한다.
- **기계 증거**: `test_forbidden_imports_are_detected[__import__]`

## Round 28 — 상대 import 우회

- **공격**: from .. import controlplane으로 prefix 검사를 피한다.
- **최종 방어**: relative import를 absolute module로 해석한다.
- **기계 증거**: `test_forbidden_imports_are_detected[relative]`

## Round 29 — 비상수 dynamic import

- **공격**: 실행 시 계산한 module 이름으로 storage를 로드한다.
- **최종 방어**: 보호 layer의 non-constant dynamic import 자체를 fail-closed 처리한다.
- **기계 증거**: `test_nonconstant_dynamic_import_fails_closed`

## Round 30 — Storage의 상위 계층 의존

- **공격**: storage가 memory_core를 import해 cycle을 만든다.
- **최종 방어**: storage→core/runtime/application dependency를 차단한다.
- **기계 증거**: `test_forbidden_imports_are_detected[storage-core]`

## Round 31 — Core의 Runtime 의존

- **공격**: Core가 Runtime 편의를 위해 상위 정책을 끌어온다.
- **최종 방어**: core→runtime/application을 차단한다.
- **기계 증거**: `test_forbidden_imports_are_detected[core-runtime]`

## Round 32 — Runtime의 Application 의존

- **공격**: Runtime이 UI/connector 타입에 결속된다.
- **최종 방어**: runtime→application을 차단한다.
- **기계 증거**: `test_forbidden_imports_are_detected[runtime-application]`

## Round 33 — 주석·문자열 오탐

- **공격**: 문서 속 import 문구 때문에 CI가 깨진다.
- **최종 방어**: 실제 AST import node만 판정한다.
- **기계 증거**: `test_comment_and_string_do_not_trigger`

## Round 34 — 문법 오류를 lint 회피로 사용

- **공격**: 파싱 실패 파일을 건너뛰게 한다.
- **최종 방어**: SyntaxError/Unicode error는 lint 전체 실패다.
- **기계 증거**: `test_syntax_error_fails_closed`

## Round 35 — Symlink Python source

- **공격**: 검사 경로 밖 파일을 symlink로 끌어온다.
- **최종 방어**: symlinked Python source를 fail-closed 처리한다.
- **기계 증거**: `test_symlinked_source_fails_closed`

## Round 36 — Private key 커밋

- **공격**: PEM private key가 tracked file에 들어간다.
- **최종 방어**: offline scan이 private-key header를 차단한다.
- **기계 증거**: `test_private_key_detected`

## Round 37 — GitHub token 커밋

- **공격**: PAT가 설정·테스트 파일에 들어간다.
- **최종 방어**: gh*/github_pat signature를 text/binary 모두 검사한다.
- **기계 증거**: `test_github_token_detected`

## Round 38 — Anthropic key 커밋

- **공격**: 실 API key가 저장소에 들어간다.
- **최종 방어**: sk-ant signature를 검사한다.
- **기계 증거**: `test_anthropic_key_detected`

## Round 39 — OpenAI key 커밋

- **공격**: router/OpenAI key가 들어간다.
- **최종 방어**: sk-/sk-proj signature를 검사한다.
- **기계 증거**: `test_openai_key_detected`

## Round 40 — 기타 provider credential

- **공격**: AWS·Slack·Google credential을 숨긴다.
- **최종 방어**: provider별 byte/text signature rule을 적용한다.
- **기계 증거**: `test_aws_key_detected / test_slack_token_detected / test_google_key_detected`

## Round 41 — 일반 secret assignment

- **공격**: 형식 미상의 key를 API_KEY=value로 커밋한다.
- **최종 방어**: config/source의 non-empty credential assignment를 차단한다.
- **기계 증거**: `test_nonempty_env_assignment_detected`

## Round 42 — Example placeholder 오탐

- **공격**: 빈 .env.example까지 차단해 scanner를 끄게 만든다.
- **최종 방어**: empty/pending/redacted/fake test values만 제한적으로 허용한다.
- **기계 증거**: `test_empty_env_assignment_allowed / test_placeholder_assignment_allowed`

## Round 43 — Symlink secret escape

- **공격**: tracked symlink가 repository 밖 credential을 가리킨다.
- **최종 방어**: absolute 또는 .. target symlink를 차단한다.
- **기계 증거**: `test_unsafe_symlink_detected`

## Round 44 — Binary 파일 내 token

- **공격**: NUL byte로 text scanner를 우회한다.
- **최종 방어**: binary byte signature도 검사하고 16MiB 초과 파일은 fail-closed한다.
- **기계 증거**: `test_binary_secret_signature_is_detected`

## Round 45 — Wheel에 runtime/secret artifact 포함

- **공격**: source는 깨끗하지만 wheel에 .key/sqlite/tests가 포함된다.
- **최종 방어**: wheel archive allowlist와 secret byte scan을 수행한다.
- **기계 증거**: `test_package_build_install_and_console_smoke`

## Round 46 — 설치된 CLI 부재

- **공격**: source import만 되고 console entry point가 누락된다.
- **최종 방어**: 격리 venv에 wheel을 강제 재설치하고 wiki --help를 실행한다.
- **기계 증거**: `test_package_build_install_and_console_smoke`

## Round 47 — PYTHONPATH가 package smoke를 속임

- **공격**: checkout metadata 때문에 pip가 이미 설치됐다고 오인한다.
- **최종 방어**: smoke subprocess에서 PYTHONPATH/PYTHONHOME을 제거하고 --force-reinstall한다.
- **기계 증거**: `test_package_build_install_and_console_smoke`

## Round 48 — 중첩 pytest 재귀

- **공격**: 검증기 테스트가 전체 pytest를 다시 실행한다.
- **최종 방어**: G2 rerun은 phase3 tests를 제외하고 CI regression은 별도 프로세스로 실행한다.
- **기계 증거**: `test_checkpoint_runtime_regression_gate_parses_count`

## Round 49 — Evidence 경로 비이식성

- **공격**: 로컬 절대 경로가 CI evidence에 들어간다.
- **최종 방어**: evidence log path는 repository-relative로 강제한다.
- **기계 증거**: `write_p3_00_evidence.py`

## Round 50 — CI만 있고 required check 미설정

- **공격**: workflow 실패에도 main merge가 가능하다.
- **최종 방어**: 필수 status check 이름과 branch protection 설정을 문서화했다. 외부 설정 확인 전 operational gate는 CONDITIONAL이다.
- **기계 증거**: `.github/BRANCH_PROTECTION_REQUIRED_CHECKS.md`

# 남은 정직한 한계

1. Bootstrap checkpoint key는 같은 PR에서 도입되므로 독립 조직 신원 서명이 아니다.
2. Offline scanner는 provider-side secret scanning을 대체하지 않는다.
3. Branch protection은 repository 외부 상태다.
4. P3-00은 G3가 아니며 P3-01 이전 기반만 고정한다.
