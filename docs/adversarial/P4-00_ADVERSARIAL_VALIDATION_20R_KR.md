# P4-00 적대적 검증 20라운드

**대상**: G3 contract pin, annotated release tag, Runtime import boundary, CI bootstrap  
**기준선**: signed G3 `phase3-core-v1.0.0` / `fa7523344008c8c5bfbcc6aca790f297524f33dc`  
**판정**: 아래 공격을 모두 차단하고 P4-01 기능을 선행 구현하지 않는다.

## Round 01 — 문서상의 G3 완료만 신뢰

- **공격**: release 문구만 보고 임의의 Phase 3 파일을 Runtime 계약으로 사용한다.
- **방어**: signed checkpoint ID, source root, tag object, commit, public API와 파일 digest를 하나의 canonical pin에 결속한다.
- **기계 증거**: `test_committed_phase3_contract_pin_verifies_release_tag_and_g3`

## Round 02 — Pin ID와 본문 분리

- **공격**: pin 본문을 바꾸고 기존 ID를 유지한다.
- **방어**: canonical pin body의 SHA-256을 재계산한다.
- **기계 증거**: `test_pin_id_tamper_is_rejected`

## Round 03 — 유효한 다른 G3 checkpoint 대체

- **공격**: pin ID도 다시 계산해 다른 checkpoint를 승인한다.
- **방어**: P4-00 코드가 정확한 G3 checkpoint 상수를 고정하고 config와 대조한다.
- **기계 증거**: `test_checkpoint_substitution_is_rejected_even_with_recomputed_pin_id`

## Round 04 — Contract catalog 축소·digest 치환

- **공격**: 불리한 계약 파일을 목록에서 빼거나 digest를 바꾼다.
- **방어**: 정렬된 exact catalog와 예상 digest/length 전체를 비교한다.
- **기계 증거**: `test_contract_catalog_substitution_is_rejected`

## Round 05 — 동일 digest 주장과 길이 불일치

- **공격**: 파일을 덧붙이거나 잘라 parser 혼동을 유도한다.
- **방어**: SHA-256과 byte length를 독립적으로 검증한다.
- **기계 증거**: `test_contract_file_digest_and_length_are_both_enforced`

## Round 06 — Lightweight tag 이동

- **공격**: 쉽게 이동 가능한 lightweight tag를 release처럼 사용한다.
- **방어**: tag ref의 Git object type이 반드시 annotated `tag`여야 한다.
- **기계 증거**: `test_lightweight_release_tag_is_rejected`

## Round 07 — Annotated tag object 재작성

- **공격**: 같은 이름·commit으로 tag annotation이나 tagger를 바꾼다.
- **방어**: tag object SHA 자체를 pin한다.
- **기계 증거**: `verify_release_tag`, committed pin test

## Round 08 — Tag를 다른 commit으로 이동

- **공격**: tag object를 새로 만들어 다른 commit을 가리킨다.
- **방어**: dereferenced commit이 G3 merge commit과 정확히 일치해야 한다.
- **기계 증거**: `verify_release_tag`

## Round 09 — 현재 checkout Core drift

- **공격**: tag는 정상으로 두고 현재 `memory_core/contracts.py`만 변경한다.
- **방어**: 현재 checkout과 release worktree 모두에서 pinned files를 검증한다.
- **기계 증거**: contract file verifier tests

## Round 10 — Release worktree 대신 현재 package import

- **공격**: editable install이 tagged verifier의 import를 현재 PR 코드로 바꾼다.
- **방어**: tagged command subprocess의 `PYTHONPATH`를 release worktree `src`로 고정한다.
- **기계 증거**: committed full pin verification

## Round 11 — Worktree 실패 후 잔류

- **공격**: 검증 도중 crash가 Git worktree metadata와 임시 파일을 남긴다.
- **방어**: `finally`에서 강제 제거·prune·임시 디렉터리 삭제를 수행한다.
- **기계 증거**: `test_release_worktree_is_removed_on_exception`

## Round 12 — Runtime의 SQLite 직접 import

- **공격**: `memory_runtime`이 `wiki_spike.controlplane`을 import한다.
- **방어**: Runtime 전용 AST allowlist가 차단한다.
- **기계 증거**: `test_storage_and_unpinned_core_imports_are_rejected`

## Round 13 — Runtime의 CAS/Git/Signing 직접 import

- **공격**: 저장·발행·서명 구현을 직접 가져와 Core 정책을 우회한다.
- **방어**: 모든 `wiki_spike` module을 default-deny하고 두 Core module만 허용한다.
- **기계 증거**: parametrized Runtime boundary tests

## Round 14 — Core package root를 통한 내부 API 우회

- **공격**: `from wiki_spike.memory_core import ...`로 내부 구현을 가져온다.
- **방어**: package root도 allowlist 밖이므로 거부한다.
- **기계 증거**: Runtime boundary root-import fixtures

## Round 15 — Dynamic import 우회

- **공격**: `importlib.import_module` 또는 `__import__`를 사용한다.
- **방어**: constant target을 검사하고 nonconstant dynamic import는 fail-closed한다.
- **기계 증거**: dynamic import boundary tests

## Round 16 — 문법 오류·symlink로 lint 회피

- **공격**: parser가 건너뛸 파일이나 repository 밖 symlink를 둔다.
- **방어**: SyntaxError, decoding failure, symlink source는 전체 gate 실패다.
- **기계 증거**: syntax/symlink tests

## Round 17 — P4-00에서 Runtime 계약을 성급히 확정

- **공격**: 후속 설계 전 임시 요청 구조를 production schema로 굳힌다.
- **방어**: `runtime-contracts.schema.json`은 모든 instance를 거부한다.
- **기계 증거**: `test_runtime_schema_is_fail_closed_until_p4_01`

## Round 18 — Phase 4 추가 파일 때문에 G3를 실패로 오인

- **공격**: evolving checkout을 signed G3 inventory와 직접 비교한다.
- **방어**: historical G3 workflow와 tests는 immutable tag worktree에서 실행한다.
- **기계 증거**: Phase 3 workflow and immutable-release tests

## Round 19 — Phase 3 CI만 통과하고 Runtime gate 생략

- **공격**: 기존 required check만 통과해 Runtime boundary 위반을 병합한다.
- **방어**: P3 preflight에도 pin/boundary를 넣고 별도 P4-00 check를 게시한다.
- **기계 증거**: workflow/tooling tests

## Round 20 — P4-00을 Phase 4 기능 완료로 과장

- **공격**: skeleton과 CI만으로 Recall·Decision·Model Runtime 완료를 선언한다.
- **방어**: conformance report가 P4-01 이후 기능, Phase 5, Production readiness를 명시적으로 제외한다.
- **기계 증거**: `test_conformance_report_preserves_phase_boundary`

# 남은 정직한 한계

1. Branch/tag protection은 GitHub 외부 설정이며 repository code만으로 강제할 수 없다.
2. ProjectionPort는 frozen G3에 없어서 Phase 4 facade로 정의했다.
3. P4-00은 contract pin과 경계만 구현하며 Runtime 기능 품질을 검증하지 않는다.
4. 모델·비용·회상·결정·질문·선제 제안은 후속 PR의 별도 적대적 검증 대상이다.
