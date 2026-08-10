# Second Brain 라이브 흡수·전환·폐기 실행 체크리스트

## 목적과 양보할 수 없는 결과

이 문서는 planning-only `RALPLAN-DR Revision 3`을 대체하지 않는 운영 실행 체크리스트다. 해당 계획은 `BLOCKED FOR CONSENSUS`이며 승인 계획이 아니다. 현행 로컬 code/test/doc closure만 사용자의 2026-08-10 `$go` 범위에 들어간다. live I/O, import, cutover, route switch, revoke, delete 또는 Canary/증거 조작은 그 `$go`로 인가되지 않는다.

- final workspace만 serving authority다. federation, query-time fallback, dual-write, per-request merge는 금지한다.
- source별 native ID, revision, watermark, tombstone, dedupe-root, citation, hash를 대사하고 source를 쓰지 않는 isolated restore로 증명한다.
- credentials/keychains/hidden reasoning은 절대 흡수하지 않는다. model cache와 `Docker.raw`는 rebuildable이며 memory import가 아니다.
- `PLAN_COMPLETE`/`CODE_COMPLETE`/focused test rc `0`은 live I/O, route switch, credential revocation, decommission 권한이 아니다.

## 상태 범례

- `[x] PLAN_COMPLETE` — 승인 계획과 기준 hash가 확인되었다. 운영 권한은 아니다.
- `[x] CODE_COMPLETE` — 코드 또는 control receipt가 존재한다. 라이브 실행 결과는 아니다.
- `[x] OPERATION_COMPLETE` — 비파괴 운영 절차와 그 증거가 완료되었다. 후속 live 권한은 아니다.
- `[>] OPERATION_IN_PROGRESS` — 현재 승인되어 실행 중이며 보호해야 하는 작업이다.
- `[!] DRIFTED` — 권위 있는 값들이 불일치한다. signed reconciliation 전에는 진행할 수 없다.
- `[?] UNVERIFIED/UNKNOWN` — 경로 또는 주장 일부는 보였으나 이 closure의 독립 검증으로 provenance/authority/effect를 확정하지 못했다.
- `[ ] NOT_STARTED` — 작업이 시작되지 않았다.
- `[⊘] NOT_AUTHORIZED` — 서명, 사람 승인, source 권한 또는 구현이 없어 실행할 수 없다.

## 권위와 기준선

| 항목 | 기준 |
|---|---|
| planning-only 입력 | `.gjc/_session-019f945b-5d94-7000-b6e9-534d890b35af/plans/ralplan/019f945b-5d94-7000-b6e9-534d890b35af/pending-approval.md` — `BLOCKED FOR CONSENSUS`, 승인/실행 권한 없음 |
| 계획 SHA-256 | `fc056bd90354b4f173228a82be654b48fc7894f15776c9f1f70e69158a259164` — planning input 식별값일 뿐 `PLAN_COMPLETE` 또는 approval가 아님 |
| 기준 branch / HEAD | `docs-root-cleanup` / `340ac67af852c189b238801f3308191b8cbd96d2` `[x] PLAN_COMPLETE` |
| Gate 8 | Canary run `31314519580`, 같은 HEAD, `in_progress` `[>] OPERATION_IN_PROGRESS` |
| code/control receipts | 아래 G015–G018 경로/다이제스트는 저장소 존재만 확인한 정적 증거다. live success, production switch, decommission 권한이 아니다. |
| 시스템 감사 | `docs/reports/MAC_DATA_AGENT_SYSTEM_AUDIT_KR.html` 존재 `[x] PLAN_COMPLETE` |
| 운영 차단 | DB-02, DB-03, DB-07은 문서상 `UNRESOLVED`; live adapter, migration, cutover, deletion은 인가되지 않았다. |

기준선 읽기 argv는 다음과 같다. 이 문서는 명령을 실행했다는 주장을 하지 않는다.

```sh
git status --short
git branch --show-current
git rev-parse HEAD
shasum -a 256 .gjc/_session-019f945b-5d94-7000-b6e9-534d890b35af/plans/ralplan/019f945b-5d94-7000-b6e9-534d890b35af/pending-approval.md
gh run view 31314519580 --json status,conclusion,headSha,url
```

## 보호 자산과 금지 작업

| 보호 자산 | 상태 | 금지 작업 |
|---|---|---|
| Gate 8 Canary run `31314519580` | `[>] OPERATION_IN_PROGRESS` | relabel, alter, restart, cancel, copy, alias, ownership claim, product proof로 대체 |
| PID `94446`, Runner PID `5505` | `[>] OPERATION_IN_PROGRESS` | kill, restart, 환경 변경, artifact 이동 |
| durable state 및 Canary artifacts | `[>] OPERATION_IN_PROGRESS` | 삭제, 정리, 덮어쓰기, 수동 복구 흉내 |
| 공유 worktree의 무관 추적·미추적 변경 | 공유 상태 | reset, restore, clean, 광범위 staging, 무관 파일 수정 |

`rm`, `git clean`, `git reset --hard`, `git checkout --`, container/volume prune, source purge, route switch, live adapter 인증, migration import, external export, Gate 8 제어는 이 단계에서 금지한다.

## 공유 root 관찰 기준선과 전용 canonical worktree 규칙

공유 root는 observation-only다. 편집 완료 시 `LC_ALL=C git status --short | shasum -a 256`으로 계산한 canonical status snapshot digest는 `18b55e29a311fc0822c166448960f352112458e27dac3c49047e4fc254c3ade1`이다. 이 digest는 shared root의 file-content hash가 아니라 status text bytes hash다.

현재 shared-root status allowlist는 다음 `git status --short` path/prefix 전부다. 다른 path가 나타나면 shared-root status drift이며 append-only checkpoint에 기록하고 조사 전에는 mutable work를 시작하지 않는다.

```text
artifacts/conformance/second-brain/db-decision-signing-red-team-v1.json
artifacts/conformance/second-brain/db-decision-signing-red-team-v2.json
artifacts/conformance/second-brain/db-decision-signing-red-team-v3.json
artifacts/conformance/second-brain/db04-recall-red-team-v1.json
artifacts/conformance/second-brain/db04-recall-red-team-v2.json
artifacts/product-release/second-brain-v1/decisions/DB-06-model-a.json
artifacts/product-release/second-brain-v1/decisions/DB-08-archive.json
artifacts/product-release/second-brain-v1/evidence/db-04-conflict-behavior-go-body-v1.json
artifacts/product-release/second-brain-v1/evidence/db-04-conflict-behavior-go-body-v2.json
artifacts/product-release/second-brain-v1/evidence/db-04-conflict-behavior-go-bundle-v1.json
artifacts/product-release/second-brain-v1/evidence/db-04-conflict-behavior-go-bundle-v2.json
artifacts/product-release/second-brain-v1/evidence/db-06-model-a-no-go-bundle-v1.json
artifacts/product-release/second-brain-v1/evidence/db-08-archive-no-go-bundle-v1.json
artifacts/product-release/second-brain-v1/governance/
artifacts/product-release/second-brain-v1/withdrawn/
docs/planning/
docs/reports/MAC_DATA_AGENT_SYSTEM_AUDIT_KR.html
docs/reports/ROADMAP_KR.html
docs/reports/SECOND_BRAIN_WORKFLOW_OVERVIEW_KR.html
test-results/
uv.lock
```

`docs/planning/`은 observed prefix이며, 이 author의 허용 edit는 이 문서 하나다. `git status --short`는 untracked directory prefix만 출력하므로 이 문서의 후속 content edit가 status text를 바꾸지 않아 self-authored documentation을 잘못 freeze하지 않는다. 종료 시 같은 read-only pipe를 다시 실행해 digest를 checkpoint에 기록한다.

`BASE-05`는 코드 전(pre-code) worktree/status guard다. CODE row는 오직 이 guard에만 의존한다. `BASE-06`은 CODE-01/02 뒤의 관찰 checkpoint이며 CODE row의 선행조건이 아니다. source artifact, signed record, receipt, ledger, route, retention 상태를 만들거나 변경하는 operational row는 별도 dedicated canonical worktree와 자신의 manual authority에 의존한다. Gate 8은 이 규칙의 실행 대상이 아니라 비간섭 관찰 대상이다.

## 명령 contract fields

모든 metavariable 값은 signed runbook/receipt에 기록한다. secret value 자체는 기록하지 않는다.

| field | 값과 제약 |
|---|---|
| `DEDICATED_WORKTREE` | `/Volumes/DevSpace/orca/workspaces/wiki-spike/trevally`; separate dedicated worktree의 canonical absolute path이며 repository root/qwen/collector와 realpath가 달라야 함 |
| `DEDICATED_BRANCH`, `DEDICATED_HEAD`, `DEDICATED_BASELINE_STATUS_DIGEST` | `whelp99-code/trevally`, `340ac67af852c189b238801f3308191b8cbd96d2`, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; initial canonical `git status --short` bytes SHA-256 |
| `DEDICATED_CODE01_STATUS_DIGEST` | `8493b30d8ae6da9a2e8926185461314a1512ed7e4767c83c76f3103a358d3e7c`; CODE-01 checkpoint의 canonical status bytes SHA-256이며 allowlist는 `scripts/second_brain_contract_resolver.py`, `tests/second_brain/test_contract_resolver_cli.py`, `tests/second_brain/test_contract_resolver_red_team.py` 세 untracked file뿐이다. `.serena/`은 ignored/preserved observation-only다. |
| `DEDICATED_CODE02_STATUS_DIGEST` | `156f96662368b63fc9367ce54a107546b45ac6e46302421df4b575992cf7f6a4`; CODE-02 checkpoint의 canonical status bytes SHA-256이며 allowlist는 CODE-01의 세 files와 `src/wiki_spike/memory_core/second_brain_ports.py`, `scripts/second_brain_cohort_boundary_scan.py`, `tests/second_brain/test_cohort_boundary_scan.py`, `tests/second_brain/test_cohort_boundary_scan_red_team.py` 네 files다. `.serena/`은 ignored/preserved observation-only다. |
| `LEDGER` | dedicated worktree 안의 append-only converge JSON ledger file; root `repository`은 `/Volumes/DevSpace/orca/Wiki-spike/wiki-spike`, every item `worktree`는 `DEDICATED_WORKTREE`이고 `repository`과 같으면 안 됨 |
| `RECORD`, `RECORDS_DIR`, `RESOLVED_SCOPE`, `EXPECTED_SCOPES`, `AGGREGATE`, `TRUSTED_BINDINGS`, `EVIDENCE_MANIFEST`, `NOW_RFC3339`, `RESOLUTION_RECEIPT` | signed decision record, record directory, scope/expected scopes, signed aggregate, trusted owner/approver binding, evidence freshness manifest, RFC3339 UTC time, resolution receipt |
| `SHADOW_DB`, `RETENTION_AUTHORITY_ENDPOINT`, `MEASUREMENT_PUBLIC_KEY`, `MEASUREMENT_KEY_FINGERPRINT`, `CHECKPOINT`, `SHADOW_SAMPLE` | deployment measurement DB, `retention-authority://` endpoint, public verification key, key fingerprint, monotonic checkpoint, one signed sample |
| `SOURCE_MANIFEST`, `CAPABILITY_MANIFEST`, `BENCHMARK_MANIFEST`, `HOLDOUT_MANIFEST`, `CONTRACT_DIGEST_FILE` | signed manifests and a file containing only resolved contract digest |
| `SOURCE_INVENTORY`, `COHORT_INVENTORY`, `COHORT_MANIFEST`, `BACKUP_MANIFEST`, `RESTORE_TARGET`, `RECALL_SAMPLE`, `RECON_RECEIPT` | immutable inventories, signed one-source cohort manifest, backup manifest, empty isolated restore target, deterministic sample specification, reconciliation receipt |
| `DENY_CLASS_SCHEMA`, `SOURCE_EXPORT`, `COHORT_PAYLOAD`, `COHORT_DB`, `COHORT_WAL`, `COHORT_CAS`, `COHORT_LOG_DIR`, `COHORT_RECEIPT`, `BOUNDARY_SCAN_RECEIPT` | deny schema, export, payload, DB/WAL/CAS/log surfaces, cohort receipt and scan receipt |
| `CUTOVER_RUNBOOK`, `CUTOVER_DECISION`, `ROUTE_AUTHORITY`, `ROUTE_TARGET`, `GENERATION_DIGEST`, `ROUTE_VERSION`, `ROLLBACK_RECEIPT`, `ROUTE_REHEARSAL_RECEIPT`, `ROUTE_SWITCH_RECEIPT`, `ROUTE_POSTCHECK_RECEIPT` | signed runbook/decision, authenticated authority, exact target/generation/version, rollback/rehearsal/switch/post-check receipts |
| `ACTIVATION_RECEIPT`, `RETENTION_END_RFC3339`, `CONSERVATION_RECEIPT`, `ALLOWLIST_DIGEST`, `CONSENT_TRANSFER_RECEIPT`, `DECOMMISSION_CERTIFICATE` | trusted activation proof, activation + exactly 90×24 hours UTC, conservation/allowlist/consent transfer receipts, signed certificate |

## BASE — 기준선·보호·dedicated worktree

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| BASE-01 | 없음 / AUTONOMOUS | `[!] DRIFTED` | planning-only 입력 | `shasum -a 256 .gjc/_session-019f945b-5d94-7000-b6e9-534d890b35af/plans/ralplan/019f945b-5d94-7000-b6e9-534d890b35af/pending-approval.md` | rc `0`, `fc056bd90354b4f173228a82be654b48fc7894f15776c9f1f70e69158a259164`는 식별값이다. 파일 상태는 `BLOCKED FOR CONSENSUS`; approval/권위로 해석하면 실패 | 변경 없음 / 없음 |
| BASE-02 | BASE-01 / AUTONOMOUS | `[x] PLAN_COMPLETE` | shared-root observation snapshot | `LC_ALL=C git status --short | shasum -a 256` | rc `0`, digest `18b55e29a311fc0822c166448960f352112458e27dac3c49047e4fc254c3ade1`; status path/prefix가 allowlist 밖이면 새 append-only drift checkpoint를 추가 | shared root 변경 없음 / 없음 |
| BASE-03 | BASE-02 / MANUAL | `[>] OPERATION_IN_PROGRESS` | Gate 8 / PID `94446` / Runner `5505` | `gh run view 31314519580 --json status,conclusion,headSha,url` | rc `0`, 관찰만; run/PID/artifact 제어는 실패 | owner 상태 전달 / 없음 |
| BASE-04 | BASE-01 / AUTONOMOUS | `[?] UNVERIFIED/UNKNOWN` | G015–G018 receipts, system audit | 아래 경로/다이제스트는 발견했으나 receipt의 signer/provenance/current authority와 live effect는 이 closure에서 검증하지 않았다 | 존재 확인을 live success로 해석하면 실패 | artifact 불변 / 없음 |
| BASE-05 | BASE-02 / MANUAL | `[x] OPERATION_COMPLETE` | **pre-code** dedicated canonical worktree guard | `git worktree list --porcelain`; `realpath "/Volumes/DevSpace/orca/workspaces/wiki-spike/trevally"`; `git -C "/Volumes/DevSpace/orca/workspaces/wiki-spike/trevally" branch --show-current`; `git -C "/Volumes/DevSpace/orca/workspaces/wiki-spike/trevally" rev-parse HEAD`; `LC_ALL=C git -C "/Volumes/DevSpace/orca/workspaces/wiki-spike/trevally" status --short | shasum -a 256` | all rc `0`; canonical path exact, branch=`whelp99-code/trevally`, HEAD=`340ac67af852c189b238801f3308191b8cbd96d2`, status digest=`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. `.serena/` exists but `.gitignore` ignores it; it is observation-only allowlisted and must not be modified/deleted | no reset/clean/restore/rebase/stage/push; `.serena/` preserved / 없음 |
| BASE-06 | BASE-05, CODE-01, CODE-02 / AUTONOMOUS | `[x] OPERATION_COMPLETE` | **post-CODE-01/02** dedicated status checkpoint | `LC_ALL=C git -C "$DEDICATED_WORKTREE" status --short | shasum -a 256`; `git -C "$DEDICATED_WORKTREE" status --short` | rc `0`, digest=`156f96662368b63fc9367ce54a107546b45ac6e46302421df4b575992cf7f6a4`; exact allowlist는 CODE-01의 세 files와 CODE-02의 `second_brain_ports.py`, cohort boundary scanner, unit/red-team test 네 files이며 `.serena/`은 ignored/preserved observation-only다. CODE-01/02 완료 후 기록한 checkpoint이며 CODE-01/02의 dependency가 아니다. | allowlist 밖 drift면 stop하고 append-only checkpoint 기록 / 없음 |

### G015–G018 receipt inventory (static discovery only)

The following paths and SHA-256 values are discoverable repository evidence. Missing from this closure are independently verified signer identity, provenance chain, current applicability, and any live/import/cutover effect; therefore the collective claim is `[?] UNVERIFIED/UNKNOWN`, not `CODE_COMPLETE` or an operational receipt.

| Gate | path | SHA-256 |
|---|---|---|
| G015 | `artifacts/conformance/second-brain/g015-quality-gate.json` | `8d82e55090fcf0d63f44aa7ab1b497b480b713c3f716c0d7ce89112b34ea43d4` |
| G015 | `artifacts/conformance/second-brain/g015-suite-receipt.json` | `7add48624c60888a5a6e269907c3e68cc1f0afa718f50b93f41ada0fe26d74e6` |
| G016 | `artifacts/conformance/second-brain/g016-quality-gate.json` | `024ec517fbfc70bea4f5bdfbf77c5aadb582f9be94ae5c3f0c2a1806db9fae25` |
| G016 | `artifacts/conformance/second-brain/g016-red-team-report.json` | `d71070cb5fd42c2acbc0bdbad7ad1fe15c98cc7ce2f99ff1c642c776482a59a6` |
| G016 | `artifacts/conformance/second-brain/g016-suite-receipt.json` | `e6103e4a032ddb10db7923705b409da36c07068f370b86a63fd9fd92fb8230f4` |
| G017 | `artifacts/conformance/second-brain/g017-quality-gate.json` | `a03eb73039abd8fe3697b9697d648f41e564a15e7676fc7c7c3b9426a80b03b3` |
| G017 | `artifacts/conformance/second-brain/g017-red-team-report.json` | `91a685cf75af503975001e9453dbc6baaab839ca6065f02f741a0b5c499afa45` |
| G017 | `artifacts/conformance/second-brain/g017-suite-receipt.json` | `2c1f4331f11bed8d5d05af7c5f4965dc7c589240a090de1216b20f1d7e364b0d` |
| G018 | `artifacts/conformance/second-brain/g018-quality-gate.json` | `1846340865c501a359ba33c2a16750c363dfb508aaeb75554751aaa8b9111780` |
| G018 | `artifacts/conformance/second-brain/g018-red-team-report.json` | `9f91cab2026cc7308d193e2d7c3210326f8373fe06a30314d83a0117ad4f3464` |
| G018 | `artifacts/conformance/second-brain/g018-suite-receipt.json` | `d5b5296b1da12e9b5354efedd61a84514c4106312354009d6fb53b0d65b9f59f` |

## 소스 분류 매트릭스

| 소스 | 역할 | 승인 manifest 상태 | 흡수 정책 | retirement 정책 |
|---|---|---|---|---|
| Codex | producer/client, Stage-2 fixture profile | DB-02 `UNRESOLVED`; fixture-only | signed DB-02 `GO`와 read-only adapter 뒤에만 허용 | core app; deletion target 아님 |
| Claude/Memory Bank | producer/client, Stage-2 fixture profile | DB-02 `UNRESOLVED`; fixture-only | consent/deletion export/watermark 증명 뒤에만 허용 | core app; deletion target 아님 |
| Git | producer/client, Stage-2 fixture profile | DB-02 `UNRESOLVED`; fixture-only | revision/rename/history rules가 signed된 reader만 | core app; deletion target 아님 |
| Markdown | producer/client, Stage-2 fixture profile | DB-02 `UNRESOLVED`; fixture-only | approved content scope reader만 | producer; deletion target 아님 |
| unified-db | migration source | DB-03 `UNRESOLVED` | source별 final-workspace non-serving cohort만 | 90일 뒤 allowlisted interface만 폐기 |
| legacy Mem0/RAG | migration source | DB-03 `UNRESOLVED` | source별 final-workspace non-serving cohort만 | 90일 뒤 allowlisted service/job/credential만 폐기 |
| me-wiki | migration source | DB-03 `UNRESOLVED` | source별 final-workspace non-serving cohort만 | 90일 뒤 allowlisted service/job/credential만 폐기 |
| GJC | control/provenance producer | 새 source decision 미서명 | approved plan/receipt metadata만 read-only import | core control client; deletion target 아님 |
| Ouroboros | workflow producer | 새 source decision 미서명 | approved final artifact만; hidden reasoning 제외 | core app; deletion target 아님 |
| Orca | workspace/client producer | 새 source decision 미서명 | approved workspace content scope만 | core app; deletion target 아님 |
| codebase-memory | derived knowledge producer | 새 source decision 미서명 | canonical source/revision proof export만; graph는 authority 아님 | derived index는 별도 승인으로만 폐기 |
| OneDrive | transport | content scope 미승인 | transport 유지; 별도 content scope 승인 전 import 금지 | deletion target 아님 |
| credentials/keychains | secret authority | 흡수 금지 | import/index/manifest/receipt body 금지 | source decommission 승인 후 secret owner만 revoke |
| model/cache | rebuildable cache | memory manifest 대상 아님 | import 금지 | rebuildable; memory deletion receipt 대상 아님 |
| Docker runtime 및 `Docker.raw` | runtime/rebuildable storage | memory manifest 대상 아님 | import 금지; audit 대상 | rebuildable; memory deletion receipt 대상 아님 |

## Gate 8 — 정확한 3-lane strict import 및 독립 검토

Lane은 정확히 `gate1`, `conformance`, `canary`다. artifact kind/workflow/commit/platform는 다음 lane-specific contract를 따른다.

| lane | `artifact_kind` / workflow | `producer_commit` 규칙 | `platform` |
|---|---|---|---|
| `gate1` | `GATE1_DECISION` / `encrypted-lifecycle-gate1-decision.yml` | `gate1_commit`; implementation commit과 달라도 됨 | `self-hosted/macos-26/arm64/wiki-gate1-workstation` |
| `conformance` | `CONFORMANCE_PRE_CANARY` / `encrypted-lifecycle-conformance.yml` | shared `implementation_commit`와 같아야 함 | `self-hosted/macos-26/arm64/wiki-conformance-workstation` |
| `canary` | `CANARY_24H` / `encrypted-lifecycle-canary.yml` | shared `implementation_commit`와 같아야 함 | `self-hosted/macos-26/arm64/wiki-canary-workstation` |

각 lane receipt는 repository code의 `STRICT_IMPORT_RECEIPT_FIELDS`와 정확히 같은 closed field set을 가진다. `repository`, `artifact_kind`, `platform`, `producer_commit`, `contract_digest`, `toolchain_lock_digest`, `workflow_file_digest`, `workflow_run_id`, `workflow_run_attempt`, `artifact_name`, `bundle_sha256`, `payload_paths`, `payload_sha256`, `source_run_url`, `verified`. `verified`는 반드시 `true`다. 세 lane의 receipt는 서로 distinct canonical bytes여야 하며 `contract_digest`, `toolchain_lock_digest`는 join 입력에서 일치한다.

Canary checkpoint resume은 같은 `workflow_run_id`의 정확히 다음 changed `workflow_run_attempt`에서만 가능하다. incomplete checkpoint만 resume할 수 있다. stale 또는 terminal failed checkpoint는 새 `workflow_run_id`의 fresh dispatch가 필요하며 historical terminal evidence는 relabel/replay/issue할 수 없다.

Strict join은 세 receipt를 `pre-review-manifest.json`의 `manifest_digest`와 `evidence-join.json`의 `manifest_digest`/`join_digest`에 bind한다. final import는 tuple/attestation digest만으로 되지 않는다. 두 manifest의 verbatim receipt가 같은지 확인하여 만든 path-sorted `artifact_inventory` `{path: sha256}`를 final receipt의 `artifact_inventory`로 import해야 한다. 누락, substituted, duplicated/aliased, extra, noncanonical path, wrong digest는 거부한다.

ARCHITECT와 CRITIC은 서로 다른 trusted reviewer key와 서로 다른 `reviewer_key_id`를 사용한다. 각 attestation은 same `workspace_id`, `implementation_commit`, `manifest_digest`에 `issued_at <= now < expires_at`, `expires_at - issued_at <= 3600 seconds`를 만족해 서명한다. self-attestation 또는 key/role reuse는 거부한다.

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| G8-01 | BASE-03 / MANUAL | `[>] OPERATION_IN_PROGRESS` | current Canary | `gh run view 31314519580 --json status,conclusion,headSha,url` | rc `0`; 관찰만. terminal failure를 resume하려 하면 실패 | owner의 fresh-dispatch 결정 대기 / 없음 |
| G8-02 | BASE-05, G8-01 종료 / MANUAL | `[ ] NOT_STARTED` | strict three-lane join | 세 lane의 complete `STRICT_IMPORT_RECEIPT_FIELDS`, `gate1_commit`, `implementation_commit`, `contract_digest`, `toolchain_lock_digest`, `workspace_id`를 evidence-join workflow에 입력 | exact field set/verified/provenance/commit/platform/digest mismatch, missing/extra/reused receipt는 실패 | fresh evidence 외 재시작 금지 / 없음 |
| G8-03 | BASE-05, G8-02 / MANUAL | `[ ] NOT_STARTED` | ARCHITECT/CRITIC attestations | distinct trusted key pairs, `manifest_digest`, canonical UTC `issued_at`/`expires_at`/`now`; max 3600 seconds freshness | role/key/manifest/time mismatch는 실패 | attestation 미수입 / 없음 |
| G8-04 | BASE-05, G8-03 / MANUAL | `[ ] NOT_STARTED` | final receipt import | `write_final_review_receipt`와 `import_final_review_receipt`가 both manifest/evidence-join-derived `artifact_inventory`를 exact bind | inventory 없이 tuple+attestations만 import, product-release prerequisite 추가, active run 변경은 실패 | import 중지 / 없음 |
| G8-05 | BASE-05, G8-04 / MANUAL | `[ ] NOT_STARTED` | GJC close | GJC close record가 imported final receipt, `manifest_digest`, `join_digest`, `artifact_inventory` digest만 참조 | run ownership claim/relabel/copy/alias는 실패 | GJC close 중지 / 없음 |

## DRIFT — 계획·문서·코드/시험 정합화

**현행 정정 (2026-08-10):** 사용자의 결정에 따른 code/doc floor는 정확히 **3 full days / 72h**다. 아래의 14-day 및 1-day 진술은 append-only historical checkpoint/review의 당시 주장으로 보존하며, 현행 code/doc 상태를 설명하는 근거로 사용하지 않는다. DRIFT-02의 서명된 supersession, DB-05/07 authority는 여전히 없으므로 모든 shadow/cutover/live operation은 `[⊘] NOT_AUTHORIZED`다.

DRIFT-01 ownership은 다음 **정확히 15개** 파일로 한정한다: `docs/adr/ADR-0028-second-brain-product-boundary.md`, `docs/ops/decision-record-signing-runbook.md`, `docs/product/decisions/DB-05-benchmark-governance.md`, `docs/product/decisions/DB-07-cutover-retention.md`, `scripts/second_brain_evaluation_governance.py`, `src/wiki_spike/applications/second_brain_shadow_measurement.py`, `src/wiki_spike/memory_core/second_brain_cutover.py`, `src/wiki_spike/memory_core/second_brain_evaluation_contracts.py`, `tests/second_brain/test_decision_doc_slo_agreement.py`, `tests/second_brain/test_evaluation_governance_tool.py`, `tests/second_brain/test_native_shadow_measurement.py`, `tests/second_brain/test_native_shadow_measurement_cli.py`, `tests/second_brain/test_native_shadow_measurement_red_team.py`, `tests/second_brain/test_stage4_evaluation_governance.py`, `tests/second_brain/test_stage4_evaluation_red_team.py`.

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| DRIFT-01 | BASE-02 / code/doc owner | `[x] CODE_DOC_COMPLETE` | 15-file code/doc scope above | current floor=`3 full days/72h`; root full suite=`2215 passed in 189.13s`, rc `0`; architecture, secrets, compile, and diff checks rc `0`. Historical 14-day/1-day rows and their test totals are superseded for current code/doc state. | Signed DRIFT-02, DB-05/07 authority, manual shadow inputs, and live I/O were not supplied. | CODE/DOC completion is non-authorizing until signed DRIFT-02 supersession; no change / 없음 |
| DRIFT-02 | BASE-05, BASE-06, DRIFT-01 / MANUAL | `[⊘] NOT_AUTHORIZED` | DB-05/07, ADR/contract digest | signed superseding reconciliation이 window, retention, threshold, cohort semantics와 digest chain을 함께 bind | unsigned edit/lowered floor/digest mismatch는 실패 | prior scope 유지 / 없음 |

## CODE — 운영 전 필수 implementation gates

이 절의 CODE-01…07은 local commit `d76359ecffaf8215c5e6ec38c4a977afbdbab6bf`에 구현되어 code gate를 완료했다. 관련 검증은 non-authorizing이며, 대응 operational row는 별도 manual authority와 증거가 있어야만 시작할 수 있다.

**Dependency correction (current):** CODE-01…07 each depend on **BASE-05 only**. Table cells below that still print `BASE-06` are historical layout text superseded by this correction; BASE-06 is a post-CODE-01/02 checkpoint and cannot gate either CODE-01 or CODE-02. This removes the BASE cycle without changing the append-only historical checkpoints.

### Current CODE dependency table (authoritative for this closure)

| IDs | only code dependency | state boundary |
|---|---|---|
| CODE-01, CODE-02, CODE-03, CODE-04, CODE-05, CODE-06, CODE-07 | `BASE-05` pre-code worktree/status guard | post-CODE-01/02 observation checkpoint only; it is not a CODE dependency. No live/manual authority follows. |

### Historical detailed CODE evidence (not the current dependency table)

The detailed CODE rows retained below are evidence detail from the prior layout. Their printed `BASE-06` dependency text is superseded by the authoritative current table; it is not a current dependency or a hidden cycle.

| ID | 의존성 / 소유 / 상태 | CREATE / layer와 Protocol mapping | unit + red-team test paths | focused verification / negative acceptance | 후속 operational dependency |
|---|---|---|---|---|---|
| CODE-01 | BASE-05, BASE-06 / implementation owner / `[x] CODE_COMPLETE` | `scripts/second_brain_contract_resolver.py` SHA-256 `1bd26f20cc3ab9e619c535cece64cece4f05d54f4a7bd239e2b2ee23622ef0c4`; Application CLI가 Core `resolve_second_brain_contract`와 `TrustedDecisionKeyBindingsV1`을 호출한다. signed evidence-freshness envelope, trusted aggregate-authority binding, canonical absolute-path/no-symlink gate, atomic collision-safe receipt publish, Stage-0-only semantics을 구현했다. | `tests/second_brain/test_contract_resolver_cli.py` SHA-256 `dab0e526b35becf65a9dac240d00ffb8969ccf1b1bdbdfe5508127d7257af47b`; `tests/second_brain/test_contract_resolver_red_team.py` SHA-256 `9bd506a85567f0552cb52106e21cbbc8f9c70019c751453f366479364feec173` | focused 23 passed rc `0`; related decision/security 47 passed rc `0`; architecture rc `0`; CLI help rc `0`; diff check rc `0`. untrusted owner/approver binding, expired `now`, stale evidence, aggregate/scope mismatch은 reject한다. Full repository suite=`NOT_RUN` at this bounded slice. `live_operation_authorized=false`; CODE_COMPLETE는 GOV live acceptance가 아니다. | GOV-01/GOV-02는 DB-02/03/07 `UNRESOLVED`로 `[⊘] NOT_AUTHORIZED`; no live action / 없음 |
| CODE-02 | BASE-05, BASE-06 / implementation owner / `[x] CODE_COMPLETE` | `src/wiki_spike/memory_core/second_brain_ports.py` SHA-256 `e25f44027081efde077c0e60b558a8f7706c062c873af6de4fbfbf7b8bc748dc`; `scripts/second_brain_cohort_boundary_scan.py` SHA-256 `10ffe4e1c81afd6d2b7831ee174723eb5cbe8ca129d2759f773d761a96df64d2`. Application scan orchestration and executable fail-closed Core DTOs implement exact 8 boundaries, fixed mandatory production-shaped deny rules, case-insensitive streaming overlap with no matched content, complete root inventory summaries, canonical path/no symlink/duplicate inode checks, concurrent file/tree mutation quarantine, and atomic collision-safe receipt publish with post-link fsync rollback. | `tests/second_brain/test_cohort_boundary_scan.py` SHA-256 `be6c4b5f8846f95121e7bf9bf3323523440f2d7404578a2ac95f36290dab96ff`; `tests/second_brain/test_cohort_boundary_scan_red_team.py` SHA-256 `b451ccc08bebaf31c7f15df9c2bef8a4f6f3d17667952908c922162e9fed6518` | focused 86 passed rc `0`; security foundation 4 passed rc `0`; architecture rc `0`; diff rc `0`; top help rc `0`; verify help rc `0`; invalid args rc `2` as expected. Full repository suite=`NOT_RUN`; no live cohort/personal/credential scan was performed. CODE_COMPLETE는 ADAPT-05/live import authorization이 아니다. | ADAPT-05/IMPORT remain `[⊘] NOT_AUTHORIZED`; no live action / 없음 |
| CODE-03 | BASE-05, BASE-06 / implementation owner / `[x] CODE_COMPLETE` | `scripts/second_brain_reconcile.py` SHA-256 `be563a412f22442e6b9321c8099150d455cd28f1e8ae9d689465ab4b2220573e`; exact public `verify` argv remains authority-less, rc `2`, and mutation-free. Internal `run_with_authority(...)` injects an already minted `RecallTrustAuthorityV2` plus `AtomicRecallSnapshotPort`; isolated restore uses a verified backup only, rolls back before receipt commit, independently revalidates the cited recall twice, and commits a closed/self-digesting hash-only receipt. No trust/key/signer registry is serialized and `live_operation_authorized=false`. | `tests/second_brain/test_second_brain_reconcile.py` SHA-256 `ac0ef8bef91216b7acf4fd73a8bbe74dc214424e3353a48e1a3783e91fa8c440`; `tests/second_brain/test_second_brain_reconcile_red_team.py` SHA-256 `dfd34fa73969784d9ee257c334559f3ff5c83e10cbd7299e294ee840c6f31752` | focused 38 passed rc `0`; Stage3/6 177 passed rc `0`; architecture/secrets/py_compile rc `0`; help rc `0`; standalone exact `verify` rc `2` with target/receipt absent; unknown rc `2`; trust-surface search rc `1` (no matches); diff rc `0`. Primary initially reproduced post-link cleanup inconsistency (`error + receipt exists`) and false-green request mismatch; both were corrected and retested. Final primary postcommit attack returns no error with committed receipt state; precommit failures roll back. CODE_COMPLETE is not operational/live authorization. | RECON-01, RECON-02, RECON-03 remain `[⊘] NOT_AUTHORIZED`; no live action / 없음 |
| CODE-04 | BASE-05, BASE-06 / implementation owner / `[x] CODE_COMPLETE` | `src/wiki_spike/infrastructure/second_brain_monotonic_append_authority.py` SHA-256 `da1d055a1e9be986c4fc7864f9cf503f721820e5b7d0fdd308a4f3b4f139028c`; `scripts/second_brain_shadow_measurement.py` SHA-256 `29bdf9a1fdec27b9771f465c5879f539bf80d09961ffbc84a1d19586613ba17b`. Infrastructure implementation is injected into the existing Application `MonotonicAppendAuthority` Protocol; signed-state/fresh-head correction closes the prior review findings. | `tests/second_brain/test_deployment_monotonic_append_authority.py` SHA-256 `04f9631622c2a82e8b9dadf192fa730b0f1c206b810aac63e6dc60959b3c711a`; `tests/second_brain/test_deployment_monotonic_append_authority_red_team.py` SHA-256 `8a557ddfe9a0cac6dd2dbe70a66c83d1ec8424a9d248dec4ba5a16a4057c7e30`; existing `tests/second_brain/test_native_shadow_measurement_cli.py`. | Independent primary evidence: original attacks reproduced before fix; after correction, same-revision tamper and restart rollback are rejected. Exact checklist suite 31 passed rc `0`; existing native shadow red-team 57 passed rc `0`; architecture rc `0`; `scan_secrets` rc `0`; scoped diff rc `0`; standalone help rc `2` as expected. Full `tests/second_brain/test_native_shadow_measurement.py`=`NOT_RUN/INCONCLUSIVE`; no endpoint connectivity or live operation occurred. CODE_COMPLETE does not authorize shadow. | SHADOW-01, SHADOW-02, SHADOW-03 remain `[⊘] NOT_AUTHORIZED` |
| CODE-05 | BASE-05, BASE-06 / implementation owner / `[x] CODE_COMPLETE` | `scripts/second_brain_route_authority.py` SHA-256 `1d7c0acb39f7a48508f9fd6513af8ecbefd3b383fdd004a3e5aca3f880b74ec1`; `src/wiki_spike/infrastructure/second_brain_route_authority.py` `358ff9a8ccd28f0b411a3913abb464f93896a830634d8e661778c127c4fdfc70`; `src/wiki_spike/memory_core/second_brain_contracts.py` `ddcd389410c7cfc41fde112401763c0749a6850ca0b2d80655f8d61ad6dff45d`; `src/wiki_spike/memory_core/second_brain_ports.py` `637f01817379e1c0b545830a43d67a035dd5b70f273fa621f0e02ac9164640f4`. Application CLI and Infrastructure atomic transaction adapter implement `RouteSwitchAuthority`. | `tests/second_brain/test_route_authority_cli.py` SHA-256 `0fb7f38c0b367e945795372db3d6bc903402ffa6b6b085d7b40459dfa9e8a935`; `tests/second_brain/test_route_authority_red_team.py` `a3e01c3b1406ab1cedef1658fa76f2626150239f90a12f2ba926d1e1a46131d9`. | Prior primary failure: `RC2/STATE_EXISTS true/OUT false`. Corrected behavior emits one signed canonical state+receipt bundle at exact `--out`; primary reproduction fixed: rc `0`, bundle exists, `CANONICAL_MUTATED`. 154 CODE-05+Stage6 passed rc `0`; architecture/secrets/compile/help/diff rc `0`; invalid rc `2`. No live route action occurred. | CUTOVER-01, CUTOVER-02, CUTOVER-03 remain `[⊘] NOT_AUTHORIZED` |
| CODE-06 | BASE-05, BASE-06 / implementation owner / `[x] CODE_COMPLETE` | `scripts/second_brain_decommission_certificate.py` SHA-256 `989535645644378ced9d6cf668f463faf8207cf1b16e745fbfb2aee6f441aa27`; `src/wiki_spike/memory_core/second_brain_contracts.py` SHA-256 `e56b094ef7d6f0a48ae74cd29109b8c07f7f81bb1980cfaf1d3d67d15f3f55ba`; `src/wiki_spike/memory_core/second_brain_ports.py` SHA-256 `2cc4bf18944bfac09c3634978bfb85dfe59a904361a0dfdd0d8eb1ef11262244`. Exact public CLI remains authority-less rc `2`, reads no input, and writes no output. Internal `DecommissionCertificateVerifierPort` receives out-of-band signer/approval registries and trusted clock; it domain-separately verifies activation, consent, four-role approvals, and certificate Ed25519 signatures, enforces exact `90*24h`, reuses CODE-03 conservation, and emits signed closed-certificate `ROLLBACK_CLOSED` evidence only with `destructive_action_authorized=false`. No deletion or revocation occurs. | `tests/second_brain/test_decommission_certificate.py` SHA-256 `55829eed614ba341cf1db0f582b6c196baa1d2e1c39f0e90fbcc0c52f7c08117`; `tests/second_brain/test_decommission_certificate_red_team.py` SHA-256 `aa66d6562c0bba3665425bde996232e8d1751a9dfa8ccb1025f77e78594f2694` | Independent primary/Sol approval after two reject/correction cycles: focused 56 passed rc `0`; prescribed Stage6/reconcile/route 192 passed rc `0`; architecture/secrets/py_compile rc `0`; help rc `0`; standalone exact rc `2` sentinel/no output; unknown rc `2`; trust-surface `rg` rc `1`; diff rc `0`. Primary corrections—missing approval registry/certificate signature verification, forged DTO normalization hiding `destructive=true`, approval bad-signature false-green, consent-expiry and commit-point tests—were all corrected and retested. CODE_COMPLETE is code-gate evidence only, not live/certificate/deletion authorization. | RETAIN-01, RETAIN-02, RETAIN-03, DELETE-01 remain `[⊘] NOT_AUTHORIZED`; no live action / 없음 |
| CODE-07 | BASE-05, BASE-06 / implementation owner / `[x] CODE_COMPLETE` | Owned files: `src/wiki_spike/memory_core/second_brain_contracts.py` SHA-256 `cc261642600698bef68866d739f9d0319cd437a2be9203ee0fcb2f01c034fc02`; `src/wiki_spike/memory_core/second_brain_ports.py` `c3a8182866fb2af3488ee809537f13ee25abb3335ef548d3064046b1825c814f`; `src/wiki_spike/connectors/codex.py` `206dca9f6f1f53c20d9634ada7c27e27396f3c5d61749a93fc82c7c4535c0618`; `src/wiki_spike/connectors/claude_memory_bank.py` `7b99a0d507760c8f3f7488e3a2479681792d0d8998606eb370d170cd6747f2f4`; `src/wiki_spike/connectors/git.py` `f515271d1df35f1bd842ffcfb10b4ce9376f10f2ff2e03f556e8d67e27fd5677`; `src/wiki_spike/connectors/markdown.py` `d929ba39579e3d317a66f5dc11965760676bf3276a3b3af79d38479fd3a8fd2e`; `src/wiki_spike/composition/second_brain_capture.py` `0acf707ca95173bf0e022819f0b87c079c4eb6f64dcfcee077fbb32e2d8348cb`. | `tests/second_brain/test_live_source_adapters.py` SHA-256 `fd1fc3860d297ee797e5f40dc2196aa8d4c279709596060c644c1b0607ee3808`; `tests/second_brain/test_live_source_adapters_red_team.py` `b779aeae0372660c20af89ec6ab8865298206204375dc4133fc04fc90ba1e701`; existing `tests/second_brain/test_stage2_connectors.py`, `tests/second_brain/test_stage2_capture_composition.py`. | Independent primary evidence: exact checklist suite 54 passed rc `0`; architecture rc `0`; `scan_secrets` rc `0`; scoped diff rc `0`. This is process-local and non-authorizing: no live I/O, import, activation, or source access occurred. `ADAPT`/`GOV` remain `[⊘] NOT_AUTHORIZED`. | ADAPT-01..05 and GOV gates remain not authorized; no live action / 없음 |

### Current closure traceability (code/doc locally committed, unpushed)

| scope | owned implementation/docs | owned tests / boundary | current claim |
|---|---|---|---|
| CODE-01 | `scripts/second_brain_contract_resolver.py` | `test_contract_resolver_cli.py`, `test_contract_resolver_red_team.py` | code-only resolver; GOV/live blocked |
| CODE-02 | `memory_core/second_brain_ports.py`, `scripts/second_brain_cohort_boundary_scan.py` | `test_cohort_boundary_scan.py`, red-team | code-only deny-boundary scan; no source scan/import |
| CODE-03 | `scripts/second_brain_reconcile.py` | `test_second_brain_reconcile.py`, red-team | code-only synthetic/isolated reconciliation; RECON manual blocked |
| CODE-04 | `infrastructure/second_brain_monotonic_append_authority.py`, `scripts/second_brain_shadow_measurement.py` | deployment authority tests, native CLI/red-team | code-only measurement adapter; SHADOW manual blocked |
| CODE-05 | route CLI, infrastructure route authority, Core contracts/ports | route CLI/red-team | code-only route transaction; CUTOVER manual blocked |
| CODE-06 | decommission certificate CLI, Core contracts/ports | certificate/red-team | code-only closed readiness; no certificate issuance/delete/revoke |
| CODE-07 | four connector files, Core contracts/ports, capture composition | live-source-adapter, Stage-2 fixture tests | fixture/process-local only; no live I/O |
| DRIFT-01 | exact 15 files enumerated above | their focused code/doc checks | 3 full days/72h code/doc floor only; DRIFT-02 absent |

**Out of this closure:** V2 API/MCP, broader E2E/browser work, source adapter credentials/I/O, import, Canary control, cutover, live activation, retention and deletion are either previously committed outside this local closure, planning-only, or externally/manual-authority blocked. No completion claim for them is made here without separate current evidence.

### Known adjustments, change budget, and rework dispatch (this closure)

| owned files | allowed adaptations | stop / escalate | exact rerun commands |
|---|---|---|---|
| `docs/planning/SECOND_BRAIN_LIVE_ABSORPTION_DECOMMISSION_CHECKLIST_KR.md`; `docs/reports/SECOND_BRAIN_WORKFLOW_OVERVIEW_KR.html`; `docs/reports/ROADMAP_KR.html` | current-state wording, dependency rows/overrides, traceability and historical labels only | any required code/artifact edit; a new final status digest/commit; missing signed DRIFT-02 or DB-05/07 authority; any live/import/cutover/delete request | `git diff --check -- docs/planning/SECOND_BRAIN_LIVE_ABSORPTION_DECOMMISSION_CHECKLIST_KR.md docs/reports/SECOND_BRAIN_WORKFLOW_OVERVIEW_KR.html docs/reports/ROADMAP_KR.html` |
| planning current layer | replace stale 14/1-day operative claims with 3-day/72h and label retained history | a current row still asserts approved 14 days, 1 day, or a CODE dependency on BASE-06 | local commit `d76359ecffaf8215c5e6ec38c4a977afbdbab6bf` is unpushed; trevally is clean with digest `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. Rerun: `awk '/^### Current CODE dependency table/,/^### Historical detailed CODE evidence/ {if ($0 ~ /BASE-06/) bad=1} END {exit bad}' docs/planning/SECOND_BRAIN_LIVE_ABSORPTION_DECOMMISSION_CHECKLIST_KR.md` |
| code-only/manual boundary | move local tests to `ADAPT-CODE`/`RECON-CODE`; leave operational rows MANUAL/live only | a manual row contains fixture-only/static argv, or code-only verification claims live I/O | `rg -n 'ADAPT-CODE|RECON-CODE|Current operational-row correction|Current SHADOW-01 correction' docs/planning/SECOND_BRAIN_LIVE_ABSORPTION_DECOMMISSION_CHECKLIST_KR.md` |

## CODE-06 설계 결정 게이트

현재 결정 상태는 `APPROVED_OPTION_A_IMPLEMENTED`이다. 사용자의 권장안 위임으로 A가 선택·구현되었고 B는 선택되지 않았다. CODE-06 code gate 완료는 operational/manual gate, certificate 발급, live action 또는 deletion을 인가하지 않는다.

- **A (권장):** exact public CLI argv를 보존하고 standalone은 fail-closed rc `2`를 유지한다. Core에 hash-only closed `ActivationReceiptV1`(trusted `activated_at` 및 route/decision/state binding 포함), `ConsentTransferReceiptV1`, 네 fresh role-approval evidence binding, `DecommissionCertificateRequestV1`/`DecommissionCertificateV1`를 추가한다. deployment-injected `DecommissionCertificateVerifierPort`/authority가 trusted clock, external signer registry, activation/approval/consent verification, certificate signing을 제공한다. trust key, clock, signing material은 file/argv에 두지 않는다. certificate는 `destructive_action_authorized=false`인 `ROLLBACK_CLOSED` readiness만 증명하며 delete/revoke하지 않는다. exact retention-end는 UTC `activated_at + 90*24h`와 같아야 하고 trusted now는 retention-end 이상이어야 한다.
- **B (비권장):** public CLI를 key registry, approval files, clock, signer로 확장하거나 self-signed activation/consent를 허용한다. 이는 승인된 surface를 변경하고 self-trust risk를 만들므로 별도 security plan과 명시적 승인이 필요하다.

## CODE-03 설계 결정 게이트

현재 결정 상태는 `APPROVED_OPTION_A_IMPLEMENTED`이다. A가 선택·구현되었고 B는 선택되지 않았다. public trust material은 존재하지 않으며, operational restore 또는 live action은 별도 manual gate 없이는 인가되지 않는다.

- **A (선택·구현):** exact public CLI argv를 보존한다. standalone public execution은 authority-less fail-closed rc `2`와 no-mutation을 유지하고, 이미 mint된 `RecallTrustAuthorityV2`와 `AtomicRecallSnapshotPort`를 받는 `run_with_authority(...)` internal composition seam을 사용한다. trusted key 또는 signer registry를 `--recall-sample`에 절대 serialize하지 않는다.
- **B (미선택 / plan-reality revert):** Stage-0 authority와 별도로 pinned signer registry를 포함하는 새로운 canonical signed offline envelope를 정의하는 선택지였다. 이는 승인된 transport/contract를 변경하며 self-supplied trust root를 받아서는 안 된다. 선택되지 않았으며 구현하지 않는다.

## GOV — embedded signature 검증과 trusted resolution

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| GOV-01 | BASE-05, BASE-06, DRIFT-02, CODE-01 / MANUAL | `[⊘] NOT_AUTHORIZED` | each DB-01..08 record | `.venv/bin/python scripts/second_brain_decision.py verify --record "$RECORD"`를 각 record에 실행 | rc `0`은 record의 embedded signatures/schema만 검증한다. trusted binding, aggregation, expiry/current-time, evidence freshness를 검증했다고 해석하면 실패 | enabled scope 변경 없음 / 없음 |
| GOV-02 | BASE-05, BASE-06, GOV-01, CODE-01 / MANUAL | `[⊘] NOT_AUTHORIZED` | contract resolver | `.venv/bin/python scripts/second_brain_contract_resolver.py resolve --records-dir "$RECORDS_DIR" --resolved-scope "$RESOLVED_SCOPE" --expected-scopes "$EXPECTED_SCOPES" --aggregate "$AGGREGATE" --trusted-bindings "$TRUSTED_BINDINGS" --evidence-manifest "$EVIDENCE_MANIFEST" --now "$NOW_RFC3339" --out "$RESOLUTION_RECEIPT"` | after CODE-01 rc `0`; trusted owner/approver bindings, scope aggregation, expiry/current-time, evidence freshness를 canonical receipt에 bind | prior signed scope 유지 / 없음 |
| GOV-03 | BASE-05, BASE-06, GOV-02 / MANUAL | `[⊘] NOT_AUTHORIZED` | `ResolvedScopeV1`, capability/source manifests | DB-01/04/05/07=`GO`, all records valid `RESOLVED`, source/feature enablement/digests가 resolution receipt에 일치 | global gate failure/scope omission은 실패; scoped `NO_GO`는 해당 source disable | prior scope 유지 / 없음 |
| GOV-04 | BASE-05, BASE-06, GOV-02 / MANUAL | `[⊘] NOT_AUTHORIZED` | GJC/Ouroboros/Orca/codebase-memory/OneDrive | source별 content class, consent, read-only export, ID/revision, tombstone, retention, owner/approver signed decision | unresolved source import 실패; OneDrive는 transport 유지 | fixture/transport 유지 / 없음 |

## ADAPT code-only verification — fixture/process-local only

| ID | 의존성 / 소유 | 상태 | 표면 | verification boundary | operational effect |
|---|---|---|---|---|---|
| ADAPT-CODE-01 | BASE-05, CODE-07 / AUTONOMOUS | `[x] CODE_COMPLETE` | fixture connector/composition tests and architecture check | process-local fixture/static checks only; no source credential, adapter connection, source read, cohort, or import input is supplied | no live I/O; only ADAPT-02, ADAPT-03, ADAPT-05 remain MANUAL; ADAPT-01/04 are superseded `[⊘] NOT_AUTHORIZED` |

## ADAPT 및 IMPORT — manual/live read-only adapter와 non-serving cohort

**Current operational-row correction:** `ADAPT-01` and `ADAPT-04` below are superseded as local test/static rows; their exact argv belongs only to `ADAPT-CODE-01` and must not be rerun as a live/operational gate. Current operational ADAPT work is MANUAL only: `ADAPT-02`, `ADAPT-03`, `ADAPT-05`, `IMPORT-01`, and `IMPORT-02`.

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| ADAPT-01 | BASE-05, CODE-07 / code-only evidence | `[x] SUPERSEDED_BY_ADAPT_CODE_01` | fixture connector/composition boundary | `ADAPT-CODE-01`의 완료된 fixture/static evidence를 참조한다; 이 row에 남은 argv나 operational work는 없다. | no operational effect; source credential/I/O/import authority를 만들지 않는다. | 없음 |
| ADAPT-02 | BASE-05, BASE-06, ADAPT-01, CODE-07 / MANUAL | `[⊘] NOT_AUTHORIZED` | source별 live reader | scope/capability, pagination, revision, cursor/watermark, deletion/tombstone, export fixture digest | write 권한 또는 complete snapshot/tombstone 부재는 실패 | capability revoke 또는 미등록 / 없음 |
| ADAPT-03 | BASE-05, BASE-06, ADAPT-02, CODE-07 / MANUAL | `[⊘] NOT_AUTHORIZED` | unified-db/legacy Mem0-RAG/me-wiki reader | DB-03 `GO`, encrypted mapping, read-only export proof | DB-03 미해결/raw metadata telemetry/fallback은 실패 | `DISCOVERED` 유지 / 없음 |
| ADAPT-04 | BASE-05, CODE-07 / code-only evidence | `[x] SUPERSEDED_BY_ADAPT_CODE_01` | architecture/security fixture boundary | `ADAPT-CODE-01`의 완료된 static evidence를 참조한다; 이 row에 남은 argv나 operational work는 없다. | no operational effect; source credential/I/O/import authority를 만들지 않는다. | 없음 |
| ADAPT-05 | BASE-05, BASE-06, ADAPT-02, CODE-02, CODE-07 / MANUAL | `[⊘] NOT_AUTHORIZED` | cohort boundary | `.venv/bin/python scripts/second_brain_cohort_boundary_scan.py verify --deny-class-schema "$DENY_CLASS_SCHEMA" --source-export "$SOURCE_EXPORT" --manifest "$COHORT_MANIFEST" --cohort-payload "$COHORT_PAYLOAD" --db "$COHORT_DB" --wal "$COHORT_WAL" --cas "$COHORT_CAS" --log-dir "$COHORT_LOG_DIR" --receipt "$COHORT_RECEIPT" --out "$BOUNDARY_SCAN_RECEIPT"` | after CODE-02 rc `0`: export→manifest→payload→DB/WAL/CAS/log/receipt 모두 deny class 없음. deny classes: `credential`, `keychain`, `secret-token`, `private-key`, `session-cookie`, `hidden-reasoning`; hit rc `2`, hash-only finding, quarantine/no-import | hit cohort 격리 / 없음 |
| IMPORT-01 | BASE-05, BASE-06, GOV-03, ADAPT-03, ADAPT-05 / MANUAL | `[⊘] NOT_AUTHORIZED` | `MigrationCohortManifestV1` | one-source roster, final workspace ref, scope/source/boundary-scan digest signed bind | multi-source/disabled source/root-qwen-collector path/missing scan은 실패 | cohort 미생성 / 없음 |
| IMPORT-02 | BASE-05, BASE-06, IMPORT-01 / MANUAL | `[⊘] NOT_AUTHORIZED` | encrypted capture/ledger | `DISCOVERED → IMPORTING → QUARANTINED_ITEM|RECONCILING|READY_NON_SERVING` only | serving exposure/live route/source mutation 실패 | import stop 또는 `ROLLED_BACK_RECONCILE` / 없음 |

## RECON code-only verification — isolated fixtures only

| ID | 의존성 / 소유 | 상태 | 표면 | verification boundary | operational effect |
|---|---|---|---|---|---|
| RECON-CODE-01 | BASE-05, CODE-03 / AUTONOMOUS | `[x] CODE_COMPLETE` | reconcile unit/red-team and static boundary evidence | synthetic/fixture-only conservation and isolated-restore behavior; no source inventory, backup, restore target, or live route is supplied | no live I/O; only RECON-01 and RECON-02 remain MANUAL; RECON-03 is superseded `[⊘] NOT_AUTHORIZED` |

## RECON — manual conservation verifier와 isolated restore

**Current operational-row correction:** `RECON-03` below is superseded as a local pytest row; its exact argv belongs to code-only verification and is not an operational gate. Current RECON work is MANUAL only: `RECON-01` and `RECON-02`, both requiring supplied source/backup/restore evidence.

`RECON_RECEIPT` planned schema `second-brain-reconciliation-receipt-v1`의 필수 fields는 source/cohort/backup input digests, accepted count, quarantined count, source total, unique `(source_ref,native_id,revision)` count, tombstone count, dedupe-root set digest, citation set digest, payload-hash set digest, collisions, deterministic recall sample digest, isolated restore target digest, result, verifier version이다.

`accepted + quarantined = source total`이어야 한다. `(source_ref,native_id,revision)`은 unique이고 source history의 revision과 일치해야 한다. 다른 source의 동일 native ID는 병합하지 않는다. dedupe는 same signed `dedupe_root_ref`와 same canonical payload hash가 모두 있을 때만 허용한다. 그 외 collision은 `QUARANTINED_ITEM`이며 accepted가 될 수 없다. citation은 source ref/native ID/revision/hash를 bind한다.

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| RECON-01 | BASE-05, BASE-06, IMPORT-02, CODE-03 / MANUAL | `[⊘] NOT_AUTHORIZED` | conservation verifier | `.venv/bin/python scripts/second_brain_reconcile.py verify --source-inventory "$SOURCE_INVENTORY" --cohort-inventory "$COHORT_INVENTORY" --cohort-manifest "$COHORT_MANIFEST" --backup-manifest "$BACKUP_MANIFEST" --restore-target "$RESTORE_TARGET" --recall-sample "$RECALL_SAMPLE" --receipt "$RECON_RECEIPT"` | after CODE-03 rc `0`; schema, all conservation/collision rules, input/backup digest, deterministic cited sample, source-independent isolated restore pass | `RECONCILING`; source read-only 유지 / 없음 |
| RECON-02 | BASE-05, BASE-06, RECON-01 / MANUAL | `[⊘] NOT_AUTHORIZED` | isolated restore | `RESTORE_TARGET`은 every source path 밖의 empty target; source network/client/fallback 없이 sample 재현 | source access/changed evidence/uncited recall 실패 | restore 격리 / 없음 |
| RECON-03 | BASE-05, CODE-03 / code-only evidence | `[x] SUPERSEDED_BY_RECON_CODE_01` | recall/citation fixture boundary | `RECON-CODE-01`의 완료된 unit/red-team evidence를 참조한다; 이 row에 남은 pytest argv나 operational work는 없다. | no operational effect; `READY_NON_SERVING` 또는 live authority를 만들지 않는다. | 없음 |

## SHADOW — retained authority와 계량 관찰

**Current SHADOW-01 correction:** code/doc is aligned to **3 full days / 72h**. The historical `plan=14/docs=1/code-tests>=3` text in the preserved detailed row below is superseded and must not be read as a current conflict. SHADOW-01 remains `[⊘] NOT_AUTHORIZED` solely because signed DRIFT-02 plus DB-05/07 authority and required operational evidence are absent.

현재 `scripts/second_brain_shadow_measurement.py`는 deployment `MonotonicAppendAuthority` adapter가 없어 의도적으로 rc `2`를 반환한다. `--help`는 gate가 아니다. CODE-04의 implementation/approval/independent review 전 shadow를 시작할 수 없다.

CODE-04 후 각각 exact argv는 공통 `--db "$SHADOW_DB" --authority-endpoint "$RETENTION_AUTHORITY_ENDPOINT" --measurement-public-key "$MEASUREMENT_PUBLIC_KEY" --measurement-key-fingerprint "$MEASUREMENT_KEY_FINGERPRINT" --resolved-scope "$RESOLVED_SCOPE" --contract "$CONTRACT_DIGEST_FILE" --source-manifest "$SOURCE_MANIFEST" --capability-manifest "$CAPABILITY_MANIFEST" --benchmark-manifest "$BENCHMARK_MANIFEST" --holdout-manifest "$HOLDOUT_MANIFEST"`에 command별 option을 더한다: `init --checkpoint "$CHECKPOINT"`; `append --sample "$SHADOW_SAMPLE"`; `status`; `verify`. 각 command는 rc `0`과 canonical JSON receipt를 내야 한다. init은 checkpoint/manifest digests, append는 monotonic sample, status는 count/current checkpoint/authority snapshot, verify는 signed aggregate measurement receipt를 bind한다. adapter/scope/digest/monotonicity/signature/denominator/retention mismatch는 rc `2`이며 cohort는 non-serving이다.

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| SHADOW-01 | BASE-05, BASE-06, DRIFT-02, RECON-02, CODE-04 / MANUAL | `[⊘] NOT_AUTHORIZED` | signed DB-05/07, cohort | code/doc floor=`3 full days/72h` aligned. Signed DRIFT-02, DB-05/07 authority, and required operational evidence are absent. | unsigned/missing authority or evidence fails; no observation starts. | observation 없음 / 없음 |
| SHADOW-02 | BASE-05, BASE-06, SHADOW-01, CODE-04 / MANUAL | `[⊘] NOT_AUTHORIZED` | deployment adapter/script | `init`, `append`, `status`, `verify` argv와 adapter attestation/receipt digests | CODE-04 전 rc `2`; CODE-04 후 all rc `0`; serving write/missing retained authority 실패 | non-serving 유지 / 없음 |
| SHADOW-03 | BASE-05, BASE-06, SHADOW-02 / MANUAL | `[⊘] NOT_AUTHORIZED` | `CutoverDecisionV1` | migration/quality/security/product external roles, safety=0, signed window, parity/source, cohort E2E, holdout unchanged, Wilson minima | role 누락/formula false/holdout change/safety>0 실패 | decision 미발행 / 없음 |

## CUTOVER — signed runbook, atomic route, rollback boundary

`CUTOVER_RUNBOOK` schema `second-brain-cutover-runbook-v1`는 cohort manifest digest, decision digest, route authority, target, generation digest, route version, pre-mutation rollback target/receipt, four-role approval digests, post-check contract를 strict fields로 가진다.

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| CUTOVER-01 | BASE-05, BASE-06, SHADOW-03, CODE-05 / MANUAL | `[⊘] NOT_AUTHORIZED` | signed runbook/decision/cohort | `.venv/bin/python -m pytest -q tests/second_brain/test_stage6_cutover.py tests/second_brain/test_stage6_cutover_red_team.py` | rc `0`; signed runbook/decision/digest/four roles absent면 route action 실패 | `READY_NON_SERVING` 유지 / 없음 |
| CUTOVER-02 | BASE-05, BASE-06, CUTOVER-01, CODE-05 / MANUAL | `[⊘] NOT_AUTHORIZED` | route rehearsal | `.venv/bin/python scripts/second_brain_route_authority.py rehearse --runbook "$CUTOVER_RUNBOOK" --decision "$CUTOVER_DECISION" --cohort-manifest "$COHORT_MANIFEST" --route-authority "$ROUTE_AUTHORITY" --target "$ROUTE_TARGET" --generation "$GENERATION_DIGEST" --route-version "$ROUTE_VERSION" --rollback-receipt "$ROLLBACK_RECEIPT" --out "$ROUTE_REHEARSAL_RECEIPT"` | after CODE-05 rc `0`; target/generation/version/pre-mutation rollback signed, state=`ROUTE_SWITCHED_NO_MUTATION` | `ROUTE_SWITCHED_NO_MUTATION → ROLLED_BACK_RECONCILE` only / 없음 |
| CUTOVER-03 | BASE-05, BASE-06, CUTOVER-02, CODE-05 / MANUAL | `[⊘] NOT_AUTHORIZED` | atomic switch/post-check | `switch-atomic --runbook "$CUTOVER_RUNBOOK" --decision "$CUTOVER_DECISION" --cohort-manifest "$COHORT_MANIFEST" --route-authority "$ROUTE_AUTHORITY" --target "$ROUTE_TARGET" --generation "$GENERATION_DIGEST" --route-version "$ROUTE_VERSION" --rollback-receipt "$ROLLBACK_RECEIPT" --out "$ROUTE_SWITCH_RECEIPT"`; then `verify --route-authority "$ROUTE_AUTHORITY" --target "$ROUTE_TARGET" --generation "$GENERATION_DIGEST" --route-version "$ROUTE_VERSION" --receipt "$ROUTE_SWITCH_RECEIPT" --out "$ROUTE_POSTCHECK_RECEIPT"` using `.venv/bin/python scripts/second_brain_route_authority.py` | after CODE-05 each rc `0`; one transaction binds active cohort/target/generation/version, no fallback/dual-write; human approvals required | pre-mutation CUTOVER-02 rollback; `CANONICAL_MUTATED` 후 external rollback fail-closed / 없음 |

## RETAIN 및 DELETE — 90일 보존, certificate, allowlisted 폐기

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| RETAIN-01 | BASE-05, BASE-06, CUTOVER-03, CODE-06 / MANUAL | `[⊘] NOT_AUTHORIZED` | source retention | trusted `ACTIVATION_RECEIPT`, source ID, read-only mode, `RETENTION_END_RFC3339` | activation + exactly 90×24h UTC이며 source write/early deletion 실패 | read-only 유지 / 없음 |
| RETAIN-02 | BASE-05, BASE-06, RETAIN-01, CODE-06 / MANUAL | `[⊘] NOT_AUTHORIZED` | source/final observation | cited recall/tombstone/no-fallback append-only receipt | resurrection/source serving/missing deletion propagation 실패 | recon/shadow로 회귀 / 없음 |
| RETAIN-03 | BASE-05, BASE-06, RETAIN-02, CODE-06 / MANUAL | `[⊘] NOT_AUTHORIZED` | `CANONICAL_MUTATED → ROLLBACK_CLOSED` | `.venv/bin/python scripts/second_brain_decommission_certificate.py verify --activation "$ACTIVATION_RECEIPT" --retention-end "$RETENTION_END_RFC3339" --decision "$CUTOVER_DECISION" --conservation "$CONSERVATION_RECEIPT" --allowlist-digest "$ALLOWLIST_DIGEST" --consent-transfer "$CONSENT_TRANSFER_RECEIPT" --out "$DECOMMISSION_CERTIFICATE"` | after CODE-06 rc `0`; trusted activation, full 90-day, fresh migration/quality/security/product approvals, backup/restore/conservation/allowlist digests, consent transfer bind되어 `ROLLBACK_CLOSED` | time/approval/digest/consent failure면 read-only 유지 / 없음 |
| DELETE-01 | BASE-05, BASE-06, RETAIN-03, CODE-06 / MANUAL | `[⊘] NOT_AUTHORIZED` | source allowlist | 90일 경과, certificate, backup/restore/conservation, human external approval | 하나라도 없으면 destructive action 실패 | source read-only 유지 / 없음 |
| DELETE-02 | BASE-05, BASE-06, DELETE-01 / MANUAL | `[⊘] NOT_AUTHORIZED` | exact targets | service/job/credential ID와 revoke/deletion receipt 1:1 bind; Orca/Codex/Claude/Git, OneDrive transport, model cache, Docker.raw 제외 | wildcard/allowlist 밖 target 실패 | deletion 수행 안 함 / signed human approval 필요 |
| DELETE-03 | BASE-05, BASE-06, DELETE-02 / MANUAL | `[⊘] NOT_AUTHORIZED` | no-resurrection | listener/job/credential absence, final cited recall, restore-without-source, backup receipt | source serving/fallback dependency 실패 | incident mode; 추가 deletion 금지 / signed human approval 필요 |

## CLEANUP — 별도 시스템 안정화

| ID | 의존성 / 소유 | 상태 | 표면 | 증거·argv | 기대 rc / 실패 조건 | rollback / 삭제 권한 |
|---|---|---|---|---|---|---|
| CLEANUP-01 | BASE-05, BASE-06 / MANUAL | `[ ] NOT_STARTED` | MCP pooling | audit의 약 774 MCP process/약 4.8 GiB와 approved plan/post-change count 대조 | protected PID 포함 시 실패 | protected PID 불변 / 없음 |
| CLEANUP-02 | BASE-05, BASE-06 / MANUAL | `[ ] NOT_STARTED` | Docker control/data ports | Docker control timeout `rc=28`, ports `5433/5434` ready, stuck docker-exec cron probes incident receipt | prune/restart가 Canary/durable state 건드리면 실패 | non-destructive diagnosis / 없음 |
| CLEANUP-03 | BASE-05, BASE-06 / MANUAL | `[ ] NOT_STARTED` | tunnel auth/port `7979` | full-write/auth `UNKNOWN` access policy evidence | auth 미검증/broad write면 live operation 실패 | external change는 separate human approval / 없음 |
| CLEANUP-04 | BASE-05, BASE-06 / MANUAL | `[ ] NOT_STARTED` | backup/memory maintenance | backup exit `70`, maintenance exit `1` 원인/restore receipt | exit code 무시 실패 | destructive cleanup 금지 / 없음 |
| CLEANUP-05 | BASE-05, BASE-06 / MANUAL | `[ ] NOT_STARTED` | disk/retention/log rotation | System Data `91%` capacity/evidence retention/log rotation | evidence 삭제로 용량 확보 실패 | capacity escalation / 없음 |

## machine-ledger bootstrap

dedicated execution worktree가 준비되어 `BASE-05`를 통과했다. ledger는 이제 create/validate 준비 상태이나, 이 체크리스트 작업은 ledger를 생성하지 않는다. 이 단계의 skill은 worktree 생성·삭제를 금지하며 repository root 또는 qwen/collector worktree를 재사용할 수 없다.

root `repository`=`/Volumes/DevSpace/orca/Wiki-spike/wiki-spike`, every item `worktree`=`/Volumes/DevSpace/orca/workspaces/wiki-spike/trevally`, 그리고 `worktree != repository`를 검증한다. `workspace_root` field는 사용하지 않는다. `BASE-06`이 통과한 뒤 authorized owner가 ledger를 생성할 수 있으며, 생성 전에는 validate command만 준비한다.

```sh
git worktree list --porcelain
realpath "$DEDICATED_WORKTREE"
git -C "$DEDICATED_WORKTREE" rev-parse --show-toplevel
git -C "$DEDICATED_WORKTREE" status --short
git -C "$DEDICATED_WORKTREE" rev-parse HEAD
.venv/bin/python "/Users/jmpark/Library/Application Support/orca/codex-accounts/37616e4b-881e-484a-92bc-691c7cea43e2/home/skills/converge-loop/scripts/converge_loop.py" validate --ledger "$LEDGER"
```

각 command는 rc `0`이어야 한다. `validate`는 `repository` exact value, every `worktree` realpath, separate worktree rule을 통과해야 한다. path/schema mismatch면 ledger validation을 시작하지 않는다.

## 활성 blocker

1. 현행 code/doc floor는 정확히 **3 full days / 72h**로 aligned다. 운영 shadow/cutover 값은 signed DRIFT-02와 DB-05/07 authority/evidence가 없으므로 확정·실행할 수 없다.
2. DB-01/02/03/05/07은 unsigned/unresolved이며 DB-02/03은 disabled/deferred, DB-01/05/07은 global block이다. DB-04의 embedded signature verification만으로 trusted identity/resolved-scope binding은 충족되지 않았고, DB-06/08 scoped `NO_GO`는 binding 수용 후에도 disabled다. GJC/Ouroboros/Orca/codebase-memory source decisions도 해소되지 않았다.
3. CODE-01..07은 모두 code-only `CODE_COMPLETE`일 뿐 live/operational/delete authorization이 아니다. RECON/ADAPT/GOV/SHADOW/CUTOVER/RETAIN/DELETE operational gates는 계속 별도 manual authority를 요구한다.
4. deployment retained-authority adapter가 없어 current shadow CLI는 의도적으로 rc `2`다.
5. Gate 8 Canary run `31314519580`은 `in_progress` 및 protected 상태다; 이 checklist는 run/PID/artifact를 제어하지 않는다.
6. external converge ledger의 OOO CODE item은 current OOO Codex runtime이 exact Terra per-run route를 노출하지 않아 `human_blocked`다. Direct Terra implementation과 independent Sol verification은 OOO PASS가 아니다.
7. Docker control plane은 `rc=28`이며, source별 90일 보존·사람 승인 전 destructive deletion은 불가하다.

## CHECKPOINT — 2026-08-09 append-only

| 날짜 | 기준선 → HEAD | 상태 변화 | 다음 실행 가능 작업 | 증거 |
|---|---|---|---|---|
| 2026-08-09 | `docs-root-cleanup` → `340ac67af852c189b238801f3308191b8cbd96d2` | plan hash, G015–G018 code/control receipts, Gate 8 Canary/runner 보호 상태가 확인되었다. shared-root observation status digest=`18b55e29a311fc0822c166448960f352112458e27dac3c49047e4fc254c3ade1`; live absorption/cutover/deletion은 시작되지 않았다. | external authority가 dedicated worktree를 제공한 뒤 BASE-05/06; 이어 14-day/1-day/>=3-day signed reconciliation | plan SHA-256, system audit, Gate 8 run `31314519580`, `LC_ALL=C git status --short | shasum -a 256` |
| 2026-08-09 | `whelp99-code/trevally` `9b8e23fac5b765a45c55a81b902c0ace1ce0cad9` → `340ac67af852c189b238801f3308191b8cbd96d2` | `git merge --ff-only docs-root-cleanup` rc `0`; canonical path=`/Volumes/DevSpace/orca/workspaces/wiki-spike/trevally`, branch=`whelp99-code/trevally`, dedicated baseline status digest=`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. `.serena/` present and ignored, observation-only allowlisted. | BASE-06 status guard 통과 뒤 authorized owner가 append-only ledger create/validate를 준비; remaining signed drift reconciliation | merge output, `realpath`, branch/HEAD/status argv, `.gitignore` `.serena/` rule |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | CODE-01 completed. dedicated status digest=`8493b30d8ae6da9a2e8926185461314a1512ed7e4767c83c76f3103a358d3e7c`; exact allowlist is resolver CLI plus CLI/red-team tests; `.serena/` remains ignored/preserved. focused 23, related decision/security 47, architecture, CLI help, diff check all rc `0`; full suite=`NOT_RUN`. External converge ledger `/Users/jmpark/.ouroboros/converge-ledgers/wiki-spike-second-brain/ledger.json` validates PASS, but its OOO CODE-01 item is `human_blocked` because current OOO Codex runtime resolves to `gpt-5.6-sol` without an exact Terra per-run route. Direct `gpt-5.6-terra` implementation with independent Sol verification was used; this is not OOO PASS. | GOV-01/GOV-02 remain `[⊘] NOT_AUTHORIZED` because DB-02/03/07 remain unresolved and receipt states `live_operation_authorized=false` | three file SHA-256 values in CODE-01; test/architecture/CLI/diff receipts; external ledger validation result |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | CODE-02 completed. dedicated status digest=`156f96662368b63fc9367ce54a107546b45ac6e46302421df4b575992cf7f6a4`; allowlist is CODE-01 three files plus CODE-02 Core ports, scanner, unit/red-team test four files; `.serena/` remains ignored/preserved. focused 86, security foundation 4, architecture, diff, top help, verify help rc `0`; invalid args rc `2`; full suite=`NOT_RUN`. No live cohort/personal/credential scan performed. | ADAPT-05/IMPORT remain `[⊘] NOT_AUTHORIZED`; CODE-02 is not live import authorization | four CODE-02 file SHA-256 values; bounded verification receipts |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | CODE-07 is `CODE_COMPLETE`: owned Core/contracts, Core/ports, four typed connectors, capture composition, and two adapter tests are recorded with exact SHA-256 values in the CODE row. Independent primary evidence: exact checklist suite 54 passed rc `0`; architecture rc `0`; `scan_secrets` rc `0`; scoped diff rc `0`. This evidence is process-local/non-authorizing: no live I/O, import, activation, or source access. CODE-03 is `[~] IN_PROGRESS_BLOCKED` after Slice A/B approved with focused 30 and Stage6 125 rc `0`, but `verify` rc `2` because no canonical out-of-band Stage-0 aggregate/trusted-key/signer-registry envelope can mint `RecallTrustAuthorityV2`; no restore mutation/trust bypass. CODE-04 is `[~] IN_PROGRESS_FAILED_REVIEW`: focused 24 and architecture rc `0`, but same-revision state-tamper and restart rollback `1→0` acceptance were reproduced; correction is in progress. CODE-05 is `[~] IN_PROGRESS`; implementation started, no verdict. | independent reviewer must re-check CODE-03 blocker, CODE-04 correction, and CODE-05 implementation; `ADAPT`/`GOV` remain `[⊘] NOT_AUTHORIZED` | CODE-07 file/test SHA-256 values and bounded command results; CODE-03/04/05 review facts |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | CODE-04 is `CODE_COMPLETE`: adapter SHA-256 `da1d055a1e9be986c4fc7864f9cf503f721820e5b7d0fdd308a4f3b4f139028c`, shadow CLI `29bdf9a1fdec27b9771f465c5879f539bf80d09961ffbc84a1d19586613ba17b`, deployment unit `04f9631622c2a82e8b9dadf192fa730b0f1c206b810aac63e6dc60959b3c711a`, deployment red test `8a557ddfe9a0cac6dd2dbe70a66c83d1ec8424a9d248dec4ba5a16a4057c7e30`. Original attacks were reproduced before fix; signed-state/fresh-head correction then rejected same-revision tamper and restart rollback. Exact checklist suite 31 passed rc `0`; native shadow red-team 57 passed rc `0`; architecture, `scan_secrets`, scoped diff rc `0`; standalone help rc `2` expected. Full native-shadow test is `NOT_RUN/INCONCLUSIVE`; no endpoint connectivity/live operation. | retain SHADOW manual gates `[⊘] NOT_AUTHORIZED`; no live shadow start follows this code evidence | primary evidence and four SHA-256 values |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | CODE-05 is `CODE_COMPLETE`: CLI `1d7c0acb39f7a48508f9fd6513af8ecbefd3b383fdd004a3e5aca3f880b74ec1`, Infrastructure adapter `358ff9a8ccd28f0b411a3913abb464f93896a830634d8e661778c127c4fdfc70`, Core contracts `ddcd389410c7cfc41fde112401763c0749a6850ca0b2d80655f8d61ad6dff45d`, Core ports `637f01817379e1c0b545830a43d67a035dd5b70f273fa621f0e02ac9164640f4`, CLI test `0fb7f38c0b367e945795372db3d6bc903402ffa6b6b085d7b40459dfa9e8a935`, red test `a3e01c3b1406ab1cedef1658fa76f2626150239f90a12f2ba926d1e1a46131d9`. Prior primary failure was `RC2/STATE_EXISTS true/OUT false`; after correction, a single signed canonical state+receipt bundle appears at exact `--out`, with primary reproduction `rc 0`, bundle exists, `CANONICAL_MUTATED`. 154 CODE-05+Stage6 passed rc `0`; architecture/secrets/compile/help/diff rc `0`; invalid rc `2`. | CUTOVER remains `[⊘] NOT_AUTHORIZED`; no live route action follows code evidence | primary evidence and six SHA-256 values |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | status digest=`7797cca3840777b8da77fcf3fa8c957b6870c90bb7fa7d4e0353397176d803b8`; CODE-03 is `DRIFTED` because the exact public CLI and trust boundary do not provide an external trust root. Choice A preserves exact argv and adds an internal authority composition seam; Choice B is a plan-reality revert requiring a new signed offline envelope and separate security plan. No authority change occurred. CODE-04/05 current `CODE_COMPLETE` bounded-review completion is acknowledged. | `PENDING_USER_APPROVAL`: select A or B before Slice C; no restore mutation or live operation is authorized. | branch/HEAD, status digest, CODE-03 design gate, CODE-04/05 bounded review evidence |
| 2026-08-10 01:40:17 KST | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | primary-verified protected GitHub run `31314519580` (`encrypted-lifecycle-canary`) is `in_progress` with empty conclusion; job `93247496969` (`CANARY_24H producer`) is `in_progress`. Step 7, `Run exact 24-hour canary and build immutable bundle`, started `2026-08-09T12:56:15Z` (`2026-08-09 21:56:15 KST`) and remains `in_progress`; steps 1–6 completed successfully. Strict local bundle import and immutable upload remain pending. No cancel, restart, or run mutation was performed; CODE-03 remains separately `PENDING_USER_APPROVAL` and no authority changed. | Do not authorize join/import work before successful Step 7 completion and immutable bundle; earliest exact 24-hour completion is `2026-08-10 21:56:15 KST`. | `gh run view 31314519580 --json databaseId,workflowName,status,conclusion,event,headSha,headBranch,createdAt,updatedAt,startedAt,jobs,url` rc `0` |
| 2026-08-10 01:40:17 KST | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | Correction of the prior row’s evidence-field omission only: dedicated worktree status digest=`7797cca3840777b8da77fcf3fa8c957b6870c90bb7fa7d4e0353397176d803b8`; exact current modified/untracked paths remain the previously reviewed CODE-01/02/03/04/05/07 implementation allowlist with no unexpected paths, and `.serena` remains ignored/preserved. No status or authority changed. | No new authorization; preserve all existing gate and authority states. | `git branch --show-current` rc `0`; `git rev-parse HEAD` rc `0`; `LC_ALL=C git status --short | shasum -a 256` rc `0` |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | status digest=`7797cca3840777b8da77fcf3fa8c957b6870c90bb7fa7d4e0353397176d803b8`; CODE-03 is `CODE_COMPLETE` under `APPROVED_OPTION_A_IMPLEMENTED`. Owned hashes: reconcile CLI `be563a412f22442e6b9321c8099150d455cd28f1e8ae9d689465ab4b2220573e`, focused test `ac0ef8bef91216b7acf4fd73a8bbe74dc214424e3353a48e1a3783e91fa8c440`, red-team test `dfd34fa73969784d9ee257c334559f3ff5c83e10cbd7299e294ee840c6f31752`. Primary-approved Option A preserves authority-less public verify rc `2`/no mutation, injects pre-minted authority internally, restores only from verified backup with precommit rollback, revalidates cited recall twice, and writes no serialized trust material. Evidence: focused 38 and Stage3/6 177 rc `0`; architecture/secrets/py_compile/help rc `0`; exact verify/unknown rc `2`; trust-surface search rc `1` no matches; diff rc `0`. Primary corrected/retested post-link `error + receipt exists` and false-green request mismatch; final postcommit attack has no error with committed receipt and precommit failures roll back. | No live action or authority change. RECON-01..03 remain `[⊘] NOT_AUTHORIZED`; public trust material is absent and operational restore/live action still requires manual gates. | supplied primary approval, branch/HEAD/status digest, three CODE-03 SHA-256 values, bounded verification rc summary; next `CODE-06` |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | current implementation status digest=`7797cca3840777b8da77fcf3fa8c957b6870c90bb7fa7d4e0353397176d803b8`; CODE-06 is `[~] IN_PROGRESS_BLOCKED`: current CODE-05 signed route state/bundle has no trusted `activated_at`; `CutoverDecisionV1`/runbook have role names/approval digests but no verifiable per-role signatures, approval timestamps, expiry, or trusted registry/freshness proof; `--allowlist-digest` is raw caller input with no signed evidence binding; no canonical consent-transfer receipt schema exists; exact public CLI has no trusted clock, key registry, or certificate signer and must not self-supply them. No CODE-06 implementation or certificate was created. | No authority, live, or deletion change. `PENDING_USER_APPROVAL`: user selects mutually exclusive A or B; no implementation/certificate/deletion before that choice. | branch/HEAD/status digest; CODE-06 design gate; current signed route/decision/runbook contracts |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | current status digest=`cb2093f720d1b8ecade94f8e25b47328b2bfc7329796e22e4f6b3ecce0427a93`; CODE-06 is `[x] CODE_COMPLETE` under `APPROVED_OPTION_A_IMPLEMENTED` (A selected by the user's recommendation delegation; B not selected). Owned hashes: CLI `989535645644378ced9d6cf668f463faf8207cf1b16e745fbfb2aee6f441aa27`, Core contracts `e56b094ef7d6f0a48ae74cd29109b8c07f7f81bb1980cfaf1d3d67d15f3f55ba`, Core ports `2cc4bf18944bfac09c3634978bfb85dfe59a904361a0dfdd0d8eb1ef11262244`, focused test `55829eed614ba341cf1db0f582b6c196baa1d2e1c39f0e90fbcc0c52f7c08117`, red-team test `aa66d6562c0bba3665425bde996232e8d1751a9dfa8ccb1025f77e78594f2694`. Exact public CLI remains authority-less rc `2`/no input read/no output; internal port uses out-of-band signer/approval registries and trusted clock to domain-separately verify activation/consent/four-role approval/certificate Ed25519, exact `90*24h`, and CODE-03 conservation; it produces signed closed `ROLLBACK_CLOSED` evidence only with `destructive_action_authorized=false`, with no deletion/revocation. Primary corrections (approval registry/certificate signature verification, forged DTO normalization, bad-signature false-green, consent-expiry and commit-point tests) were corrected/retested. | No live/certificate/deletion action or authority change. Next dependencies are Gate8, DB, GOV, and all manual operational gates; RETAIN-01..03 and DELETE-01 remain `[⊘] NOT_AUTHORIZED`. | supplied primary/Sol approval; focused 56 rc `0`; Stage6/reconcile/route 192 rc `0`; architecture/secrets/py_compile/help rc `0`; exact standalone rc `2` sentinel/no output; unknown rc `2`; trust-surface `rg` rc `1`; diff rc `0` |
| 2026-08-10 04:23:13 KST | `docs-root-cleanup` / `340ac67af852c189b238801f3308191b8cbd96d2` | Gate 8 observed evidence only: workflow `encrypted-lifecycle-canary`, run `31314519580`, job `93247496969`, status `in_progress`, conclusion empty. `CANARY_24H producer` step started `2026-08-09T12:56:15Z` (`2026-08-09 21:56:15 KST`); steps 1–6 succeeded. Strict local import and upload remain pending. No cancel, restart, run, PID, or artifact mutation was performed. | Do not cancel or restart. Do not authorize local import/upload or any live action until successful producer completion and required immutable evidence; earliest exact 24-hour completion is `2026-08-10 21:56:15 KST`. | verified live observation supplied at `2026-08-10 04:23:13 KST`; workflow/run/job/status/conclusion/head branch/SHA and producer-step timestamps |
| 2026-08-10 | `whelp99-code/trevally` and shared root / `340ac67af852c189b238801f3308191b8cbd96d2` | Current DB decision audit: trevally contains only `DB-04.json`; its embedded Ed25519 signatures verify rc `0`, decision is global `GO`, expiry `2027-08-07`, but trusted identity binding and resolved-scope verification remain required. Shared root additionally contains `DB-06-model-a.json` and `DB-08-archive.json`; embedded signatures verify rc `0`, each is scoped `NO_GO`, expires `2027-08-06`, SHA-256 respectively `4b0e6b7fcf38d4151e4e9587066cfb70fc5cbc0634ff8b49db34a86ba69298a2` and `5d82483d49106018b41e13d37c2693a562571e49dff098edb803e960a4624b60`. These shared-root records were not copied and no trusted-key binding is claimed. DB-01/02/03/05/07 remain unsigned/unresolved: DB-01/05/07 global block; DB-02/03 disabled/deferred. | GOV/live/import/cutover/delete remain `[⊘] NOT_AUTHORIZED`. DB-06/08 scopes remain disabled even if trusted binding is later accepted. Primary recommends resolving DRIFT-01 with a 14-day executable/doc minimum; that work is `IMPLEMENTATION_IN_PROGRESS` under separate Terra ownership. DRIFT-02 signed supersession remains `[⊘] NOT_AUTHORIZED`. | supplied verified decision audit: embedded-signature checks rc `0`; record presence/scope/expiry/SHA-256 facts; no shared-root record copy or authority change |
| 2026-08-10 | `whelp99-code/trevally` / `340ac67af852c189b238801f3308191b8cbd96d2` | DRIFT-01 current sync: 15 separate Terra-owned files align executable/doc minimum to 14 full days. `RecallSloV1` rejects `<14`, evaluation CLI defaults to 14, and `CutoverDecisionV1` requires `observation_days>=14`; DB-05/07, ADR, and runbook retain proposed 14 full days, `UNRESOLVED`, and signed-supersession-required wording. 90-day retention is unchanged. Primary independent evidence: 191 core/doc/stage4/stage6 + native CLI 7 + native checkpoint 1 = 199 passed rc `0`; architecture/secrets/py_compile/diff rc `0`; worker aggregate 198 rc `0`. Long native `test_signed_samples_require_real_wall_clock_and_raw_denominators` is `INCONCLUSIVE/NOT_RUN`, interrupted after 86.35s without a completed result on the existing crypto verification path; it is not counted as a pass. | DRIFT-01 is `[x] CODE_DOC_COMPLETE` only, non-authorizing. DRIFT-02 remains `[⊘] NOT_AUTHORIZED`; all GOV/live/import/shadow/cutover/delete gates remain non-authorized. | supplied independent/worker test and static evidence; 15-file alignment and unresolved decision/runbook evidence |
| 2026-08-10 | `whelp99-code/trevally` / `d76359ecffaf8215c5e6ec38c4a977afbdbab6bf` | Local commit `feat(second-brain): harden non-serving migration gates` records 44 files; post-commit dedicated status is clean with digest=`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. Root full command `PYTHONDONTWRITEBYTECODE=1 uv run --isolated --python 3.12 --extra dev python -m pytest -p no:cacheprovider -q` completed `2215 passed in 189.13s`, rc `0`. Architecture, secrets, compile, and diff checks are rc `0`; security re-review PASS addressed all 8 findings with no new CRITICAL/HIGH. | Local code/test closure is complete and committed locally only; it is not pushed and grants no live/import/cutover/delete authority. Signed DRIFT-02 and DB-05/07 operational authority remain absent; all manual operational gates stay `[⊘] NOT_AUTHORIZED`. | supplied local commit/status/full-suite/static/security evidence; operational/governance owner must separately supply authority and live evidence |
| 2026-08-10 | shared root / `docs-root-cleanup` | After this documentation edit, `LC_ALL=C git status --short | shasum -a 256` is `99a7098bffa773848b4b62a54c5eb135c52e47c518f85719d1bbc6b6477ff647`. The three owned documents remain under already-untracked `docs/planning/` / `docs/reports/` status prefixes, so content changes do not themselves alter status text. | Observation only; no stage, commit, push, or operational authority change. | shared-root status command rc `0` |
| 2026-08-10 | shared root / `docs-root-cleanup` | Final current observation after `.gitignore` and duplicate-test cleanup: status digest=`99a7098bffa773848b4b62a54c5eb135c52e47c518f85719d1bbc6b6477ff647`; exact current allowlist is below. Trevally remains clean at local commit `d76359ecffaf8215c5e6ec38c4a977afbdbab6bf`, status digest=`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. | Observation only; no stage, commit, push, or operational authority change. | `LC_ALL=C git status --short | shasum -a 256` rc `0`; supplied trevally clean commit/status evidence |

Final shared-root status allowlist (exact status paths/prefixes):

```text
.gitignore
artifacts/conformance/second-brain/db-decision-signing-red-team-v1.json
artifacts/conformance/second-brain/db-decision-signing-red-team-v2.json
artifacts/conformance/second-brain/db-decision-signing-red-team-v3.json
artifacts/conformance/second-brain/db04-recall-red-team-v1.json
artifacts/conformance/second-brain/db04-recall-red-team-v2.json
artifacts/product-release/second-brain-v1/decisions/DB-06-model-a.json
artifacts/product-release/second-brain-v1/decisions/DB-08-archive.json
artifacts/product-release/second-brain-v1/evidence/db-04-conflict-behavior-go-body-v1.json
artifacts/product-release/second-brain-v1/evidence/db-04-conflict-behavior-go-body-v2.json
artifacts/product-release/second-brain-v1/evidence/db-04-conflict-behavior-go-bundle-v1.json
artifacts/product-release/second-brain-v1/evidence/db-04-conflict-behavior-go-bundle-v2.json
artifacts/product-release/second-brain-v1/evidence/db-06-model-a-no-go-bundle-v1.json
artifacts/product-release/second-brain-v1/evidence/db-08-archive-no-go-bundle-v1.json
artifacts/product-release/second-brain-v1/governance/
artifacts/product-release/second-brain-v1/withdrawn/
docs/planning/
docs/reports/MAC_DATA_AGENT_SYSTEM_AUDIT_KR.html
docs/reports/ROADMAP_KR.html
docs/reports/SECOND_BRAIN_WORKFLOW_OVERVIEW_KR.html
uv.lock
```

새 checkpoint는 기존 행을 수정하지 않고 새 행만 추가한다. status drift는 status digest, branch, HEAD, observation time, allowlist comparison result, command rc를 새 행에 포함한다.

## REVIEW LOG

| 날짜 | 검토 유형 | 작성 사실 | 결론 | 다음 책임 |
|---|---|---|---|---|
| 2026-08-09 | 초기 작성 및 independent-review 보완 | plan SHA/branch/HEAD, Gate 8 runbook의 3-lane strict receipt wire, current shared-root status digest/allowlist, G015–G018 receipts, fixture-only/synthetic-only composition, DB-02/03/07 `UNRESOLVED`, current shadow CLI rc `2` design을 반영했다. | 이 문서는 live import, route switch, credential revoke, deletion을 인가하지 않는다. dedicated worktree, CODE-01..06 independent review, signed drift reconciliation이 선행 blocker다. | 운영 owner가 worktree/source authority를 제공하고 independent reviewer가 CODE gates, Gate 8 final import, resolution/cutover/decommission receipts를 검토한다. |
| 2026-08-10 | CODE-01 evidence update | CODE-01 implementation/test SHA-256, dedicated allowlisted status checkpoint, bounded verification, external ledger human-blocked routing result를 기록했다. | CODE-01 is `CODE_COMPLETE`, not live authorization and not OOO PASS. | independent reviewer가 CODE-01 receipt와 remaining CODE-02..07, DB decision/live gates를 분리 검토한다. |
| 2026-08-10 | CODE-02 evidence update | CODE-02 Core/scanner/test SHA-256, seven-file dedicated allowlist checkpoint, bounded verification, no-live-scan boundary를 기록했다. | CODE-02 is `CODE_COMPLETE`, not ADAPT-05, live cohort, or import authorization. | independent reviewer가 CODE-02 receipt와 remaining CODE-03..07, DB decision/live gates를 분리 검토한다. |
| 2026-08-10 | CODE-03/04/05/07 checkpoint review | CODE-07 owned-file/test SHA-256와 process-local bounded evidence(54 passed, architecture, `scan_secrets`, scoped diff 모두 rc `0`)를 기록했다. CODE-03 Slice A/B evidence(focused 30, Stage6 125, architecture/compile/diff rc `0`)와 Stage-0 trust-authority-envelope blocker/`verify` rc `2`, CODE-04 focused 24/architecture rc `0` 및 재현된 same-revision state tamper와 restart rollback `1→0` acceptance, CODE-05 implementation-started/no-verdict를 기록했다. | CODE-07 is `CODE_COMPLETE` only; no live I/O/import/activation occurred. CODE-03 is blocked, CODE-04 review failed pending correction, CODE-05 has no verdict. `ADAPT`/`GOV` and live/manual/deletion authorizations remain unchanged and `[⊘] NOT_AUTHORIZED` where previously so marked. | independent primary reviewer가 CODE-03 authority-envelope design, CODE-04 correction proof, CODE-05 implementation, and all separate governance/live gates를 분리 검증한다. |
| 2026-08-10 | CODE-04 primary-approved completion review | Original same-revision tamper and restart rollback attacks were reproduced before the signed-state/fresh-head correction; both are rejected after it. The exact CODE-04 hashes and bounded evidence (checklist 31, native red-team 57, architecture, `scan_secrets`, scoped diff rc `0`; standalone help rc `2` expected) are recorded. Full `test_native_shadow_measurement.py` is `NOT_RUN/INCONCLUSIVE`; no endpoint connectivity or live operation was tested. | CODE-04 is `CODE_COMPLETE` only. SHADOW manual gates remain `[⊘] NOT_AUTHORIZED`; no authorization changed. | independent operational authority must separately provide and verify all SHADOW manual-gate prerequisites. |
| 2026-08-10 | CODE-05 primary-approved completion review | Prior primary failure `RC2/STATE_EXISTS true/OUT false` is retained as history. The corrected implementation emits one signed canonical state+receipt bundle at exact `--out`; primary reproduction fixed with rc `0`, bundle exists, `CANONICAL_MUTATED`. Exact hashes and bounded evidence (154 CODE-05+Stage6, architecture, secrets, compile, help, diff rc `0`; invalid rc `2`) are recorded. | CODE-05 is `CODE_COMPLETE` only. No live route action occurred; CUTOVER manual gates remain `[⊘] NOT_AUTHORIZED`. | independent operational authority must separately provide and verify all CUTOVER manual-gate prerequisites. |
| 2026-08-10 | CODE-03 plan-sync design review | exact CLI/trust-boundary drift requires either A: preserve public argv with fail-closed standalone rc `2` plus an internal authority composition seam, or B: a separately approved canonical signed offline envelope with an external, non-self-supplied trust root. CODE-04/05 bounded-review `CODE_COMPLETE` evidence is acknowledged; no authority changed. | `REJECT` pending explicit design choice: implementation without an external trust root would be security-critical. No Slice-C restore mutation or live operation is authorized. | user selects A or B; primary/Sol then supplies explicit scope to Terra and independently verifies. |
| 2026-08-10 | CODE-03 final primary verdict record | Supplied primary/Sol verdict approves Slice C Option A after correction: exact public verify remains authority-less rc `2` and mutation-free; internal pre-minted `RecallTrustAuthorityV2` + `AtomicRecallSnapshotPort` seam, verified-backup-only isolated restore, precommit rollback, double independent cited-recall revalidation, and closed/self-digesting hash-only receipt are covered by the recorded hashes and bounded evidence. Initial post-link cleanup inconsistency (`error + receipt exists`) and false-green request mismatch were reproduced, corrected, and retested; final postcommit attack has no error with committed receipt state and precommit failures roll back. | `APPROVE` for the CODE-03 code gate only. CODE-03 is `CODE_COMPLETE`, not operational/live authorization; RECON-01..03 and all operational/manual gates remain unchanged `[⊘] NOT_AUTHORIZED`. | operational authority separately evaluates RECON/manual gates; next implementation gate is CODE-06. |
| 2026-08-10 | CODE-06 plan-sync design review | Current CODE-05 signed route state/bundle has no trusted `activated_at`; `CutoverDecisionV1`/runbook provide role names/approval digests but not verifiable per-role signatures, approval timestamps, expiry, or trusted registry/freshness proof; public `--allowlist-digest` is unbound caller input; no canonical consent-transfer receipt schema exists; the exact public CLI has no trusted clock, key registry, or certificate signer. Self-declared activation time, approvals, allowlist, or consent would be security-critical. No CODE-06 code, certificate, authority, live action, or deletion was created/changed. | `REJECT` pending design choice. CODE-06 remains `[~] IN_PROGRESS_BLOCKED`; CODE-01/02/03/04/05/07 remain code-only `CODE_COMPLETE`. | user selects A or B in the CODE-06 design gate; primary/Sol supplies explicit implementation scope and independently verifies any later Terra work. |
| 2026-08-10 | CODE-06 final primary verdict record | Primary/Sol independently approved Option A after two reject/correction cycles. Exact public CLI remains authority-less rc `2`, reads no input, and emits no output. Internal `DecommissionCertificateVerifierPort` accepts only out-of-band signer/approval registries and trusted clock, domain-separately verifies activation, consent, four-role approvals, and certificate Ed25519 signature, enforces exact `90*24h`, reuses CODE-03 conservation, and writes signed closed `ROLLBACK_CLOSED` evidence only with `destructive_action_authorized=false`. Missing approval registry/certificate-signature verification, forged DTO normalization hiding `destructive=true`, approval bad-signature false-green, consent-expiry, and commit-point cases were corrected and retested. | `APPROVE` for the CODE-06 code gate only: `APPROVED_OPTION_A_IMPLEMENTED` and `CODE_COMPLETE`. Operational/manual gates remain unchanged; no live action, certificate issuance, deletion, or revocation is authorized. | operational authority separately evaluates Gate8, DB, GOV, RETAIN, DELETE, and all manual prerequisites. |
| 2026-08-10 | DRIFT-01 final independent evidence record | Separate Terra-owned implementation/doc work aligns 15 files to a 14-full-day executable/doc minimum: `RecallSloV1` rejects `<14`, evaluation CLI default=14, `CutoverDecisionV1` requires `observation_days>=14`, and DB-05/07, ADR, and runbook retain proposed 14 full days with unresolved signed supersession. 90-day retention is unchanged. Primary independently passed 191 core/doc/stage4/stage6 tests, native CLI 7, and native checkpoint 1 (199 total, all rc `0`); architecture, secrets, py_compile, and diff rc `0`; worker aggregate 198 rc `0`. The long native `test_signed_samples_require_real_wall_clock_and_raw_denominators` has no completed result: it was interrupted after 86.35s at the existing crypto verification path and remains `INCONCLUSIVE/NOT_RUN`, not a passing test. | `CODE_DOC_COMPLETE` for DRIFT-01 only; no signed policy supersession or operational authorization. DRIFT-02 and GOV/live/import/shadow/cutover/delete gates remain `[⊘] NOT_AUTHORIZED`. | authorized operational/governance owner must complete signed DRIFT-02 supersession before any operational use. |
| 2026-08-10 | plan-review correction (append-only) | Prior `REJECT` findings are addressed in the current-state layer: `pending-approval.md` is labeled planning-only/`BLOCKED FOR CONSENSUS`; `$go` is constrained to local code/test/doc closure; BASE pre-code guard and post-CODE checkpoint are split; CODE-01…07 depend only on BASE-05; current code/doc floor is 3 full days/72h; 14-day/1-day and 199-test statements remain historical and are superseded for current state; DRIFT-02/DB-05/07 authority remains absent; ADAPT/RECON code-only rows are distinct from manual/live rows; 15 DRIFT files and static G015–G018 path/digests are enumerated. | No final full-suite total, post-commit hash, live I/O, import, cutover, or deletion result is claimed. Code remains uncommitted at this stage; operational gates stay `[⊘] NOT_AUTHORIZED`. | independent reviewer may validate the stated docs/static boundaries; governance/manual authority must supply signed DRIFT-02 and all operational evidence separately. |

| 2026-08-10 | final local closure evidence (append-only) | Follow-up independent evidence records local commit `d76359ecffaf8215c5e6ec38c4a977afbdbab6bf` (44 files), clean trevally status digest `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, root full suite `2215 passed in 189.13s` rc `0`, architecture/secrets/compile/diff rc `0`, and security re-review PASS for all 8 findings with no new CRITICAL/HIGH. | Replaces the prior row's “uncommitted/no final suite” current-state limitation only. Commit is local and not pushed; no live/import/cutover/delete authority changes. | retain signed DRIFT-02, DB-05/07, manual operational evidence, and separate live authority as blockers. |

### 2026-08-10 mobile shadow effective-observation checkpoint (append-only)

Mobile laptop power-off, sleep, or offline gaps are excluded from effective
observation time; valid prior effective time resumes when collection resumes.
The required floor remains 3 full days / 72 effective hours, so calendar
completion may exceed 72 hours. This code/doc checkpoint grants no live,
shadow, cutover, or other operational authority.
