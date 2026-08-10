# wiki-spike 완료 설명서 (Phase 1a + 1b + SUB-07 + 통합 CLI)
**기준 설계**: `wiki_dev_plan_v3.3_standalone.md`  
**성격**: v3.3의 위험한 발행 가정을 **실제 git·sqlite 코드로 검증한 폐기 가능 spike** (스키마 동결 아님)  
**규모**: 소스 14개 모듈 + 테스트 6개 파일, 약 2,287 LOC, **53개 테스트 전부 통과**

---

## 1. 이번에 완료한 것

| 범위 | 내용 | 상태 |
|---|---|---|
| **Phase 1a** | CAS write-once, canonicalization(NFC), Merkle, Ed25519, Claim IR, SourceManifest 상태머신, 결정론 mock 추출기, IngestService | ✅ |
| **Phase 1b** | candidate commit + retention anchor + citation 순서(SUB-05), SQLite 활성화 트랜잭션 + publication CAS + orphan-first + CAS 패자 requeue + read-model 결속(SUB-06) | ✅ |
| **SUB-07** | single-publisher lease, remote mirror(파생 미러·idempotent), search staleness post-filter(§11) | ✅ |
| **통합** | Phase 1a→1b를 잇는 `wiki ingest/search/mirror/log` CLI (영속 git+sqlite+서명키) | ✅ |

---

## 2. 모듈 지도

```
src/wiki_spike/
├── canonical.py     NFC + 정렬키 JSON, raw number 금지(→ canonical string)
├── hashing.py       sha256, canonical_hash, sorted-leaf Merkle root
├── signing.py       Ed25519 + domain separator + 키 로테이션 + 키 영속화
├── cas.py           CAS write-once(0o444, verify-after-write, tombstone-only)
├── models.py        SourceManifest 상태머신, Claim IR(3분할), ResolutionDecision,
│                    accepted_claim_set_root(비순환 Merkle)
├── claims.py        결정론 mock 추출기(소스=데이터, 지시 미실행)
├── ingest.py        Phase 1a IngestService (발행 없음)
├── assembler.py     결정론 render + citation index + wiki_files_root
├── gitrepo.py       git plumbing (commit-tree, retention anchor, CAS ref, gc)
├── generation.py    SUB-05: 순서 강제 render→citation→digest→descriptor→id→서명→commit→anchor
├── controlplane.py  SUB-06/07: SQLite 계약, 활성화 트랜잭션, lease, resolution, search index
├── publish.py       발행 오케스트레이션 + CAS 패자 requeue + resolution/search 기록
├── mirror.py        SUB-07: 원격 미러(파생), outbox relay(idempotent)
├── search.py        SUB-07: staleness post-filter(§11)
└── workspace.py     통합: 1a+1b+SUB-07 배선(영속) + lease 가드
```

---

## 3. 코드로 입증한 v3.3 핵심 주장 (문서 정합이 아니라 실행)

1. **N1 비순환** — `generation_id = H(descriptor)`이고 descriptor에 commit oid/자기 id 없음. commit 안 manifest에도 자기 commit oid 없음. (`test_generation_id_is_acyclic_hash_of_descriptor`, `test_manifest_in_commit_has_no_self_commit_oid`)
2. **N2 citation 순서** — citation index가 commit **안**에 존재 = commit 전에 빌드됨. (`test_citation_index_present_in_commit`)
3. **N3 retention anchor** — `git gc --prune=now` 후 anchor 있는 candidate는 살아남고(서명 검증까지), anchor 없는 commit은 제거됨. **양방향으로 anchor의 필요성 입증**. (`test_git_gc_retention_anchor_keeps_candidate`, `test_git_gc_prunes_unanchored_commit`)
4. **N4 orphan-first** — git prepare 후 DB 활성화 전 crash → 아무것도 발행 안 됨, candidate는 보존. DB 후 crash → outbox relay 재개. (`test_crash_before_db_...`, `test_crash_after_db_...`)
5. **N5 활성화 원자성** — 단일 `BEGIN IMMEDIATE`에 CAS + read-model binding + 상태전환 + 포인터전환 + outbox. binding 불일치 시 발행 거부. (`test_activation_refuses_on_binding_mismatch`)
6. **CAS 패자 requeue** — stale parent 발행이 CASConflict → 새 parent로 rebuild 후 성공, **정상 소스 유실 없음**. (`test_stale_cas_conflict_and_requeue`)
7. **§11 staleness** — 검색 인덱스가 뒤처져도 현재 세대에서 superseded된 claim은 post-filter로 반환 안 됨. (`test_search_filters_superseded_when_stale`)
8. **single-publisher lease** — 다른 publisher가 lease 보유 시 발행 거부. (`test_lease_blocks_second_publisher`)
9. **원격 미러 idempotent** — outbox 기반 push, 재실행 no-op, 원격에 객체 도달. (`test_mirror_pushes_and_is_idempotent`)

---

## 4. spike가 새로 드러낸 설계 디테일 (문서만으론 안 보이던 것)

- **release 포인터 진실원은 SQLite** → git `releases/current` ref는 미러링 전 DB 포인터로부터 **materialize** 해야 함. 이걸 빠뜨려 push 실패가 났고, "파생 미러" 규칙을 명시적으로 코드에 넣어 해결.
- **Phase 1a엔 영속 control-plane이 없음** → cross-process idempotency/compile은 in-memory manifest에 의존 불가. CAS 존재 + content 순수함수 재유도로 해결. (Phase 1b가 SQLite를 정말로 필요로 함을 입증)

---

## 5. 실행 방법

```bash
pip install --break-system-packages cryptography pytest
cd wiki-spike
PYTHONPATH=src python3 -m pytest -q            # 53 tests

# 통합 파이프라인
PYTHONPATH=src python3 -m wiki_spike.cli --root /tmp/ws ingest tests/fixtures/normal.md
PYTHONPATH=src python3 -m wiki_spike.cli --root /tmp/ws log
PYTHONPATH=src python3 -m wiki_spike.cli --root /tmp/ws search Product
PYTHONPATH=src python3 -m wiki_spike.cli --root /tmp/ws mirror
```

---

## 6. 아직 남긴 것 (정직하게)

- **확률적 NarrativeDraft render** — pinned LLM(exact model ID) 확정 후 교체. 현재는 결정론 assembler(대안 A).
- **실제 전원장애 crash-matrix** — WAL/synchronous=FULL 계약은 넣었으나 물리 전원장애 테스트는 범위 밖.
- **exact model ID** — 여전히 PENDING(spike는 MOCK). selection eval로 확정 필요.

이 spike는 "프로덕션 코드"가 아니라, **v3.3의 발행 코어·SUB-07 가정이 실제 git·sqlite에서 성립함을 실행으로 보인 검증물**이다. 스키마는 검증 후 동결 대상이다.
