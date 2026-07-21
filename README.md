# wiki-spike — Phase 1a Walking Skeleton (disposable)

Reference: `wiki_dev_plan_v3.3_standalone.md`, §13 (SUB-01/02), §14 (M1a).

> ⚠️ **Disposable spike.** The schema here is NOT a production contract. Its purpose
> is to *validate* the v3.3 design assumptions in code before Phase 1b. Several
> round-4/5 blockers (self-referential hash, git-gc, citation ordering) were the
> kind of bug that only a running spike surfaces — so we run one.

## Scope (Phase 1a only)
Deterministic infrastructure that needs **no LLM** (exact model id is still PENDING):

- **CAS write-once** (`cas.py`): content-addressed, `0o444` after commit,
  verify-after-write, delete-via-tombstone-only, integrity `scan()`.
- **Canonicalization** (`canonical.py`): Unicode **NFC**, sorted keys, and a hard
  rule that **raw numbers are forbidden** (numbers/dates/versions/ids must be
  canonical strings) — closes the IEEE-754 gap from review round 5.
- **Merkle root** (`hashing.py`): sorted-leaf, domain-separated → order-independent
  `accepted_claim_set_root` over **generation-id-free** `ResolutionDecision`s
  (closes the indirect self-reference N1).
- **Ed25519 signing** (`signing.py`): domain separator `wiki.generation.v1`,
  keyring with rotation (old key ids stay verifiable).
- **Claim IR** (`models.py`): `ClaimIdentity` (claim_id **includes polarity**),
  `ClaimAssertion` (evidence array), `Evidence` (multi-locator: text_span/pdf/table),
  strict `SourceManifest` state machine.
- **Deterministic mock extractor** (`claims.py`): stands in for the pinned LLM so
  M1a runs without a model. Source body is treated strictly as **data**; injection
  strings are inert and do **not** trigger quarantine.
- **IngestService** (`ingest.py`): `receive` → CAS + manifest; `compile` → Claim IR.
  **No publication / no generation commit / no read models** (that is Phase 1b).

## Phase 1b spike (SUB-05 + SUB-06) — validated with REAL git + sqlite
Built to *test the riskiest design claims in code*, not for production:

- **SUB-05 candidate build** (`generation.py`, `assembler.py`, `gitrepo.py`):
  strict order render → citation index → digests → descriptor → `generation_id =
  H(descriptor)` → sign → `git commit-tree` → **retention anchor**
  `refs/wiki/generations/<gen>`.
  - Fixes **N2** (citation index is built *before* the commit and lives inside it).
  - Fixes **N1** (descriptor has no commit oid / no generation_id → acyclic; the
    manifest inside the commit never contains its own commit oid).
  - Fixes **N3** (retention anchor keeps the candidate reachable across `git gc`).
- **SUB-06 activation** (`controlplane.py`, `publish.py`): SQLite control-plane with
  the contract PRAGMAs (WAL / synchronous=FULL / foreign_keys / busy_timeout), a
  single `BEGIN IMMEDIATE` activation that atomically does CAS(parent) + read-model
  **binding** check + state flip + pointer flip + outbox insert.
  - **orphan-first** (§5-2): git is prepare-only; SQLite commit is the sole
    authoritative activation boundary.
  - **CAS-loser requeue** (§5-4): a stale publisher rebuilds against the new parent
    and retries — no ingest is lost.

### Phase 1b facts the spike proved in code
- `git gc --prune=now` prunes an **unanchored** commit but **keeps** the anchored
  candidate (test proves both directions → the retention anchor is load-bearing).
- Activation is **refused** on read-model digest mismatch or not-ready state
  (B3 binding enforced inside the transaction; publication pointer stays put).
- Reproducible `generation_id`: same inputs → same descriptor → same id across repos.

## Still deferred (beyond this spike)
The probabilistic NarrativeDraft render path (needs the pinned LLM) and the full
crash-matrix under real power-loss. Everything else below is now implemented.

## SUB-07 — remote mirror, single-publisher lease, staleness (real git + sqlite)
- **Single-publisher lease** (`controlplane.py`): a TTL lease row; only the holder
  publishes. `test_lease_exclusivity` / `test_lease_expires`.
- **Remote mirror** (`mirror.py`): control-plane DB is authoritative, the Git remote
  is a **derived** mirror. The outbox drives idempotent pushes; immutable
  `generations/<gen>` refs plus a force-synced `releases/current` (materialized from
  the DB pointer). Re-running is a no-op. `test_mirror_pushes_and_is_idempotent`.
- **Search staleness post-filter** (`search.py`, §11): the search pointer may lag the
  wiki pointer; every hit is post-filtered against the CURRENT wiki generation's
  claim resolution so **superseded/retracted claims are never returned**, results are
  flagged `stale`, and disabled past `max_generation_lag`.
  `test_search_filters_superseded_when_stale`.

## Integration — Phase 1a → 1b in one CLI (`workspace.py`, `cli.py`)
`wiki ingest <path>` runs receive → compile → publish under a lease; `wiki search`,
`wiki mirror`, and `wiki log` complete the loop. Persistent git repo + SQLite +
Ed25519 signing key under `--root`.

```bash
wiki ingest tests/fixtures/normal.md     # -> generation published, pointer advanced
wiki log                                 # G1 superseded / G2 published
wiki search Product                      # staleness-aware query
wiki mirror                              # relay outbox to the remote mirror
```
Exit codes: `0` ok · `3` quarantined · `4` idempotent · `5` zero claims ·
`7` lease held by another publisher · `66` path not found.

### Facts the SUB-07/integration spike proved in code
- Release pointer authority is in **SQLite**; the git `releases/current` ref must be
  *materialized from the DB* before mirroring (the spike surfaced this — a missing
  ref caused a push failure until the derived-mirror rule was made explicit).
- A lagging search index never leaks a superseded claim (post-filter, not LKG alone).
- A second publisher is refused while the lease is held.

## What the spike already proved (design facts, not opinions)
1. **No persistent control-plane in 1a**: cross-process idempotency and compile
   cannot rely on in-memory manifests. Fixed by keying idempotency off the
   persistent CAS and re-deriving representation from content (a pure function).
   → confirms Phase 1b genuinely needs the SQLite control-plane.
2. **Polarity must be in `claim_id`**: `positive` vs `negative` produce distinct
   ids end-to-end (test proves the round-4 bug is gone).
3. **Injection-as-data**: a source containing "delete every page…" is staged and
   compiles to its one legitimate claim; the instruction is never executed.

## Run
```bash
pip install --break-system-packages cryptography pytest
cd wiki-spike
PYTHONPATH=src python3 -m pytest -q                 # 75 tests
PYTHONPATH=src python3 -m wiki_spike.cli --root /tmp/wk receive tests/fixtures/normal.md
PYTHONPATH=src python3 -m wiki_spike.cli --root /tmp/wk compile <source_id>
```

### CLI exit codes
`0` ok · `3` quarantined · `4` idempotent no-op · `5` zero claims · `66` path not found.
