# ADR-0027: Encrypted lifecycle recovery, floor protocol, and deletion

- Status: Accepted (Gate 1)
- Date: 2026-07-24
- Scope: Encrypted Single-Memory Lifecycle — deletion phase model, dual create-only custody, binding-aware reconciliation partition, recovery proof modes, forward-only floor protocol, freshness serve gate, WAL read linearization, three-tier deletion truth, threat limits
- Binding plan artifacts (path + sha256):
  - `.gjc/_session-019f8ebe-012e-7000-b140-8e9aced136fc/plans/ralplan/019f8ebe-012e-7000-b140-8e9aced136fc/stage-08-revision.md` — `ef4ff3b275356e5c9754550c9cbfb04a65ffc6668204f3e9fa0578479146048d`
  - `stage-09-revision.md` (same directory) — `284cbe71af0519c79b21f7dda8cdd145a3a5366193f30540f3d54866a923a1f3`
  - `stage-10-revision.md` (same directory) — `2fe01ee1…` (Revision 10, supersession authoritative over Stage 8/9 wording)
- Companion ADR: ADR-0026 (authority/identity). This ADR owns recovery and deletion; identity messages, KDF labels, and the single signature-input rule it depends on are defined there and not restated in full.

## Context

Deletion in this system must be irreversible for keys while remaining auditable, and must never destroy an artifact that any authenticated authority still considers active. Two independent, physically separate key custodians (platform Keychain and a recovery keystore) exist specifically so that neither authority alone can complete a destructive action, and so that partial failure during creation never leaves an artifact revision unrecoverable but also un-destroyable. The binding registry (ADR-0026 §1) is the sole authority for classifying an artifact as destroyable; SQLite is always only a cache in this decision.

Revision 9 closed the freshness-gate wire and the floor-completion crash matrix; Revision 10 struck the one remaining ambiguous adoption path, added a floor-checkpoint replay-binding validation step, retired a duplicate attestation type name, and added the operator-facing quarantine recovery contract. Revision 10 is authoritative wherever it conflicts with Stage 8 or Stage 9 text.

## Decision

### 1. Deletion phase model

```
REQUESTED → API_VETO → TOMBSTONE → CHECKPOINT_COMMITTED
  → REVOCATION_KEYS_DESTROYED → KEYS_DESTROYED / CRYPTO_SHRED_COMPLETE → PURGE → COMPLETE
```

`API_VETO` is a distinct phase from crypto-shred: it is the fail-fast check that current live/restored serving, in-flight reads, cache, and history immediately stop offering a selector once a FORGET request is accepted, and it happens *before* any key material is touched. Crypto-shred (`REVOCATION_KEYS_DESTROYED` → `KEYS_DESTROYED`/`CRYPTO_SHRED_COMPLETE`) is the separate, later, irreversible phase where both custodians' ARK material for the targeted revision(s) is destroyed. `PURGE` removes remaining ciphertext/CAS/registry bookkeeping once keys are gone; `COMPLETE` is the terminal, immutable state that gates body-bearing `remember --new-consent` (ADR-0026 §2 new-consent preconditions require authoritative prior deletion phase `COMPLETE`).

The phase sequence is strictly forward-only. No phase is skippable, and no phase reachable after `REVOCATION_KEYS_DESTROYED` can be reversed — this is the crypto-shred irreversibility guarantee.

**Deletion phase ↔ binding transition-leaf token mapping (P3 errata).** The `deletion-state-v1` phase enum and the `binding-leaf-v1` `LifecycleTransitionLeafV1` status enum name the same underlying crypto-shred step with two tokens that MUST be treated as 1:1 equivalents by any implementation and mapping table:

| deletion-state phase | binding transition-leaf status | meaning |
|---|---|---|
| `REVOCATION_KEYS_DESTROYED` | `REVOCATION_KEYS_DESTROYED` | first custodian's ARK destroyed |
| `CRYPTO_SHRED_COMPLETE` | `KEYS_DESTROYED` | both custodians' ARK material destroyed; revision cryptographically unrecoverable |

The divergent spelling (`CRYPTO_SHRED_COMPLETE` in the deletion-state machine vs `KEYS_DESTROYED` in the transition leaf) is sanctioned but MUST resolve through this table; no third state exists between them.

### 2. Dual create-only custody

Every per-artifact-revision ARK (ADR-0026 §6) is created independently in platform Keychain and in a separate recovery keystore, never derived from one custodian by the other. The sequence is:

`PREPARED → platform create/readback → recovery create/readback → CAS materialization → final SQLite ACTIVE election`

Both custodians are create-only: an existing key is never overwritten in place, only created then later destroyed. Each creation step is immediately followed by an authenticated readback before the next step proceeds, so a crash between create and readback is detectable rather than silently assumed. SQLite only elects `ACTIVE` after both custodians and CAS materialization are confirmed — SQLite ACTIVE is a downstream cache write, never the first commit point.

**Orphan inventory reconciliation** joins DB, platform, recovery, and CAS state against a current signed binding checkpoint before any destructive action. Because the DB owner row is only a cache, classification is always: DB/platform/recovery/CAS joined with a current signed checkpoint and exact registry proof (leaf, history inclusion, sparse current membership/non-membership — ADR-0026 §1).

### 3. Binding-aware reconciliation partition

Classification outcomes are exhaustive and exact:

- `RESUME_EXACT` — current PREPARED membership plus exact non-ACTIVE intent/metadata; resumes the exact in-flight custody sequence, never a new one.
- `DESTROY_UNBOUND` — exact current-map non-membership plus complete DB/staging/CAS/provider inventories, or membership in `PREPARED→EXPIRED` for the exact never-ACTIVE intent.
- `DESTROY_LOSER` / `DESTROY_EXPIRED` — current exact membership in `LOSER`/`EXPIRED` plus complete non-collision joins.
- `QUARANTINE_ACTIVE` — current ACTIVE, or a historical ACTIVE without a later valid `VETOED`/`DESTROYED` transition. **Never destroyed.**
- `QUARANTINE_COLLISION` — any handle/identity/fingerprint disagreement across joined authorities.
- `QUARANTINE_UNKNOWN` — everything else: missing, stale, or corrupt authority or inventory.

The invariant is unconditional: only unbound, losing, or expired artifacts are ever destroyed; anything currently `ACTIVE`-bound is never destroyed under any code path, crash timing, or reconciliation race. Before each provider destroy call, body-free cleanup evidence is persisted; under lease, a fresh challenge/checkpoint/consistency proof is fetched and DB winner/ACTIVE/staging/providers/CAS are re-read. Destroy proceeds conditionally only if status/proof/snapshots/fingerprint remain exact and no active historical binding exists; any change between classification and destroy yields zero further destroy calls for that attempt.

### 4. Recovery proof modes

Two recovery/restore proof modes exist, both requiring a fresh signed checkpoint and proof set, never a cached or stale one:

- **DELTA_CONTINUITY** — proves generation continuity from the last locally trusted checkpoint forward through unbroken history-consistency and inclusion proofs to the terminal current leaf.
- **AUTHORITATIVE_SNAPSHOT** — proves consistency directly against a freshly issued authoritative checkpoint without requiring the full intermediate history chain, for cases where DELTA_CONTINUITY's local trust anchor is unavailable or too far behind.

Both modes require: complete veto/transition sets, history consistency from the classified checkpoint, valid signer chain, and non-regressing local floor. Expiry or a missing proof under either mode is `QUARANTINE_UNKNOWN`, never destructive or restorative authority — an incomplete proof can never be treated as an implicit pass.

### 5. Four-state floor protocol

Attempt states are exactly `CHALLENGE_RESERVED`, `COUNTER_UPDATE_PREPARED`, `FLOOR_UPDATE_PREPARED`, `KEYCHAIN_COMMITTED`, cycling back to stable `FLOOR_STABLE` on successful completion. Only one active attempt exists at a time; a new reservation is forbidden until the current attempt stabilizes or quarantines.

1. Under `BEGIN IMMEDIATE`, require exact DB/Keychain stable equality, reserve `old+1` and a fresh `ChallengeNonceHex64`, persist exact request bytes/digests, then dispatch.
2. Before any valid response-derived candidate is prepared, any terminal malformed/invalid/timeout/outage/cancel/explicit-abort/startup-abandonment transitions `CHALLENGE_RESERVED → COUNTER_UPDATE_PREPARED` exactly once — the **only** constructor path for a counter-only candidate. A counter-only candidate can never be prepared after a response-derived candidate exists.
3. A fully validated response (workspace, old floor, nonce/counter, signer chain, clock/freshness, checkpoint, consistency, veto/transition/binding proofs, non-regression, policy) transitions atomically to `FLOOR_UPDATE_PREPARED` with one exact `VALIDATED_ADVANCE` candidate and its canonical evidence digests.
4. Once `FLOOR_UPDATE_PREPARED` exists, candidate bytes are immutable and **must complete** through Keychain CAS/readback and DB stabilization — the CAS/readback path is the same regardless of whether the candidate arrived via a full response or (never, per step 2) a counter-only path. Expiry after preparation cannot replace, downgrade, cancel, or rewrite it to counter-only.
5. CAS Keychain from exact old hash/generation to exact candidate; authenticate readback; persist `KEYCHAIN_COMMITTED`; copy exact readback into DB stable; re-read both authorities. A Keychain/DB outage retries the same bytes; unknown CAS outcome always reads Keychain first before any further mutation.
6. If preparation evidence expires before stabilization or before first survivor serve, the exact candidate still finishes, but restored visibility is marked `FRESH_CHALLENGE_REQUIRED`; no survivor keys or plaintext are created or served until a later fresh challenge stabilizes from the now-stable floor.
7. **(R9-1/R10-1, binding, supersedes Stage 8 §7):** CAS "winning" is limited to the single exact candidate A per attempt. Any Keychain value B other than the expected old floor or byte-identical A — including an otherwise-valid authenticated direct child — transitions the attempt to `QUARANTINED_FLOOR_CONFLICT` (see §8). No adoption, supersession, multi-hop, or sequential-chain convergence path exists in this system at any revision from R9 forward.
8. A new reservation is forbidden until stabilization or quarantine; the next counter is stable+1. No failure, outage, expiry, or loser reuses a nonce or counter, or serves.

### 6. Durable freshness serve gate

`FreshnessServeGateV1` is exactly `{schema:"wiki-freshness-serve-gate-v1", workspace_id, state:"CLEAR|FRESH_CHALLENGE_REQUIRED", stable_floor_generation, stable_checkpoint_id, source_candidate_digest, reason:"ATTESTATION_EXPIRED_BEFORE_STABILIZE|CLOCK_WINDOW_EXPIRED|NONE", updated_at}`, all counters/generations canonical decimal strings, IDs strict existing scalar types.

**R10-3 (binding):** the schema admits a `oneOf` constraint with exactly three valid `(state, reason)` pairs:

1. `("CLEAR", "NONE")`
2. `("FRESH_CHALLENGE_REQUIRED", "ATTESTATION_EXPIRED_BEFORE_STABILIZE")`
3. `("FRESH_CHALLENGE_REQUIRED", "CLOCK_WINDOW_EXPIRED")`

Any other combination fails schema validation at write time and is treated as malformed (no-serve) at read time. The initial floor bootstrap transaction atomically writes `("CLEAR","NONE")` with the initial floor row.

**Errata correction (LOW, consensus pass 10):** the two enumerated fields (`state` with 2 values, `reason` with 3 values) admit 2×3 = 6 total combinations, of which exactly 3 are valid per the `oneOf` list above — leaving exactly **three invalid in-enum pairs**, not six. Negative-vector coverage for this gate MUST enumerate exactly the three invalid in-enum combinations (`CLEAR`+either expiry reason, `FRESH_CHALLENGE_REQUIRED`+`NONE`) plus any out-of-enum values; a "six invalid pairs" framing is corrected here and must not be carried into schemas or test plans.

If A completes after freshness expiry, the same final `BEGIN IMMEDIATE` transaction that stabilizes A also writes `FRESH_CHALLENGE_REQUIRED`; survivor keys and serve remain disabled until a newly validated exact candidate completes through the §5 protocol and atomically clears the gate. Missing/malformed/non-CLEAR always means no-serve. Attempt cleanup never deletes the gate.

### 7. Attestation identity and floor-checkpoint replay binding

**R10-4 (binding):** `BindingLatestReadAttestationPayloadV1` (R9-3) *is* the concrete frozen schema for every reference to a "latest read attestation" in the binding-registry/recovery freshness path. The name `LatestReadAttestationV1` is retired from normative text; schema files and code use only `BindingLatestReadAttestationPayloadV1`. The deletion-provider veto-set attestation (Revision 5) remains a distinct type with its own domain and is unaffected by this retirement.

Wire: `{payload, signature_algorithm:"Ed25519", signature}` where `payload` is exactly `{schema, workspace_id, request_nonce, challenge_counter, request_floor_checkpoint_id, checkpoint_id, checkpoint_sha256, checkpoint_sequence, history_size, history_root, current_map_size, current_map_root, signer_key_id, issued_at, expires_at}`, all numbers decimal strings, signed under domain `wiki.binding.latest-read-attestation.v1\0` (ADR-0026 §4). `checkpoint_id == checkpoint_sha256 == sha256(canonical checkpoint payload)`.

**R10-5 (binding):** added to the ordered validation pipeline at step 2 (attestation validation): `request_floor_checkpoint_id` MUST equal the `stable_checkpoint_id` of the local floor row read in the *same transaction* that reserved `(request_nonce, challenge_counter)`. A mismatch aborts with `attestation_floor_mismatch` before any checkpoint/proof processing, key staging, destroy, or serve. This binds a provider response to the exact local floor its challenge was issued from and prevents cross-floor replay. Coverage requires one positive vector plus two negative vectors (wrong floor at issue time; floor advanced between reservation and response).

Full validation order (R9-3, amended by R10-5): strict decode and raw canonical-byte equality → attestation signature/time/nonce/counter/signer chain → `request_floor_checkpoint_id` == reservation-transaction `stable_checkpoint_id` (R10-5) → checkpoint ID/signature and equality with signed roots/sizes → history consistency → every inclusion/transition → sparse membership/non-membership → binding classification → monotonic local-floor update. Any omission, extra/reorder, fork/gap, invalid transition, root/size mismatch, stale/replayed attestation, duplicate proof, or noncanonical bytes aborts before destroy, key staging, or serve.

### 8. `QUARANTINED_FLOOR_CONFLICT` operator recovery contract (R10-6, binding)

Quarantine is never automatically resolved. Operator recovery is a documented, audited, offline procedure:

1. Export the quarantine record (attempt rows, authenticated A and B digests, Keychain readback receipt) as a body-free signed report.
2. Determine authority: if B is provider-authenticated and strictly newer by counter/generation, local candidate A is abandoned — the operator issues a **fresh challenge from the authenticated B floor** after independently verifying B's signer chain; A is never retro-completed under any circumstance. If B cannot be authenticated, the workspace remains quarantined and restore-from-verified-backup is the only path.
3. Recovery never mutates candidate bytes, never lowers any floor, never re-enables serve before a new fresh challenge completes through the §5 protocol, and always appends the resolution to the audit ledger.
4. The operational runbook MUST include a `QUARANTINED_FLOOR_CONFLICT` chapter; its absence is a Gate 1 documentation failure.

Required vectors: authenticated-newer-B recovery, unauthenticatable-B permanent quarantine, and crash during recovery export (idempotent re-export).

### 9. WAL checked-snapshot read linearization

Read linearization has exactly one point: the atomic checked-snapshot read acquisition under WAL. There is no writer-fence or transaction-completion linearization point. A "delete-after-check" read (a read whose selector is invalidated by a FORGET accepted concurrently) is legitimate and treated as one pre-linearized response — it reflects state as of its own atomic checked-snapshot acquisition, not a later state, and is never retroactively invalidated. Forced two-connection barrier tests validate this ordering directly against WAL semantics.

### 10. Three-tier deletion truth and backup residual bound

Deletion truth is explicitly three-tiered, and no single tier is conflated with another in documentation, tests, or user-facing claims:

1. **Immediate live** — API veto (phase `API_VETO`) stops all new selector-based serving immediately upon accepted FORGET, before any key material is touched.
2. **Bounded backup** — a fixed residual window of **N = 30 days** during which a verified backup restore could still surface pre-deletion ciphertext; this bound is a documented operational limit, not a cryptographic guarantee, and rollback (see below) is explicitly bounded by current veto state.
3. **Irreversible egress disclosure** — once approved-external egress has disclosed content, that disclosure cannot be recalled; deletion after egress removes the local system's copies and future serving, but does not and cannot claim to erase already-disclosed external copies.

### 11. Threat limits (explicit non-claims)

This system makes no claim of physical SSD-block overwrite, no claim of resistance to a root or kernel-level adversary, and no claim of live-memory (in-process/swap) protection. Crypto-shred destroys the ARK material required to decrypt a given artifact revision; it does not claim that residual ciphertext bytes are physically unrecoverable from underlying storage media, nor that an adversary with root/kernel access or live process memory access is denied. Documentation, tests, and operator runbooks must not overclaim beyond: deterministic private identity, targeted crypto-shred of key material, fail-closed recovery, conservative cleanup (never destroy ACTIVE-bound), WAL-correct linearized reads, and auditable evidence.

## Consequences

- The strict forward-only deletion phase model and irreversible crypto-shred boundary make "undelete" structurally impossible past `REVOCATION_KEYS_DESTROYED`, at the cost of requiring every recovery/new-consent path to originate fresh material rather than resuming prior state.
- Binding-aware reconciliation guarantees zero accidental destruction of ACTIVE-bound artifacts even under corrupt-row or concurrent-classification races, at the cost of defaulting to `QUARANTINE_UNKNOWN` (no progress) whenever authority cannot be freshly and completely proven.
- The R9-1/R10-1 exact-A floor completion rule eliminates an entire class of unverifiable convergence races, at the cost of routing every non-exact CAS outcome to a manual, audited operator procedure (§8) rather than automatic resolution.
- The three valid `(state,reason)` freshness pairs (R10-3) make the serve gate exhaustively enumerable and testable, correcting the earlier six-invalid-pair miscount to the accurate three.
- WAL checked-snapshot linearization gives one unambiguous "as-of" point for every read, including deletion races, at the cost of requiring every reader to treat a delete-after-check response as valid rather than stale.
- The 30-day backup residual and three-tier deletion truth make the system's actual guarantees explicit and bounded, preventing overclaiming in documentation while still requiring operational discipline (verified-backup-only restore, no ad hoc copies) to keep the bound meaningful.

## Non-goals

Identity message construction, HKDF labels, the single signature-input rule, nonce typing, ARK per-revision granularity as a concept, and bundle self-field projection are owned by ADR-0026 and are referenced here only where recovery/deletion mechanics depend on them.
