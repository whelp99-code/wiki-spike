Encrypted Single-Memory Lifecycle — Approved Execution

Binding plan set (ralplan consensus pass 10, sha 788685b8):
- Base: .gjc/_session-019f8ebe-012e-7000-b140-8e9aced136fc/plans/ralplan/019f8ebe-012e-7000-b140-8e9aced136fc/stage-08-revision.md
- Delta: stage-09-revision.md (R9-1..R9-4)
- Delta: stage-10-revision.md (R10-1..R10-6, supersession authoritative)

Constraints:
- Strict gate sequencing: each gate requires prior gate PASS.
- Never parallel-edit identity/KDF, floor, ARK/deletion, or binding authority.
- Executor receives one approved gate at a time.
- Frozen Core rejects raw numeric values; all numerics are canonical decimal strings.
- No product initialization until Gate 1 PASS.
- Gate 9 (Agent-Blackbox) is out of scope absent a new ADR.
- Repository pin: main 6de541c (554 tests passing).
- All 11 owner intent decisions remain binding.
- Escalation/Risk Gate: stop and require same-artifact Architect/Critic review on any schema/enum/key/provider/durable surface change.

@goal: Gate 0+1 — Governance pin and blocking contracts/feasibility
Pin branch/ref/workflow/admin evidence (Gate 0 read-only governance). Then produce
the complete Gate 1 blocking artifact set: ADR-0026 (authority/identity), ADR-0027
(recovery/deletion), all strict schemas under schemas/encrypted-lifecycle/, complete
literal test vectors under tests/fixtures/encrypted_lifecycle/ (identity, KDF, nonces,
binding wire/roots/proofs, floor state machine, bundle one-pass, evidence DAG, WAL,
new-consent, crash matrix), generator and independent validator scripts, SQLCipher
feasibility harness, Gate 1 validator/writer, bundle builder/importer, and CI workflows
with exact platform tokens and four-way commit equality. Independently reproduce all
identity/nonce/binding/floor/bundle bytes. Zero HIGH/MEDIUM ambiguity. Strict bundle
import. No product initialization. Includes R9-1 strict exact-A floor completion,
R9-2 FreshnessServeGateV1, R9-3 binding attestation/proof wire, R9-4 canonical manifest
raw-byte enforcement, R10-1 supersession enumeration, R10-2 single signature-input rule,
R10-3 serve-gate valid pairs, R10-4 attestation type identity, R10-5
request_floor_checkpoint_id validation, R10-6 QUARANTINED_FLOOR_CONFLICT recovery contract.

@goal: Gate 2 — Encrypted foundation
Pre-write guard and architecture boundaries, selected storage profile marker (SQLCipher
A or field-AEAD B, no runtime fallback), identity/KDF module, create-only dual custody
(platform + recovery keystores), protected DB initialization, opaque CAS, command
manifests, convergent winner election, binding registry with signed history and sparse
current map, corrupt-row-safe reconciliation, and evidence plumbing. All encrypted
before durability. WAL checked-snapshot reads.

@goal: Gate 3 — Deterministic vertical
Encrypted ingestion (REMEMBER) through candidate review (APPROVE/REJECT), change set
construction, signed generation with binding checkpoint, activation via readback/CAS,
and opaque projection. Complete ExpectedActiveRevisionV1 projection. DELTA_CONTINUITY
and AUTHORITATIVE_SNAPSHOT recovery modes. Forward-only floor protocol with immutable
prepared-floor completion and freshness serve gate.

@goal: Gate 4 — Review, correction, multi-source, new-consent
Terminal review workflow, atomic R1 retract/R2 add corrections, support/contradict
evidence edges, tombstone behavior, multi-source evidence fragments with exact locators
(BYTE_RANGE, LINE_RANGE, JSON_POINTER, WHOLE_SOURCE), and body-bearing new-consent
(REMEMBER --new-consent) only after completed prior deletion with both custody absence
receipts.

@goal: Gate 5 — Deletion and selective restore
Immediate forget veto through shred/purge completion, deletion checkpoint, dual ARK
destroy (platform + recovery), crash recovery at every transaction boundary, both
recovery modes (DELTA_CONTINUITY, AUTHORITATIVE_SNAPSHOT), immutable floor and binding
proofs before visibility, QUARANTINED_FLOOR_CONFLICT operator recovery, and
QUARANTINE_UNKNOWN fail-closed for missing/corrupt/stale proof.

@goal: Gate 6 — Extraction value
Resolve egress policy (local-default, deny-by-default external), frozen 60-item
extraction corpus (40/10/10), bounded attempts (2 attempts / 5 business days),
extractor profiles (LOCAL_RULES_V1, LOCAL_MODEL_V1, APPROVED_EXTERNAL_V1), and
approved egress ledger.

@goal: Gate 7 — Read-only MCP
Two scoped authenticated MCP tools (memory_recall, memory_source), 64 KiB response
bound, shared checked-snapshot primitive, no write path, no caller trust beyond
authentication.

@goal: Gate 8 — Conformance, canary, and review
Same-commit conformance run and exactly 24-hour canary on self-hosted macOS runners,
three strict immutable tuple imports (gate1, conformance, canary), verdict-free
pre-review manifest, two independent attestations, separate receipt, evidence join
preserving three independent import receipts, and 30-query recall corpus (15/5/5/5).
