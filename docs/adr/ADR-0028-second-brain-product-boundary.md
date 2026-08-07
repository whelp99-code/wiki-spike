# ADR-0028: Second-brain product boundary and serving authority

- Status: Proposed — implementation is blocked pending Stage-0 resolution and same-artifact review.
- Date: 2026-07-28
- Scope: Sole serving authority, source integration, authority transactions, temporal reads, privacy, composition, migration, projections, and evidence boundaries for the second-brain product.

## Context

A personal-memory product needs one answer to deletion, consent, freshness, conflict, temporal validity, and citation. Existing sources have different identifiers, history, export, and retention semantics. A permanent query-time federation, legacy fallback, or dual-write would create competing truth and make those guarantees non-atomic. Product evidence must also remain separate from the active Gate 8 evidence, whose tuple, labels, state, receipts, and history are immutable and outside this ADR's scope.

## Decision

### Sole authority and canonicalization

wiki-spike is the sole serving authority for the V2 product. Codex, Claude/Memory Bank, Git, Markdown, unified-db, legacy Mem0/RAG, and me-wiki are read-only capture or migration inputs, never peer serving gateways. Adapter-led canonicalization feeds one reviewed encrypted ledger and one V2 recall authority. No federation, query-time merge, read-through fallback, dual-write, or per-request legacy fallback is allowed.

Commands and decisions are immutable evidence. Accepted changesets plus activated signed generations are memory-state authority. Binding, deletion, freshness, capability, and route/cohort state are current visibility authority. Search, conflict, publication, dashboard, and other managed projections are rebuildable/withholdable only and never competing truth.

### Authority unit of work and outbox

Each mutation is one `BEGIN IMMEDIATE` authority unit of work: validate command and capability; persist encrypted CAS artifact and immutable signed intent; atomically commit the authoritative control row, outbox entry, and event reference; then idempotently materialize projections. A projection, event log, cursor, or outbox cannot establish memory truth independently. Current consent disable vetoes capture and serving.

### Temporal serving contract

`RecallServeSnapshotV2` is the sole multi-result linearization primitive. One WAL read transaction pins workspace, selected signed generation/checkpoint, binding/deletion/freshness/capability epochs, projection version, transaction cut, selected revisions, and resolved-scope/contract digest. Application authorizes and obtains it once; Runtime uses only its pinned candidates; Application verifies statements against it. Continuations bind its digest, ordered cursor, and capability subject/scope and fail closed on expiry or authority, checkpoint, or scope mismatch.

Requests carry `recorded_as_of` (transaction axis, defaulting to the cut) and `valid_as_of` (IANA time). Intervals are `[from,to)`. Precedence is: authorization denial; global authority/floor/binding/recovery/route/cohort invalidity; current deletion/consent veto; transaction eligibility; validity/expiry; support/conflict winner or abstention; then snapshot candidate/citation verification. No per-artifact reread may form an answer.

### Privacy field classes

Native account/scope/configuration, native IDs, revisions, paths, cursors, raw normalized-body digests, bodies, locators, labels, rationales, benchmark content, and external payloads are privacy-bearing. Native mapping is immutable encrypted CAS content. Durable databases, manifests, and telemetry carry only typed opaque keyed references and ciphertext digests, never those raw values or unkeyed content digests. Query text is ephemeral or a keyed reference. Telemetry and release evidence are body-free. Hidden reasoning is never persisted.

Benchmark data has separate encrypted storage, keys, and capabilities from serving memory; it cannot become recall candidates or generation input. External egress is local-first and requires a separately valid, explicit data-class/provider/route opt-in; there is no provider fallback.

### One connector family and composition

Core owns source-reader, source-checkpoint, and low-level API/filesystem/credential ports. Application owns exactly one typed connector family at `connectors/{codex,claude_memory_bank,git,markdown}` implementing source-reader/checkpoint ports. Infrastructure owns only low-level API, filesystem, and credential clients implementing distinct Core ports. Infrastructure must not implement typed source adapters or import connectors, Application, Runtime, or legacy storage. Connectors must not import Infrastructure. Composition alone creates low-level clients, injects them into connectors, and crosses layers.

The sole production root is V2-only composition. V2 API and MCP transports are transport-only. Production startup must not reach V1 handlers, direct-key mode, `Workspace`, legacy CLI/storage constructors, or generic plaintext-dump routes. Compatibility V1 is isolated from production composition.

### Migration, cutover, and retention

Migration cohorts write directly into the final encrypted workspace and remain non-serving until activation. They are not shadow workspaces and cannot be cross-namespace promoted, re-encrypted, or re-identified. Cohorts are source-by-source, limited to enabled migration sources in the resolved scope, and require a 1-day measured shadow period before cutover. After that period, a cohort that satisfies the quantitative cutover formula and all external role approvals transitions directly to live serving. Legacy systems are read-only for 90 days after activation.

Before first canonical mutation, an emergency rollback can route the whole cohort to the exact read-only pre-cutover UI/API with banner and write freeze. The first canonical mutation closes rollback. Thereafter failure is fail-closed disable/read-abstention, never legacy routing or history/key resurrection. Cutover requires its separately signed decision and evidence; this ADR grants no activation.

### Projection and evidence boundary

First-release publication is limited to managed internal projections. External export is disabled until a destination-specific DB-08 record is validly GO. Product evaluation and product-release evidence are separate from product serving authority and must use their own manifests and receipts. Fresh foundational evidence may be referenced only by exact authorized digest; active Gate 8 evidence must never be relabeled, copied, imported, modified, restarted, canceled, or presented as product proof.

## Alternatives considered

1. **Permanent federation/query-time merge:** Rejected because it creates competing serving, deletion, consent, temporal, and citation authorities.
2. **Big-bang replacement:** Rejected because source semantics, benchmark quality, reconciliation, and rollback evidence are unproven.
3. **Adapter-led canonicalization in a final workspace:** Chosen because it permits source-specific ingestion while retaining one reviewed, encrypted serving authority and bounded pre-mutation rollback.

## Consequences

- Stage 0 requires every DB-01..08 record to be validly resolved; DB-01, DB-04, DB-05, and DB-07 require global GO. Scoped NO_GO for DB-02, DB-03, DB-06, or DB-08 disables only the named source/profile, migration cohort, provider route, or export destination and never enables fallback.
- `ResolvedScopeV1` and its signed contract digest bind decision versions/digests, enabled and disabled sources, allowed cohorts, feature flags, destinations, and mandatory-release constraints. Scope changes require supersession and rereview.
- Every signed DB record carries a positive record revision, decision timestamp, verbatim original interview question plus reconciliation, and either no supersession for revision 1 or an exact prior-revision digest linkage for the same decision scope. These lifecycle fields are signed and included in decision and aggregate digests.
- The Stage-0 manifest fixes DB-02 to `Codex`, `Claude/Memory Bank`, `Git`, and `Markdown`, and DB-03 to `unified-db`, `legacy Mem0/RAG`, and `me-wiki`; DB-06 and DB-08 require explicit signed configured scopes. The resolved feature set is closed and exactly derived from valid global GO decisions; mandatory release constraints are non-empty.
- No implementation, capture, listener, egress, publication, route switch, release certification, or product evidence claim is authorized by this ADR alone.
- Existing ADR-0026 and ADR-0027 remain binding for identity, binding, deletion, floor, recovery, and freshness; this ADR does not weaken them.

## Follow-ups

1. Obtain schema-valid, evidence-complete, unexpired signatures for DB-01..08 and materialize the resolved scope/contract digest.
2. Complete same-artifact review for ADR-0026A and confirm ADR-0027 is not weakened.
3. Define and verify V2 contracts, privacy field handling, authority/outbox semantics, connector ownership, root denial, and temporal snapshot behavior before implementation.
4. Produce separate evaluation, product-release, migration, and cutover evidence; do not use Gate 8 as product proof.
5. Keep multi-user collaboration, autonomous promotion, external publication, and permanent federation outside the first release unless separately approved.
