# DB-03 — Migration sources

- **Record version:** 1
- **Canonical scope inventory:** three DB-03 `migration_source` scope names, exactly `legacy Mem0/RAG`, `me-wiki`, and `unified-db`; each is independently resolved.
- **Scope class:** Source-scoped
- **Owner:** Migration
- **Approver:** Security
- **Status:** UNRESOLVED — draft decision specification; no migration source has signatures, evidence digests, or a valid GO.
- **Decision deadline / implementation gate:** Before source registration or migration-cohort registration.
- **Expiry:** Each source GO expires at the earlier of its stated expiry or a change to export behavior, schema/version, native identity/revision semantics, watermark behavior, or deletion/history behavior. A changed result requires a versioned superseding record.

## Original intent and reconciliation

**Original intent (verbatim):** “unified-db, legacy Mem0/RAG, and me-wiki are all intended read-only migration sources. Each must independently satisfy export, identity, revision, watermark, deletion-history, and fixture requirements; no runtime fallback is allowed.”

**Reconciled intended decision:** the configured DB-03 manifest is exactly `legacy Mem0/RAG`, `me-wiki`, and `unified-db`. They are intended read-only migration inputs only. They are never serving authorities or runtime fallback paths. Each source independently requires verified export, identity, revision, watermark, deletion/history, and fixture evidence before it may enter a migration cohort.

## Required signed decision

For every named migration source, the final record must state `GO` or `NO_GO`, its canonical source scope, owner and Security approver identities/signatures, decision date/expiry, and evidence digests. It must pin read-only export method; schema and version; native ID and revision mapping; cursor/watermark and overlap behavior; pagination/limits; deletion/tombstone and history behavior; retention; and source fixture digest. Missing, stale, invalid, or unsigned material is **UNRESOLVED**, not `NO_GO`.

A source-specific `GO` requires:

1. A read-only export fixture that cannot mutate the source.
2. A pinned schema/version and mapping evidence for source identity and revisions.
3. Watermark/cursor evidence, including overlap/restart behavior sufficient for reconciliation.
4. Deletion and history samples that distinguish tombstones, retained history, and unavailable history without inference.
5. Signed evidence digests and owner/Security signatures.

## GO / NO_GO semantics

- **GO:** permits only that source to be registered as a read-only migration input and to appear in allowed migration sources and a later signed cohort roster.
- **NO_GO:** excludes only that source from the migration cohort. It cannot be imported, routed, retried, or substituted through configuration; no legacy or unified serving fallback is allowed.
- **UNRESOLVED:** excludes that source. This document is not approval to import or route any migration source.

## Acceptance evidence for the implementation gate

Registration requires a valid signed GO and immutable evidence references for read-only export, pinned identity/revision mapping, watermark/reconciliation, deletion/history treatment, and fixture results. Later cutover may use only a roster that is a subset of, and binds the exact digest of, allowed migration sources in the resolved scope; Stage 6 cannot cut over a source unless its DB-03/capability resolution is GO.
