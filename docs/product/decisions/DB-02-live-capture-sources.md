# DB-02 — Live capture sources

- **Record version:** 1
- **Canonical scope:** `source-profile:<source>:<profile>`; one independently resolved scope for each of `codex`, `claude-memory-bank`, `git`, and `markdown`.
- **Scope class:** Source-scoped
- **Owner:** Data Steward
- **Approver:** Privacy
- **Status:** UNRESOLVED — draft decision specification; no source/profile has signed approval, evidence digests, or a valid GO.
- **Decision deadline / implementation gate:** Before enabling the corresponding source adapter or profile.
- **Expiry:** Each source/profile GO expires at the earlier of its stated expiry or a change to provider terms/API behavior, consent, retention, deletion semantics, source capability, or fixture. A changed source/profile result requires a versioned superseding record.

## Original intent and reconciliation

**Original intent (verbatim):** “Codex, Claude/Memory Bank, Git, and Markdown are all intended first-release sources, but each remains disabled until its source-specific consent, retention, deletion, capability, and fixture evidence resolves GO.”

**Reconciled intended decision:** Codex, Claude/Memory Bank, Git, and Markdown are intended live sources, not enabled sources. Each exact source/profile is independently disabled by default and becomes eligible only after its own source capability, consent, retention, deletion, and fixture evidence is approved `GO`. Approval for one source/profile does not approve another profile, source, or provider.

## Required signed decision

For each named source/profile, the final record must state `GO` or `NO_GO`, canonical source/profile scope, owner and Privacy approver identities/signatures, decision date/expiry, and evidence digests. It must identify permitted artifact/data classes, account/scope boundary, credential/auth boundary, ID/revision and cursor behavior, pagination/limits, rename/history rewrite/symlink behavior where applicable, complete snapshot and tombstone deletion behavior, export mechanism, retention, reconciliation cadence, and fixture digest. Missing, stale, invalid, or unsigned material is **UNRESOLVED**, not `NO_GO`.

Required evidence for a source/profile `GO` is:

1. Current provider terms and API samples, or equivalent local-source capability evidence.
2. A source-specific consent fixture for the permitted account/scope and data classes.
3. Retention and deletion policy evidence plus a deletion/tombstone sample proving that deletion is not inferred.
4. A capability fixture exercising the declared source behavior, including cursor/checkpoint and source-specific edge cases.
5. Digests for all evidence and signatures by Data Steward and Privacy.

## GO / NO_GO semantics

- **GO:** enables only the exact named source/profile in composition and capability issuance; it must be included in the signed resolved scope, source/capability manifest, and eligible cohorts.
- **NO_GO:** disables only that named source/profile. It remains synthetic-only, is excluded from enabled sources and cohorts, and cannot be re-enabled by configuration or a fallback adapter.
- **UNRESOLVED:** leaves that source/profile disabled. This document does not enable any source.

## Acceptance evidence for the implementation gate

The adapter gate accepts a source/profile only with a valid signed GO and immutable evidence references demonstrating consent enforcement, retention classification, deletion/tombstone handling, declared capability behavior, and source fixture results. A valid scoped NO_GO is a successful Stage-0 resolution only for its disabled scope; Stage 2 still requires at least one consented non-synthetic capture source in the aggregated resolved scope.
