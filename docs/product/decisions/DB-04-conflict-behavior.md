# DB-04 — Conflict behavior

- **Record version:** 1
- **Canonical scope:** `global:first-release:conflict-behavior`
- **Scope class:** Global
- **Owner:** Product
- **Approver:** Trust
- **Status:** UNRESOLVED — draft decision specification; no signed owner/approver approval, evidence digests, or dated GO exists.
- **Decision deadline / implementation gate:** Stage 0, before ledger or recall implementation.
- **Expiry:** A signed GO expires at the earlier of its stated expiry or a material change to conflict presentation, citation semantics, review/approval semantics, or winner selection. A changed result requires a versioned superseding record; this draft supersedes nothing.

## Original intent and reconciliation

**Original intent (verbatim):** “Recall co-displays conflicting memories and their citations. When an approved current decision exists, it is marked as the winner while superseded/conflicting evidence remains visible.”

**Reconciled intended decision:** Recall must co-display conflicting memories with their citations. An approved current decision may be marked as the current decision winner, but it does not erase, hide, or rewrite superseded or conflicting evidence. Where review has not approved a current decision, recall must not invent a winner and must expose an abstention/conflict state.

## Required signed decision

The final record must state `GO` or `NO_GO`, bind global scope, owner and Trust approver identities/signatures, decision date/expiry, evidence digests, and this reconciliation. It must define the reviewed-current-decision predicate, citation requirements, winner marking, superseded-evidence visibility, conflict and abstention presentation, and behavior when citations or approval state cannot be verified. Missing, stale, invalid, or unsigned material is **UNRESOLVED**, not `NO_GO`.

A `GO` requires:

1. UX prototypes for co-display of conflicting memories and their citations, approved winner marking, superseded evidence, and abstention/no-winner states.
2. Adversarial conflict fixtures covering conflicting assertions, an approved current decision, supersession, absent approval, withdrawn support, and unavailable or invalid citation evidence.
3. Acceptance criteria proving that a winner never suppresses contrary/superseded evidence and that unverified state does not become a winner.
4. Evidence digests and signatures by Product and Trust.

## GO / NO_GO semantics

- **GO:** permits ledger and recall implementation only with the co-display, citation, reviewed-winner, and abstention behavior specified here. It is bound into the resolved scope and contract digest.
- **NO_GO:** is globally fatal and blocks ledger/recall implementation and product progression. It does not permit a single-result presentation, hidden conflict evidence, or automatic winner fallback.
- **UNRESOLVED:** blocks the same implementation gate. This document is currently unresolved and cannot be treated as a completed signed GO receipt.

## Acceptance evidence for the implementation gate

Before the gate passes, retain the signed decision and immutable evidence references proving: conflicting items and citations are co-displayed; an approved current decision is visibly marked as winner; superseded/conflicting evidence remains accessible with its citation; absent or invalid approval yields abstention rather than a fabricated winner; and citation verification failure does not silently serve an unsupported result. Stage-0 exit requires this global decision to be validly resolved as `GO`.
