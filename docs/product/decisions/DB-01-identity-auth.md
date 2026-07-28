# DB-01 — Identity and authorization

- **Record version:** 1
- **Canonical scope:** `global:first-release:identity-auth`
- **Scope class:** Global
- **Owner:** Product
- **Approver:** Security
- **Status:** UNRESOLVED — draft decision specification; no owner or approver signature, evidence digest, or dated approval is present.
- **Decision deadline / implementation gate:** Stage 0, before any identity, capability, listener, or later implementation.
- **Expiry:** A signed GO expires at the earlier of its stated expiry or any material change to trust roots, device enrollment, delegation authorization, or authorization UX. A replacement must be a versioned superseding record; this draft supersedes nothing.

## Original intent and reconciliation

**Original intent (verbatim):** “Single user with multiple trusted devices; explicit delegated reviewers are permitted. Delegation is action-scoped, revocable, auditable, and never grants ownership transfer.”

**Reconciled intended decision:** First release is for one owning user who may enroll multiple trusted devices. A delegated reviewer may receive only an explicit, action-scoped authorization. Delegation is revocable, auditable, time-bounded where the authorization says so, and cannot transfer workspace ownership, ownership privileges, or authority to delegate further.

## Required signed decision

The eventual signed decision must be either `GO` or `NO_GO`, name the exact workspace/profile scope, record owner and Security approver identities and signatures, bind evidence by digest, state decision date and expiry, and preserve this reconciliation. Unknown fields, absent signatures, invalid signatures, stale evidence, expired approval, or unanswered evidence leave the record **UNRESOLVED**, not `NO_GO`.

A `GO` authorizes implementation only when all of the following are evidenced:

1. A trust-root and device/auth threat assessment covering enrollment, loss, compromise, recovery, wrong-workspace access, and revocation.
2. An authorization UX fixture showing owner enrollment, trusted-device use, action-scoped delegation, visible scope, revocation, audit visibility, and denied actions.
3. A delegation fixture proving least privilege: an allowed action succeeds; an ungranted action, ownership transfer, re-delegation, expired delegation, and revoked delegation fail without a write.
4. Evidence digests for the assessment and every fixture, plus owner and Security signatures over the final record.

## GO / NO_GO semantics

- **GO:** permits only the identity/auth implementation described above and binds its evidence and expiry into the Stage-0 resolved scope and contract digest.
- **NO_GO:** is globally fatal. It blocks product identity/capability, listeners, and all later implementation; it does not authorize a weaker identity model, shared ownership, or an implicit reviewer fallback.
- **UNRESOLVED:** has the same blocking effect as no record for Stage-0 exit. This document is currently unresolved and is not a GO receipt.

## Acceptance evidence for the implementation gate

Before the gate can pass, retain the signed record and immutable evidence references showing: trusted-device enrollment and revocation; owner-only authority; action-scoped reviewer allow/deny behavior; audit records for grant and revoke; wrong-workspace denial; and zero-write denial for expired or revoked authority. Stage 0 may aggregate this decision only as validly resolved; because this is global, Stage-0 exit requires `GO`.
