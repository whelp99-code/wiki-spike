# ADR-0003 — AcceptedChangeSet publication boundary

## Status
Accepted for P3-05.

## Context
A `CommandEnvelope` is a request, not authoritative state. Only a fully resolved,
canonically hashed `AcceptedChangeSet` may be bound into a signed generation. The
existing storage engine already has a strong Git prepare / SQLite activate boundary,
but the legacy `PublishService.publish()` combined those phases and could not expose
crash-before/after-activation semantics to the Core.

## Decision
1. `ChangeSetBuilder` creates a workspace-scoped, parent-pinned change set over
   self-authenticating object revision references.
2. `StoragePublicationAdapter` resolves every reference, recalculates each revision
   hash, recalculates `changes_root` and `changeset_id`, and rejects partial input.
3. `PublishService.prepare()` creates and registers immutable candidate/release
   artifacts but never moves the publication pointer.
4. `PublishService.activate_prepared()` performs the existing SQLite CAS activation.
5. The exact change-set binding is included in the signed generation descriptor.
6. Same-change-set replay returns the already published generation and repairs
   mandatory DB materialization from the signed snapshot.
7. The legacy ingestion path remains backward compatible and may retain its bounded
   rebase retry; the AcceptedChangeSet path is strict and never silently rebases.

## Consequences
- Git prepare artifacts may exist as recoverable orphans after a crash.
- A failed validation or stale parent never changes the publication pointer.
- Mandatory post-activation materialization is idempotently repairable.
- P3-06 may build optional projections independently from this authoritative boundary.
