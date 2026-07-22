# ADR-0007 — Read-old/write-new schemas, explicit kinds, and historical keys

## Status
Accepted for P3-09.

## Context
Long-lived signed generations must remain readable after schemas and signing keys
change. Silently accepting unknown versions or deleting old verification keys would
make historical artifacts unverifiable. Allowing arbitrary kind strings would let
connectors and plugins invent incompatible payload semantics.

## Decision
1. Every versioned artifact carries a schema family and canonical positive integer
   version. Unknown families or versions fail closed.
2. All registered schema versions remain readable. One monotonically increasing write
   version is selected per family; new artifacts are emitted only at that version.
3. Old artifacts are validated in their original schema and migrated in memory through
   an explicit acyclic path. The original bytes are never rewritten.
4. Every schema version has a content digest and a canonical fixture digest. Registry
   startup fails if the fixture or validator changes the fixture unexpectedly.
5. Memory kinds are explicit definitions bound to a readable schema. Creatable kinds
   must target the current write schema.
6. Initial built-in kinds are reserved. Extension kinds require a namespace and cannot
   replace an existing definition. Retired kinds remain readable but cannot be created.
7. Historical public-key records contain only public material, allowed purposes,
   allowed domains, validity interval, and predecessor identity.
8. Key activation selects the current writer for one purpose/domain pair; rotation does
   not remove the predecessor record.
9. Signature frames include both purpose and domain before the payload. A valid
   generation signature cannot be replayed as a release/checkpoint/plugin signature.
10. Historical verification uses the key and validity interval that applied at
    `signed_at`, not merely the current active key.

## Consequences
- Schema migrations are executable code and must be covered by canonical fixtures.
- Recovery must restore registry snapshots and the compatible validator/migration code.
- Kind definition changes create new content-bound definition IDs rather than mutating
  historical definitions silently.
- Private signing material is never included in registry snapshots.
- P3-10 may use the deterministic registry snapshots as Recovery Set inventory inputs.
