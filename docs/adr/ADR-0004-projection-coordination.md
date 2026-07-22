# ADR-0004 — Projection coordination and independent pointers

## Status
Accepted for P3-06.

## Context
Signed Generation artifacts are the authoritative logical state. Identity, chronology,
keyword, semantic, graph, and export views are rebuildable projections. Treating every
projection as one release unit would let a semantic or graph failure block Core state,
while updating identity and chronology independently could expose a half-published
minimum profile.

## Decision
1. Projection builders consume a workspace-scoped, generation-pinned record set.
2. Every build emits a deterministic artifact manifest containing workspace,
   generation, schema version, records root, and artifact digest.
3. All successful artifacts are bound into a staging manifest before any pointer moves.
4. `identity` and `chronology` are the exact minimum profile and advance with one atomic
   compare-and-swap operation.
5. Optional projections advance independently; failure or CAS loss preserves their
   previous last-known-good pointer.
6. Projection pointers and artifacts are keyed by `(workspace_id, projection_name)`.
7. Rebuilding the same logical input must produce the same records root, artifact
   digest, and staging manifest digest.
8. Query results from a stale optional projection are post-filtered against the
   authoritative state at the requested generation.
9. Projection failure never changes or rolls back the authoritative Generation pointer.

## Consequences
- Minimum-profile availability is coupled only between identity and chronology.
- Optional projections can lag and expose their source generation explicitly.
- Staged artifacts that lose a pointer CAS are harmless, immutable rebuild products.
- Storage adapters may persist pointers later, but the Core contract remains free of
  Git, SQLite, CAS, and provider-specific imports.
