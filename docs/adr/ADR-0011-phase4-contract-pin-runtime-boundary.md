# ADR-0011: Phase 4 consumes an immutable G3 contract through a narrow Runtime boundary

- Status: Accepted for P4-00
- Date: 2026-07-22
- Scope: Phase 3 contract pin, Runtime import boundary, Phase 4 CI bootstrap

## Context

Phase 3 is complete at signed G3 checkpoint
`379297f172ebf60a30dd4bce8b8e1dc139ff249ea72b2561879af5807afed832` and
annotated tag `phase3-core-v1.0.0`. Phase 4 must evolve the repository without
redefining the Phase 3 source inventory as though it were still G3. It also must
not reach around Core ports into SQLite, CAS, Git, signing, publication, or the
legacy Workspace object.

Running the historical G3 verifier against an evolving Phase 4 checkout is
incorrect: the signed inventory is intentionally immutable, while Phase 4 adds
new source. Conversely, merely retaining a prose release name is insufficient;
a moved lightweight tag or modified Core file could silently change Runtime
semantics.

## Decision

### 1. Immutable contract pin

`.github/phase4-g3-contract-pin.json` content-binds:

- repository and release name;
- annotated tag object ID and dereferenced commit;
- signed G3 checkpoint ID and source root;
- public Core API digest;
- the exact Phase 3 files consumed as Runtime contracts;
- the expected Phase 3 status-check names;
- the only Core modules Runtime may import directly.

`verify_phase3_contract_pin.py` requires the annotated tag object and commit to
match, verifies pinned files both in the current checkout and a detached release
worktree, and runs the signed G3 verifier and conformance verification inside
that worktree. A Phase 4 PR therefore cannot modify frozen Core files while
claiming to consume the same release.

### 2. Historical G3 CI

`phase3-g3-conformance` checks out the immutable tag rather than the evolving PR
head. It remains proof of the historical Phase 3 release. Current Phase 4 code is
validated by `phase4-preflight` and by the existing regression gate.

### 3. Runtime import boundary

Runtime source under `src/wiki_spike/memory_runtime` may import:

- its own package;
- `wiki_spike.memory_core.contracts`;
- `wiki_spike.memory_core.ports`.

All other `wiki_spike` imports are rejected by AST analysis, including constant
or nonconstant dynamic imports. This is stricter than the general layer lint and
prevents direct coupling to Core implementation modules.

The frozen Phase 3 release has no general `ProjectionPort` in `memory_core.ports`.
P4-00 therefore defines a narrow Runtime-owned `ProjectionPort` facade in
`memory_runtime.core_api`; it does not modify the signed Phase 3 API.

### 4. Closed Runtime schema

P4-00 does not invent Runtime request or result contracts. The Phase 4 Runtime
schema is a fail-closed skeleton that rejects every instance. P4-01 must replace
it with explicit versioned contracts and state-machine tests.

## Consequences

- Phase 4 can add code without invalidating the historical G3 proof.
- Frozen Core contract files cannot drift unnoticed in later PRs.
- Runtime dependency direction is machine-enforced before orchestration exists.
- The Phase 3 tag becomes an operationally load-bearing immutable reference.
- P4-00 is infrastructure only; it implements no recall, decision, model, action,
  or application behavior.

## Limitations

- Git tag immutability ultimately depends on repository administration. The pin
  detects movement but cannot prevent an administrator from attempting it.
- Import lint controls source dependencies, not every possible runtime side
  channel or subprocess. Later gateways require separate capability controls.
- Branch-protection required checks are external GitHub state.
- This ADR does not claim Production readiness.

## Rollback

P4-00 is additive except for adapting historical G3 tests/workflow to verify the
immutable tag. Reverting it removes the Phase 4 package, schemas, pin, lint,
workflow, and evidence, and restores the prior current-checkout G3 behavior.
