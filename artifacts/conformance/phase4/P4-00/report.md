# P4-00 Conformance Report

## Scope

P4-00 establishes the Phase 4 bootstrap boundary only:

- immutable annotated-tag pin to signed G3;
- exact Phase 3 contract-file hashes;
- tag-worktree G3 verification;
- strict Runtime import allowlist;
- closed Runtime schema skeleton;
- Phase 4 preflight and minimized evidence.

## Requirement mapping

| Requirement | Evidence | Status |
|---|---|---|
| P4-F-020 Runtime boundary | `check_runtime_boundaries.py`, negative fixtures | PASS when CI is Green |
| G3 dependency | `phase4-g3-contract-pin.json`, signed tag worktree verification | PASS when CI is Green |
| Runtime schema freeze avoidance | `runtime-contracts.schema.json` rejects all instances | PASS |
| Existing regression | full warnings-as-errors suite and package smoke | PASS when CI is Green |

## Explicit non-scope

P4-00 does **not** implement P4-01 Runtime contracts or orchestration, temporal
resolution, retrieval, EvidencePack, recall, decision extraction, clarification,
proactive suggestions, action intents, model routing, budgets, or degradation.
It adds no Phase 5 connector, UI, notification, or external action execution.

## Security and privacy

The pin and evidence contain hashes, IDs, paths, counts, and status only. They do
not contain user memory content, prompt/response bodies, credentials, private
keys, or provider tokens. Runtime has no direct path to Storage implementations.

## Rollback

The change is additive except for making historical G3 verification tag-based.
Reverting P4-00 removes the Phase 4 package, schemas, scripts, tests, workflow,
and docs, and restores previous workflow/test behavior.

## Completion semantics

P4-00 is complete only after `phase3-preflight`, `phase3-g3-conformance`, and
`phase4-preflight` pass on its PR. It is not Phase 4 complete, not Phase 5
started, and not Production ready.
