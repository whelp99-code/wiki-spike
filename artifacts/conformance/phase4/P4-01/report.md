# P4-01 Conformance Report

## Scope

P4-01 implements only the Phase 4 Runtime metadata contracts and provider-neutral
Orchestrator state machine:

- stable operation identity and workspace-scoped idempotency;
- strict request, cancellation, result-reference, status, and response contracts;
- finite ordered pipeline stages;
- retry resumption through immutable stage result references;
- cancellation, absolute deadline, lease, and fencing behavior;
- in-memory conformance adapters with immutable semantic snapshots;
- Runtime-owned validation errors and enforced Core import boundary.

It does **not** implement P4-02 Intent/Temporal resolution, retrieval, model routing,
verification, recall, decision extraction, proactive behavior, external actions, or
Phase 5 applications.

## Requirement mapping

| Requirement | Evidence | Status |
|---|---|---|
| P4-F-001 stable operation | content-bound operation ID; redelivery tests | PASS |
| P4-F-001 deadline | strict UTC deadline; pre/post-stage checks | PASS |
| P4-F-001 state machine | ordered finite pipeline and terminal alternatives | PASS |
| duplicate prevention | stage leases, fencing, immutable result reuse | PASS |
| cancellation | first-signal immutability, race precedence, cooperative checkpoints | PASS |
| mutable-input isolation | entry revalidation, stage-local requests, immutable result snapshots | PASS |
| Runtime metadata privacy | response contains StageResultRef only | PASS |
| P4-F-020 boundary | Runtime imports only pinned Core contracts/ports | PASS |

## Security and privacy

Public contracts contain IDs, hashes, timestamps, reason codes, schema IDs, and
provenance references. They do not contain source text, model prompts/responses,
credentials, or provider clients. Cancellation/deadline wins over uncommitted output.

## Failure semantics

- transient stage failure and lost claim: `retry_later`;
- fatal/unhandled stage failure: terminal `failed`;
- unknown route/idempotency mismatch: `rejected`;
- cancellation/deadline: terminal and no uncommitted result reference;
- nondeterministic duplicate stage result: terminal failure.

## Rollback

P4-01 is additive and changes no signed Phase 3 artifact or Storage schema. Reverting
its files returns Runtime to the P4-00 closed contract skeleton.

## Completion semantics

P4-01 is complete only after full regression and all three required CI checks pass on
the exact PR head. CI evidence from an earlier bootstrap or superseded commit is not
sufficient. It does not create G4 and does not authorize Phase 5 work. P4-02 may begin
only after P4-01 is merged.
