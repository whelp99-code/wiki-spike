# ADR-0012: Stable Runtime operation and fenced stage orchestration

- Status: Accepted for P4-01
- Date: 2026-07-22
- Scope: Runtime request/response/status contracts, cancellation, deadlines, retries, stage result references

## Context

Phase 4 Runtime will later coordinate intent resolution, retrieval, model generation,
verification, recall, decisions, clarification, and proactive suggestions. Those
components are probabilistic or provider-dependent, but their orchestration cannot be.
A delivery retry must not create a second logical operation, a slow worker must not
commit after losing its lease, and cancellation or deadline expiry must win over an
uncommitted result.

The Runtime also cannot put source text, model output, credentials, or mutable storage
handles into its public response. Phase 3 remains the authoritative persistence layer;
P4-01 only defines metadata contracts and an adapter-independent reference state
machine.

## Decision

### 1. Stable operation identity

`RuntimeRequest.operation_id` is the domain-separated SHA-256 of semantic request
identity:

- idempotency key;
- workspace and actor;
- request type;
- absolute UTC deadline;
- requested Generation;
- canonical payload.

Transport `request_id` and `received_at` are excluded. A redelivery can therefore use
a new request ID without creating a new logical operation. Reusing an idempotency key
with a different semantic identity is rejected.

### 2. Strict versioned contracts

P4-01 publishes five explicit contract families:

- `RuntimeRequest`;
- `CancellationSignal`;
- `StageResultRef`;
- `RuntimeStatus`;
- `RuntimeResponse`.

All use exact field allowlists, canonical UTF-8 JSON, Unicode NFC, canonical integer
strings, strict UTC timestamps, and content-bound IDs. Raw JSON numbers are forbidden.
Runtime owns its validation error taxonomy and translates failures from the frozen Core
canonicalization primitive instead of importing Core implementation errors. Request
contracts are revalidated at Orchestrator entry, and handlers receive stage-local request
copies so mutable nested data cannot alter the operation behind its content-bound ID.
Status/state/retryability/result-reference combinations are validated as a single
semantic contract rather than independent strings.

### 3. Finite state machine

A pipeline is a strict ordered subset of:

```text
received
→ planned
→ retrieved
→ generated
→ verified
→ proposed
→ completed
```

Terminal alternatives are:

```text
rejected | abstained | degraded | failed | cancelled
```

Pipelines begin at `planned`; stages cannot repeat or move backward. `generated`
requires a later `verified` stage, and `proposed` requires verification and must be the
last configured stage.

### 4. Immutable stage results

Handlers return a canonical `RuntimeStageResult`. The result store persists immutable
canonical semantic bytes rather than a caller-owned mutable object and returns a
content-bound `StageResultRef`. Reads reconstruct isolated copies. Public status and
response objects contain references only. A retry with the same operation, stage, and
input digest reuses the existing result without rerunning the handler. A different
semantic result for the same key is a deterministic failure.

### 5. Lease and fencing

Each stage claim binds operation, stage, attempt, delivery request, and input digest.
Only the active unexpired claim may commit. An expired or superseded claim cannot
publish. If a worker stored an immutable result and then lost its claim, the next worker
may adopt that result, so recovery does not duplicate provider work.

### 6. Cancellation and deadline precedence

Cancellation is content-bound and the first accepted signal is immutable. A signal
that predates operation creation is rejected, and a late cancellation cannot rewrite a
terminal operation. Handlers receive a cooperative checkpoint API and must check before
and after stage execution. Cancellation also wins when it races with transient or fatal
handler failure. Cancellation or absolute deadline expiry wins over an uncommitted
result; that result remains unreferenced.

### 7. Error semantics

- transient handler failure → `retry_later`, claim released, no terminal cache;
- lost/expired claim → `retry_later`, result may be adopted on retry;
- fatal or unhandled failure → terminal `failed`;
- unknown route or idempotency conflict → terminal `rejected` without creating or
  modifying an unrelated operation;
- completed, rejected, abstained, and degraded stage outcomes may expose only the
  final `StageResultRef`, never inline payload.

## Consequences

- Later Phase 4 engines can be replaced without changing operation semantics.
- Provider retries and process crashes do not create duplicate logical stages.
- Runtime status is safe to expose because it contains bounded metadata and hashes.
- The in-memory stores are reference implementations for conformance tests, not
  production persistence adapters.

## Limitations and deferred work

P4-01 does not implement intent/temporal resolution, retrieval, model calls,
verification, cost budgets, durable distributed leases, or external actions. Persistent
operation/result stores must preserve the same atomicity and fencing contracts in a
later deployment adapter. This ADR does not claim Phase 4 or Production completion.

## Rollback

P4-01 is additive. Reverting it removes the Runtime contracts, orchestrator, schema,
tests, and documents without modifying signed Phase 3 artifacts or Storage schemas.
