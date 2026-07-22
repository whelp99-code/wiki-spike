# ADR-0005 — Operational events are non-authoritative, monotonic notifications

## Status
Accepted for P3-07.

## Context
Commands, AcceptedChangeSets, signed Generations, and operational notifications have
different meanings. Reusing an event log as logical state would create a second truth
source; treating delivery as exactly-once would hide crash windows and duplicate risk.

## Decision
1. Only signed Generation artifacts are authoritative logical state.
2. `OperationalEvent` contains minimal metadata plus an optional `payload_ref`; memory
   body content is not embedded in the event envelope.
3. Event identity is the SHA-256 of its canonical immutable fields.
4. Every event carries workspace, generation, parent generation, and a canonical
   monotonic generation sequence.
5. Consumers deduplicate by `(workspace_id, consumer_id, event_id)`.
6. Consumers reject sequence gaps and parent-chain mismatches without advancing their
   checkpoint.
7. A handler prepares a deterministic `ConsumerEffect`; the consumer store commits
   effect, dedupe marker, and checkpoint atomically.
8. A poison event is retried within a bounded attempt budget, then dead-lettered and
   checkpointed. This is safe because the event is rebuildable from signed state.
9. Replay resumes strictly after the consumer checkpoint and stops at the first gap.
10. Checkpoints and dedupe state are workspace-scoped.

## Consequences
- Delivery semantics are at-least-once with deterministic dedupe.
- Event consumers can be rebuilt or replayed without becoming truth sources.
- External side effects require their own idempotent gateway in a later phase.
- Dead letters are operational evidence and must retain event references, not private
  memory payloads.
