# ADR-0009: Privacy-preserving operability and bounded work

- Status: Accepted for Phase 3 P3-11
- Date: 2026-07-22
- Scope: audit references, telemetry degradation, backpressure, export requests

## Decision

1. Audit records contain HMAC-SHA256 references and bounded codes only. They have no
   body, prompt, response, token, credential, or free-form message field.
2. Telemetry contains aggregate buckets/counts only. On sink failure a minimal local
   audit is mandatory; double failure is explicit.
3. Queue length, queued cost, per-workspace items, retry operation count, attempts,
   cumulative cost, deadlines, and half-open probes are all bounded.
4. Export requests are policy checked and converted to deterministic projection jobs.
   Core stores only a digest `delivery_intent_ref` and has no external destination
   writer/client. Target classes enforce sensitivity ceilings.
5. If a newly queued export job cannot be audited, it is cancelled.

## Consequences

Overload and observability failure have deterministic outcomes. Logs do not become a
shadow copy of private memory, and external delivery remains a Phase 5 responsibility.

## Limitations

Durable audit persistence, HMAC-key rotation, distributed queue consensus, and actual
export delivery are deployment/application concerns and are not claimed by P3-11.
