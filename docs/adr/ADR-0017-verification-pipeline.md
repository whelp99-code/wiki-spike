# ADR-0017: Layered Verification Pipeline

- Status: Accepted for P4-06
- Date: 2026-07-23
- Scope: `verification.py`

## Context

Phase 4 Runtime must remain deterministic at orchestration and policy boundaries even when retrieval or model components are probabilistic. Layered Verification Pipeline is isolated from Storage, credentials, connectors, UI, and external action execution.

## Decision

Implement Layer D/P/Policy separation, abstention, modality non-escalation. All public objects are versioned, canonical, content-bound, and workspace/generation aware. Unknown data fails closed. Source or model bodies stay behind references except where a user-facing answer contract explicitly needs presentation text.

## Security and privacy

No provider credential, mutable client, direct Storage handle, prompt body, or source body is stored in operational metadata. Sensitivity cannot be lowered implicitly. Optional dependency failure degrades or abstains without changing authoritative Core state.

## Consequences

The component can be independently replaced and tested. Its output is safe to pass to the next Runtime stage because identity, provenance references, generation, modality, expiry, and omission semantics are explicit.

## Limitations

This is the first provider-neutral contract implementation. It does not claim production scale, distributed persistence, real model quality, external connector readiness, or autonomous action permission.

## Rollback

The change is additive. Reverting P4-06 removes its module, tests, schema/document evidence, and leaves prior Runtime and signed Phase 3 artifacts unchanged.
