# P4-04 Conformance Report — Generation-aware Retrieval Broker

## Scope

- Implementation: `retrieval.py`
- Decision: exact-first retrieval, authoritative post-filter, optional-channel degradation
- Boundary: Runtime only; no Storage, connector, UI, credential, or external action execution.

## Acceptance

- strict versioned/content-bound contracts: PASS
- deterministic/idempotent behavior: PASS
- sensitivity/provenance/expiry enforcement: PASS
- failure/degrade behavior: PASS
- adversarial rounds: 20/20

## Completion semantics

This report is subordinate to the P4-14 G4 gate. `P4-04` is accepted only when the full regression, architecture/runtime boundary, secret scan, package smoke, and signed G4 checkpoint verifier all pass.
