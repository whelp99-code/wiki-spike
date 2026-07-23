# P4-08 Conformance Report — Decision Candidate Engine

## Scope

- Implementation: `decision.py`
- Decision: exact source span, decision status taxonomy, hedge preservation
- Boundary: Runtime only; no Storage, connector, UI, credential, or external action execution.

## Acceptance

- strict versioned/content-bound contracts: PASS
- deterministic/idempotent behavior: PASS
- sensitivity/provenance/expiry enforcement: PASS
- failure/degrade behavior: PASS
- adversarial rounds: 20/20

## Completion semantics

This report is subordinate to the P4-14 G4 gate. `P4-08` is accepted only when the full regression, architecture/runtime boundary, secret scan, package smoke, and signed G4 checkpoint verifier all pass.
