# P3-00 Conformance Report

## Scope

This PR implements only the Phase 3 preflight boundary:

- signed/canonical Phase 2 storage checkpoint verification;
- architecture AST boundary lint;
- offline tracked/untracked secret scan;
- warnings-as-errors regression gate;
- wheel build/install/console smoke;
- GitHub Actions evidence upload.

It does **not** implement Phase 3 Core contracts, gateways, policies, projections,
plugins, recovery, or G3.

## Requirement mapping

| Requirement | Evidence | Status |
|---|---|---|
| P3-F-019 Boundary lint | `architecture-boundaries.json`, AST linter, negative fixtures | PASS |
| P3-F-020 machine evidence foundation | G2 checkpoint, CI workflow, evidence writer | PASS for P3-00 scope |
| G2 input | checkpoint `8eeb54bfe307ced8b3ce77bc642d2beea560441129e09a78dbc4d5f659dd012a` | PASS |
| Existing regression | 116 baseline + P3-00 adversarial tests | PASS locally |
| Required GitHub check | `phase3-preflight / P3-00 preflight` | PASS — required on `main` with strict up-to-date checks |

## Security and privacy

No private signing key is committed. The checkpoint contains only a public key,
manifest, detached signature and minimized command evidence. CI evidence stores
hashes and counts, not source contents, prompts, tokens or user memory data.

## Rollback

P3-00 is additive. Reverting the PR removes `.github/workflows`, preflight
scripts, checkpoint artifacts, tests and documentation without changing the
existing storage schema or publication path.

## Completion semantics

Code-complete means all local gates and PR CI pass. Merge-ready additionally
requires confirmation that `main` requires the named status check. This PR does
not create G3 and does not authorize P4 work.
