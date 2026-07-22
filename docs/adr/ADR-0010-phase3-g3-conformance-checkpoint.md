# ADR-0010: Phase 3 G3 conformance checkpoint

- Status: Accepted for P3-12
- Date: 2026-07-22
- Contract release: `phase3-core-v1.0.0`

## Context

Phase 3 cannot be completed by prose, file presence, or a green test count alone. The
Core boundary contains twenty independent requirements, historical cryptographic
contracts, a recovery drill, and operational privacy limits. A final gate must bind
what was reviewed to the exact source, schemas, tests, ADRs, and closed set of CI
commands that established conformance.

A checkpoint stored inside the same commit cannot hash that commit without becoming
self-referential. Dynamic CI logs also contain nondeterministic paths and timing and
must not become logical truth.

## Decision

G3 uses four distinct artifacts:

1. `requirements.json` maps exactly `P3-F-001` through `P3-F-020` to implementation,
   test, evidence, and closed-catalog gate IDs.
2. `phase3-source-inventory.json` content-binds Phase 3 source, tests, schemas, ADRs,
   adversarial reports, CI and scripts. G3 checkpoint files and dynamic run evidence
   are excluded to avoid self-reference.
3. `phase3-g3-checkpoint.json` binds the source root, requirements matrix, public API,
   G2 checkpoint, ADR registry, required gates, test-count floors, contract release,
   lineage anchor, and Ed25519 verification key fingerprint.
4. CI produces per-commit G3 evidence containing gate names, status, counts, and log
   hashes. Evidence does not contain memory bodies, prompts, credentials, or keys.

The checkpoint is signed in the dedicated domain `wiki.phase3.checkpoint.v1`. The
bootstrap trust record pins the checkpoint ID, source root, release, repository, and
public-key fingerprint. As with G2, same-PR bootstrap trust proves integrity and
repeatability, not independent organizational identity.

The gate command catalog is code-owned. The matrix may reference only known gate IDs
and cannot inject shell commands. A committed negative fixture removes a required
gate and must cause validation failure.

## Completion semantics

`phase3-core-v1.0.0` is eligible only when both repository checks pass:

- `phase3-preflight / P3-00 preflight`
- `phase3-g3-conformance / G3 conformance checkpoint`

After the P3-12 merge, the merge commit may be tagged `phase3-core-v1.0.0` only after
re-running the checkpoint verifier on that exact commit. The tag is a release marker;
the signed G3 checkpoint remains the machine-verifiable contract identity.

## Consequences

- Changes to any bound Phase 3 file invalidate the checkpoint and require a new
  contract release/checkpoint.
- Phase 4 pins the G3 checkpoint ID and source root, not a floating branch.
- Dynamic CI evidence is operational proof, not a second logical truth source.
- P3-12 adds no Runtime, Application, connector, or model behavior.

## Rollback

Before tagging, revert P3-12. After tagging, do not move the tag or rewrite the G3
checkpoint; issue a new contract version and checkpoint.
