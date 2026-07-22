# ADR-0001: Phase 2 bootstrap checkpoint trust

- Status: Accepted for the disposable Phase 3 spike
- Date: 2026-07-22
- Scope: `P3-00`

## Context

Phase 3 may not start from prose claims such as “116 tests passed.” It needs a
machine-verifiable Phase 2 input. The baseline commit is
`026bc351020661cd91dc44b79e1d250d21e89a84` in
`whelp99-code/wiki-spike`.

## Decision

`artifacts/checkpoints/g2/` contains a canonical checkpoint manifest, detached
Ed25519 signature, public key, and canonical test evidence. The manifest binds:

- repository, commit and Git tree;
- raw `git ls-tree` digest and tracked-file count;
- regression minimum and test-evidence digest;
- signing domain and public-key fingerprint.

CI verifies that the baseline commit is an ancestor of the PR head, all digests
and the detached signature match, and the current regression suite is still at
least 116 tests.

## Trust limitation

The bootstrap public key and trust record enter the repository in the same
reviewed PR. Therefore the signature proves integrity and repeatability, not an
independent organizational identity. GitHub review history is the bootstrap
trust anchor. Production purpose-separated key management is deferred to
`P3-09`; this limitation must not be described as production release signing.

The private checkpoint key was generated outside the repository, used once,
and destroyed. Only the public key is committed.
