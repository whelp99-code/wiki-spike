# Required branch-protection checks

## Phase 3 baseline checks

```text
phase3-preflight / P3-00 preflight
phase3-g3-conformance / G3 conformance checkpoint
```

The G3 check verifies the immutable annotated tag `phase3-core-v1.0.0` at
`fa7523344008c8c5bfbcc6aca790f297524f33dc`; it does not reinterpret the evolving
Phase 4 checkout as Phase 3 source.

## Phase 4 checks

Starting with P4-00, `main` should additionally require:

```text
phase4-preflight / P4-00 contract pin
```

Recommended additional settings:

- require a pull request before merging;
- require the branch to be up to date;
- dismiss stale approvals on new commits;
- block force pushes and branch deletion;
- require conversation resolution.

Repository branch-protection settings are external control-plane state and cannot
be proven by repository code alone. CI evidence establishes that a check ran; an
administrator must still confirm that GitHub requires it before merge.
