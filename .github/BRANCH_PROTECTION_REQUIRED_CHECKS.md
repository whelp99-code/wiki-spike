# Required branch-protection checks

## Current product check

The current pull-request gate is:

```text
phase3-preflight / P3-00 preflight
```

The legacy workflow/job name is retained because GitHub branch protection already
expects it. The implementation runs `scripts/run_operational_gate.sh` and proves the
current Wiki Memory product path:

```text
Wiki Memory.app / support CLI / read-only AI tools
→ composition/local_second_brain.py
→ existing Encrypted Lifecycle / Second Brain Core
```

It does **not** relabel Phase 3 evidence as current product evidence.

The current gate checks:

- operational and architecture boundaries;
- absence of a parallel memory database or fallback path;
- general-user lifecycle tests;
- existing Gate 3/4/5/7 core slices used by the app;
- existing authenticated V2 CLI and compatibility isolation;
- one secret scan;
- one installed-wheel lifecycle including backup/restore and read-only AI recall.

## Historical release-audit workflows

The following workflows are manual `workflow_dispatch` audits and must not be
configured as required pull-request checks because they do not run on pull requests:

```text
phase3-g3-conformance / G3 conformance checkpoint
phase4-preflight / P4-00 contract pin
phase4-g4-conformance / G4 conformance checkpoint
```

They preserve and verify their own historical/release semantics. They must not be
copied, renamed, or presented as evidence that the current Wiki Memory product passed.

## Recommended GitHub settings

- require a pull request before merging;
- require `phase3-preflight / P3-00 preflight`;
- require the branch to be up to date;
- dismiss stale approvals on new commits;
- require conversation resolution;
- block force pushes and branch deletion.

Branch-protection configuration is external GitHub state. Repository code can prove
what a check does, but an administrator must still confirm which check GitHub actually
requires.
