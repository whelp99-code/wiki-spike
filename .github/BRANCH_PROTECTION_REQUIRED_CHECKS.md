# Required branch-protection check

The repository administrator must configure `main` to require this status check:

```text
phase3-preflight / P3-00 preflight
```

Recommended additional settings:

- require a pull request before merging;
- require the branch to be up to date;
- dismiss stale approvals on new commits;
- block force pushes and branch deletion;
- require conversation resolution.

The workflow is committed by P3-00, but repository branch-protection settings
are external control-plane state and cannot be proven by repository code alone.
Until that setting is confirmed, P3-00 is code-complete but its merge-policy
gate remains operationally conditional.
