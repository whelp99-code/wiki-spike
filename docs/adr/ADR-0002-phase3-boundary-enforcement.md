# ADR-0002: AST-enforced architecture boundaries

- Status: Accepted
- Date: 2026-07-22
- Scope: `P3-00`

## Decision

Phase 3 starts additively. Existing storage modules remain in place. New Core,
Runtime and Application packages are classified by path in
`architecture-boundaries.json`; `scripts/check_architecture_boundaries.py`
parses Python ASTs and rejects both static and constant-string dynamic imports
that cross a forbidden boundary.

The initial load-bearing rule is that Runtime/Application code cannot directly
import CAS, SQLite control-plane, Git plumbing, generation, publication,
signing, or Workspace implementations. They must eventually use versioned Core
ports. Storage cannot import higher layers, Core cannot import Runtime or
Application, and Runtime cannot import Application.

Comments and ordinary strings are not treated as imports. Relative imports and
constant `importlib.import_module`/`__import__` calls are resolved and checked.
Syntax errors and symlinked Python source fail closed.
