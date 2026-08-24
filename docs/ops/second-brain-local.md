# Local second-brain operations

Verified `LOCAL / UNCERTIFIED` surface only. This page does not publish a
certified product or authorize destructive work. Certified work stays on a
separate workspace and a later acceptance driver.

Install the wheel into a disposable venv, then invoke the absolute
`bin/wiki` and `bin/wiki-mcp` entry points. The workspace base root must be
mode `0700`. Recovery must live on `/Volumes/DevSpace` so it is a different
device from `~/Library/Keychains`. Owner and workspace refs are
`owner:<64hex>` and `workspace:<64hex>`.

## Installed CLI

```text
bin/wiki --root "$WORKSPACE" --mode local --recovery-root "$RECOVERY" \
  init --bootstrap-owner-ref "$OWNER_REF" --workspace-ref "$WORKSPACE_REF"

bin/wiki --root "$WORKSPACE" --mode local --recovery-root "$RECOVERY" \
  --owner-ref "$OWNER_REF" remember --content-type markdown --idempotency-ref "$IDEM"

bin/wiki --root "$WORKSPACE" --mode local --recovery-root "$RECOVERY" \
  --owner-ref "$OWNER_REF" inbox --limit 20

bin/wiki --root "$WORKSPACE" --mode local --recovery-root "$RECOVERY" \
  --owner-ref "$OWNER_REF" approve --candidate "$CANDIDATE" \
  --expected-revision "$REVISION" --expected-cut 1

bin/wiki --root "$WORKSPACE" --mode local --recovery-root "$RECOVERY" \
  --owner-ref "$OWNER_REF" recall --as-of-cut 2

bin/wiki --root "$WORKSPACE" --mode local --recovery-root "$RECOVERY" \
  --owner-ref "$OWNER_REF" forget --candidate "$CANDIDATE" \
  --expected-revision "$REVISION" --expected-cut 2

bin/wiki --root "$WORKSPACE" --mode local --recovery-root "$RECOVERY" \
  --owner-ref "$OWNER_REF" status --detail summary
```

`status` reports mode `LOCAL`. The workspace remains `LOCAL / UNCERTIFIED`.

## Installed MCP

```text
bin/wiki-mcp --root "$WORKSPACE" --mode local --owner-ref "$OWNER_REF" \
  --recovery-root "$RECOVERY"
```

Negotiate `2026-07-28` with `server/discover` and `2025-11-25` with
`initialize` / `initialized`. Tools for the local journey are
`second_brain.init`, `second_brain.remember`, `second_brain.inbox`,
`second_brain.review`, `second_brain.recall`, and `second_brain.forget`.

## Acceptance driver

```text
tmp="$(mktemp -d)"
uv run python scripts/second_brain_acceptance.py local \
  --workspace-root "$tmp/workspace" \
  --fixture-root tests/fixtures/second-brain/acceptance \
  --evidence-out .omo/evidence/wiki-spike-complete-second-brain/task-53/local-acceptance.json \
  --expect-mode LOCAL \
  --mcp-protocol 2026-07-28 \
  --mcp-protocol 2025-11-25
```

The driver builds the wheel, installs it into a fresh venv, runs
init → remember → inbox → review → recall → forget on CLI and both MCP
revisions, writes the body-free receipt, and removes Keychain items,
workspaces, and venvs.
