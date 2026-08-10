# Withdrawn decision records

A record here is cryptographically valid but was withdrawn because its evidence
does not meet the governing decision spec. Its scope is therefore
**UNRESOLVED**, which the specs define as excluded and disabled.

This directory is a curation convention, not an enforcement mechanism. No code
discovers decision records by scanning a directory: `resolve_second_brain_contract`
(`src/wiki_spike/memory_core/second_brain_contracts.py`) takes an explicit
`Sequence[DecisionRecordV1]` and performs no filesystem I/O, and
`scripts/second_brain_decision.py verify` takes an explicit `--record` path. A
record is excluded because whoever assembles the decision sequence stops naming
it; moving it here records that intent where a reader will find it.

What actually fails closed is the contract's exact-match rule: enabled scopes
must equal the GO set and disabled scopes the NO_GO set, so a migration source
cannot enter `enabled_migration_sources` without a matching GO record in the
passed sequence. Withdrawal removes the only record that could have authorized
`unified-db`.

Nothing here is deleted, and nothing here is mutated.

## DB-03-unified-db.json

- Withdrawn: 2026-08-06
- Signed outcome: `GO`, `migration_source` / `unified-db`, record revision 1
- Signatures: valid — `verify` exits 0 with `signatures_verified: true`
- `expires_at`: 2026-08-20T00:00:00Z

Withdrawn because the GO is unsupportable under
`docs/product/decisions/DB-03-migration-sources.md`, which makes five items
mandatory preconditions for a source-specific GO. Two are unmet:

1. a read-only export fixture that cannot mutate the source — absent
4. deletion and history samples distinguishing tombstones, retained history,
   and unavailable history without inference — absent

The spec routes missing or partial material to **UNRESOLVED, not NO_GO**, and
defines no partial-GO tier. The record's own `reason` concedes the gap
("Evidence is partial"), and its bound evidence
(`../unified-db-inventory-v1.json`) records
`historyAvailability: incomplete-without-source-specific-export-proof` and
`defaultDecision: STOP_PENDING_IMMUTABLE_SNAPSHOT_AND_DIFF`. Because the caveat
lived only in free-text fields, any consumer checking `outcome == "GO"` would
have read an unqualified authorization. Requirements 2, 3 and 5 were not
re-assessed; two unmet preconditions already settle the outcome.

### Consequence for the product contract

`ExpectedScopeManifestV1` requires a DB-03 entry for every migration source —
`legacy Mem0/RAG`, `me-wiki`, and `unified-db`. With this record withdrawn,
full contract resolution cannot succeed for DB-03 `unified-db` until that scope
is decided again: `resolve_second_brain_contract` raises `InvalidContractValue`
on the expected-scope-manifest mismatch. It does not return the `BLOCKED`
outcome, which is reserved for a global-scope `NO_GO`. That is the intended
meaning of UNRESOLVED, not a regression.

### Restoring it

`mv` back into `../decisions/` and re-add it to the caller's decision sequence.
Two caveats:

- The restore window ends at `expires_at` 2026-08-20T00:00:00Z. After that,
  `DecisionRecordV1.from_mapping(now=...)` — and therefore
  `resolve_second_brain_contract`, which always passes `now` — rejects the
  record with `decision is expired`. Bare `from_mapping()` with the default
  `now=None` skips the expiry gate entirely.
- `verify` takes no `now=`, so it keeps reporting `signatures_verified: true`
  even after expiry. Signature validity is not usability.

Past that window, re-issuing requires the evidence the inventory itself names as
next required — an owner-produced immutable snapshot taken after writers are
quiesced, a zero-write proof, a body-free per-source uniqueness diff, and
source-specific deletion/history treatment — bound by a fresh `evidence_digest`.

### Audit note

`../../../conformance/second-brain/db-decision-signing-red-team-v1.json` records
a `verify` run against this record at its pre-withdrawal path,
`../decisions/DB-03-unified-db.json`. That transcript is a point-in-time
execution record and is deliberately left unmodified; the path was correct when
it ran. Replaying it now yields a missing file because of this withdrawal, not
because of tampering.
Its sibling `db-decision-signing-red-team-v2.json` re-runs the suite against the
post-withdrawal state and supersedes it for current-state questions; v1 is
retained as the pre-withdrawal record.
