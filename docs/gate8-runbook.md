# Gate 8 Runbook — Conformance, Canary, and Review

Gate 8 ("Conformance, canary, and review") closes the Encrypted Single-Memory
Lifecycle. It is deliberately split into **machine evidence** (produced by CI on
self-hosted runners) and **review evidence** (produced by the independent
ARCHITECT/CRITIC review over that machine evidence). No single artifact claims a
delivery verdict on its own; the verdict-free manifest is signed by two
independent reviewers, and a separate receipt records the outcome.

## macOS 26 platform cutover

The owner superseded the historical Darwin 24/macOS 15 platform pin with the
Darwin 25/macOS 26 contract below. Historical plans remain immutable audit
records, but commit `2fe371311e6290b60b8b5634af8cf14b97f0452c` and runs
`30188838986`, `30188869214`, `30188878973`, and `30188879689` are obsolete
under this contract. They MUST NOT be relabeled, imported, or joined.

After publishing a migration commit, always produce a completely fresh evidence
sequence:

1. dispatch fresh Ubuntu `SQLCIPHER_FEASIBILITY`;
2. use its exact tuple to dispatch fresh macOS 26 `GATE1_DECISION`;
3. dispatch fresh macOS 26 `CONFORMANCE_PRE_CANARY` and exact-24-hour
   `CANARY_24H` at the migration implementation commit;
4. strictly join only those new three lane tuples;
5. obtain fresh independent ARCHITECT/CRITIC signatures and import the final
   receipt.

Changing the platform enum changes the contract digest, so even the earlier
successful Ubuntu feasibility artifact cannot seed the migrated Gate 1 lane.

## Lanes and immutable tuples

| Lane | Artifact kind | Workflow | Commit binding |
|---|---|---|---|
| gate1 | `GATE1_DECISION` | `encrypted-lifecycle-gate1-decision.yml` | `gate1_commit` |
| conformance | `CONFORMANCE_PRE_CANARY` | `encrypted-lifecycle-conformance.yml` | `implementation_commit` |
| canary | `CANARY_24H` | `encrypted-lifecycle-canary.yml` | `implementation_commit` |

Gate 1 MAY use a different commit. Conformance and canary MUST use the same
immutable `implementation_commit`. Gate 1, conformance, and canary run only on
their dedicated self-hosted `arm64` runners with Darwin kernel major `25` and
`sw_vers -productVersion` matching `26.*`; their platform identities are,
respectively, `self-hosted/macos-26/arm64/wiki-gate1-workstation`,
`self-hosted/macos-26/arm64/wiki-conformance-workstation`, and
`self-hosted/macos-26/arm64/wiki-canary-workstation`. Record the complete tuple
for each lane: repository, run ID, run attempt, exact artifact name, bundle
SHA-256, source-run URL, platform, producer commit, contract digest,
toolchain-lock digest, and workflow-file digest.

## 1. Produce conformance evidence

Run `scripts/run_encrypted_lifecycle_conformance.py` from the checked-out
`implementation_commit`, with the complete conformance tuple. Its immutable
bundle is the conformance lane input to the join.

## 2. Run or resume the durable canary

Dispatch `encrypted-lifecycle-canary.yml` at `implementation_commit`. The
canary service owns its durable root at the absolute private path supplied by
`CANARY_DURABLE_STATE_ROOT`; it is not a GitHub artifact and no resume artifact
input exists.

A GitHub rerun of the same original workflow run ID (a changed attempt) resumes
only that run's checkpoint chain. The service derives the chain path from
repository, implementation commit, and the original run ID, so it never scans
or reuses another run for the same commit. An incomplete checkpoint resumes;
a stale checkpoint or a failed terminal checkpoint requires a fresh workflow dispatch
with a new run ID. A terminal-issued checkpoint is terminal: its evidence cannot be
replayed, relabeled, or issued again. Historical runs do not block a fresh workflow
dispatch. A healthy terminal run produces the `CANARY_24H` bundle after the configured
24-hour duration.

## 3. Strict three-lane join

Dispatch `encrypted-lifecycle-evidence-join.yml` with all three complete lane
tuples, `gate1_commit`, shared `implementation_commit`, `contract_digest`,
`toolchain_lock_digest`, and `workspace_id`. It downloads each exact named
artifact separately and strictly imports it. The join rejects missing,
substituted, extra, or mismatched artifacts and emits the verdict-free
`pre-review-manifest.json` and `evidence-join.json`.

## 4. Issue, write, and strictly import the final receipt

The final receipt freezes a path-sorted `{path: sha256}` inventory derived from
the complete strict-import receipts. It is canonical JSON and is rejected when
a path is omitted, substituted, duplicated/aliased, extra, noncanonical, or
has the wrong digest. Both the pre-review manifest and evidence join must
contain identical strict receipts.

```python
from wiki_spike.infrastructure.conformance import (
    ARCHITECT, CRITIC, attest_manifest, write_final_review_receipt,
    import_final_review_receipt,
)

arch = attest_manifest(
    reviewer_role=ARCHITECT, reviewer_key_id="arch-key", private_key=arch_sk,
    workspace_id=workspace_id, implementation_commit=implementation_commit,
    manifest_digest=manifest.manifest_digest, issued_at=issued_at, expires_at=expires_at,
)
critic = attest_manifest(
    reviewer_role=CRITIC, reviewer_key_id="critic-key", private_key=critic_sk,
    workspace_id=workspace_id, implementation_commit=implementation_commit,
    manifest_digest=manifest.manifest_digest, issued_at=issued_at, expires_at=expires_at,
)
receipt = write_final_review_receipt(
    workspace_id=workspace_id, implementation_commit=implementation_commit,
    manifest=manifest, evidence_join=evidence_join, attestations=(arch, critic),
    trusted_reviewers=trusted_reviewers, now=now,
)
import_final_review_receipt(
    receipt, trusted_reviewers=trusted_reviewers, workspace_id=workspace_id,
    implementation_commit=implementation_commit, manifest=manifest,
    evidence_join=evidence_join, now=now,
)
```

`trusted_reviewers` maps each role to its current `(key_id, public_key)`.
`issued_at`, `expires_at`, and `now` are canonical UTC timestamps; attestations
must be issued no later than `now`, unexpired, and no longer than one hour.
ARCHITECT and CRITIC roles and key IDs must be distinct.

## 5. External execution

Push the implementation commit, dispatch Gate 1, conformance, and the durable
canary on their designated self-hosted runners, then dispatch the evidence
join with the recorded tuples. Obtain independent reviewer signatures, write
the final receipt, and strictly import it using the APIs above. These
runner, GitHub artifact, and signing operations are intentionally external to
local preparation.
