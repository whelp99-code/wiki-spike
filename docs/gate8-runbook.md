# Gate 8 Runbook — Conformance, Canary, and Review

Gate 8 ("Conformance, canary, and review") closes the Encrypted Single-Memory
Lifecycle. It is deliberately split into **machine evidence** (produced by CI on
self-hosted runners) and **review evidence** (produced by the independent
ARCHITECT/CRITIC review over that machine evidence). No single artifact claims a
delivery verdict on its own; the verdict-free manifest is signed by two
independent reviewers, and a separate receipt records the outcome.

## Lanes and producers

| Lane | Artifact kind | Producer | Workflow |
|---|---|---|---|
| gate1 | `GATE1_DECISION` | Gate 1 decision writer | (Gate 1) |
| conformance | `CONFORMANCE_PRE_CANARY` | `scripts/run_encrypted_lifecycle_conformance.py` | same-commit conformance run |
| canary | `CANARY_24H` | `scripts/run_encrypted_lifecycle_canary_24h.py` | `encrypted-lifecycle-canary-24h.yml` |

All three lanes MUST be bound to the **same `producer_commit`** (the immutable
commit under review). The join fails closed on any producer_commit mismatch.

## 1. Same-commit conformance run

Runs the full conformance surface at the implementation commit and wraps the
report into an immutable `CONFORMANCE_PRE_CANARY` bundle:

```bash
python3 scripts/run_encrypted_lifecycle_conformance.py \
  --output-dir artifacts/encrypted-lifecycle/conformance \
  --bundle-output-dir artifacts/encrypted-lifecycle/conformance \
  --workflow-run-id "$RUN_ID" --workflow-run-attempt "$RUN_ATTEMPT" \
  --platform "self-hosted/macos-15/arm64/wiki-conformance-workstation" \
  --contract-digest "$CONTRACT_DIGEST" \
  --toolchain-lock-digest "$TOOLCHAIN_LOCK_DIGEST" \
  --workflow-file-digest "$WORKFLOW_FILE_DIGEST"
```

The run is fail-closed: it executes the encrypted-lifecycle test suite, the
architecture-boundary check, the independent vector validator, the recall corpus
evaluation (Top-3 ≥ 0.80, zero forbidden returns), and the extraction corpus
evaluation (zero forbidden returns). Any failing surface marks the run
non-conformant, exits non-zero, and refuses to emit a bundle. It never
fabricates a green result.

## 2. Exactly-24-hour canary (self-hosted macOS)

Trigger `encrypted-lifecycle-canary-24h.yml` (workflow_dispatch) against the
immutable commit. It runs the canary on a self-hosted macOS 15 / arm64 runner
for exactly 24 hours (default `duration_seconds=86400`, probing every 15
minutes), exercising a full remember → decrypt → forget/veto round-trip on a
fresh disposable workspace each probe, then wraps the report into an immutable
`CANARY_24H` bundle. A single failed probe marks the canary unhealthy and the
job fails closed (no bundle is emitted by an unhealthy run).

Local short-canary smoke test (no 24h wait):

```bash
python3 scripts/run_encrypted_lifecycle_canary_24h.py --duration-seconds 0 --interval-seconds 0 --output-dir /tmp/canary
```

## 3. Three-lane evidence join (verdict-free)

Once all three immutable bundles exist, trigger
`encrypted-lifecycle-conformance.yml` (workflow_dispatch) with the three
producing run IDs. It downloads and **strictly imports** each bundle
(`scripts/import_encrypted_lifecycle_bundle.py` — re-implemented from scratch,
never trusting the builder), requires a single producer_commit across lanes, and
runs `scripts/join_gate8_evidence.py` to emit:

- `pre-review-manifest.json` — the **verdict-free** enumeration of the three
  imported bundles bound to the implementation commit (no pass/fail field).
- `evidence-join.json` — preserves the three independent import receipts
  verbatim under one digest.

The join is not a delivery gate and emits no verdict. A missing input, a failed
strict import, or a producer_commit mismatch is a hard failure (no false-green).

## 4. Independent review (two attestations + separate receipt)

Over the emitted `manifest_digest`, the ARCHITECT and CRITIC each independently
sign an attestation, and a separate receipt records the reviewed outcome
(`wiki_spike.infrastructure.conformance`):

```python
from wiki_spike.infrastructure.conformance import (
    ARCHITECT, CRITIC,
    attest_manifest, build_review_receipt, verify_review_receipt,
)

arch = attest_manifest(role=ARCHITECT, key_id="arch-key", private_key=arch_sk, manifest_digest=manifest_digest)
critic = attest_manifest(role=CRITIC, key_id="critic-key", private_key=critic_sk, manifest_digest=manifest_digest)
receipt = build_review_receipt(workspace_id=ws, manifest_digest=manifest_digest, attestations=(arch, critic))
verify_review_receipt(receipt, {ARCHITECT: arch_pk, CRITIC: critic_pk}, manifest_digest)
```

The receipt is valid only when both required roles are present, distinct, bound
to the manifest digest, and verify under their role public keys. Attestations
are domain-separated (R10-2), so a signature is valid only for its exact
role/key/manifest digest.

## What is NOT automated here

- The 24-hour canary requires a real 24h window on a self-hosted macOS runner.
- The ARCHITECT/CRITIC attestations and the separate review receipt are produced
  by the review process (human/agent reviewers holding independent keys); the
  machinery builds and verifies them but never fabricates a verdict or a
  signature.
