# ADR-0008: Complete Recovery Set and clean-room verification

- Status: Accepted for Phase 3 P3-10
- Date: 2026-07-22
- Scope: Recovery inventory, dry-run verification, restore orchestration, evidence

## Context

A Git clone or an SQLite copy is not a complete recovery. Logical truth is held by
signed Generation artifacts, while SQLite and projections are rebuildable
materializations. A usable disaster-recovery contract must also retain CAS objects,
Git reachability refs, historical verification keys, encrypted sidecars, registry
versions, and the control-plane checkpoint.

A recovery bundle is security-sensitive. If its manifest, historical key registry,
or target pointers can be substituted, a technically valid but stale or attacker-
selected state could be restored. Recovery therefore needs an out-of-band trust
anchor and content-bound inventory, not a self-asserted directory listing.

## Decision

### 1. Recovery Set inventory

`RecoveryManifest` content-binds every item by category, canonical relative path,
SHA-256 digest, byte length, encryption metadata, and dependency IDs. The minimum
set includes:

- CAS object;
- Git object and retention ref inventory;
- signed Generation and Release manifests;
- historical public-key registry;
- control-plane checkpoint;
- schema and kind registry snapshots.

Tombstones, export manifests, policy registries, and encrypted secret sidecars are
included when present. A listed item is mandatory; missing or corrupt bytes fail
closed.

### 2. Independent trust anchor

The Recovery Manifest is Ed25519-signed in the purpose/domain frame
`recovery_manifest / wiki.recovery.manifest.v1`. `RecoveryTrustAnchor` is supplied
separately and pins:

- workspace;
- recovery signer public key and key ID;
- expected manifest ID;
- expected historical-key registry snapshot digest.

The key registry inside the bundle cannot establish its own trust.

### 3. Historical signature verification

The historical public-key snapshot is canonical and content-bound. Generation,
Release, and Export items require explicit `RecoverySignatureBinding` records and
are verified against purpose, domain, validity time, and retained public keys.
Private signing keys are not part of the Recovery Set.

### 4. Restore workflow

The coordinator performs:

```text
write freeze
→ re-read and pin signed manifest
→ verify complete inventory and signatures
→ stage exact verified bytes
→ restore authoritative state root
→ rebuild control plane and projections
→ verify publication/release/checkpoint/projection pointers
→ execute strict sample queries
→ commit restore
→ write minimized RecoveryEvidence
→ release freeze
```

Any failure aborts the staging session. The target adapter owns its atomic staging
and commit semantics; Core never writes Git, SQLite, CAS, or projection engines
directly.

### 5. Dry-run CLI

`scripts/p3_10_recovery_dry_run.py` verifies a filesystem bundle without acquiring
a write freeze or mutating a target. The trust anchor is a separate input. Output
contains only IDs, digests, counts, pointers, and status—never item payloads,
secret sidecars, prompts, tokens, or private keys.

### 6. Completion semantics

Restore success requires all of the following:

- trusted manifest signature;
- full item and dependency verification;
- historical artifact signatures;
- authoritative state-root match;
- control-plane checkpoint match;
- publication and Release pointer match;
- required `identity` and `chronology` projection pointers;
- strict sample-query result digests.

Clone success alone is not recovery success.

## Consequences

- Recovery manifests and trust anchors become versioned operational artifacts.
- Optional projections are rebuilt; they are not accepted as authoritative backup
  state.
- Recovery can be exercised with in-memory or production adapters using the same
  Core protocols.
- A freeze-release failure after commit is reported explicitly rather than hidden.

## Limitations and deferred work

P3-10 defines Core contracts and a filesystem dry-run adapter. It does not provide:

- production object-store, Git-provider, SQLite, or KMS restore adapters;
- secret-sidecar decryption-key escrow or rotation ceremony;
- multi-node consensus or automatic failover;
- measured production RPO/RTO;
- continuous backup scheduling.

Those require deployment-specific adapters and operational drills. P3-10 must not
be described as production disaster-recovery readiness by itself.

## Rollback

The change is additive. Reverting the P3-10 PR removes the Recovery Core module,
script, schema, tests, and documents without changing existing Storage schemas or
published Generation artifacts.
