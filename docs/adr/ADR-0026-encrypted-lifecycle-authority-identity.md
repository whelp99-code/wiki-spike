# ADR-0026: Encrypted lifecycle fact authority and canonical identity contract

- Status: Accepted (Gate 1)
- Date: 2026-07-24
- Scope: Encrypted Single-Memory Lifecycle — fact authority matrix, canonical identity/HMAC contract, KDF labels, signature-input construction, nonce typing, ARK granularity, command/manifest/junction cardinality, envelope identity, bundle self-field projection
- Binding plan artifacts (path + sha256):
  - `.gjc/_session-019f8ebe-012e-7000-b140-8e9aced136fc/plans/ralplan/019f8ebe-012e-7000-b140-8e9aced136fc/stage-08-revision.md` — `ef4ff3b275356e5c9754550c9cbfb04a65ffc6668204f3e9fa0578479146048d`
  - `stage-09-revision.md` (same directory) — `284cbe71af0519c79b21f7dda8cdd145a3a5366193f30540f3d54866a923a1f3`
  - `stage-10-revision.md` (same directory) — `2fe01ee1…` (Revision 10, supersession authoritative over Stage 8/9 wording)
- Companion ADR: ADR-0027 (recovery/deletion). This ADR owns authority and identity only; it does not restate recovery, deletion, or floor-protocol normative text beyond what identity depends on.

## Context

The encrypted-lifecycle workspace persists mutable plaintext-adjacent state in SQLite, immutable ciphertext/signed artifacts in CAS/Git, and a separately signed binding registry. These three stores can disagree during crash, replay, or partial commit. Every identity, signature, and derived key in the system must be independently reproducible by an external verifier without changing the frozen Phase 3 Core, which rejects raw JSON numeric tokens (`src/wiki_spike/memory_core/contracts.py::canonical_bytes` → `_normalize` raises `InvalidContractValue` on `int`/`float`; see lines 27-28). All wire numerics in this ADR are therefore canonical decimal strings validated against closed regexes, never JSON numbers.

Revision 9 added exact freshness/proof wire closure; Revision 10 struck one Stage 8 provision, unified all signature-input construction under one rule, constrained the freshness-gate enum, retired a duplicate type name, and added a floor-checkpoint replay-binding validation step. Revision 10 is authoritative wherever it conflicts with Stage 8 or Stage 9 text.

## Decision

### 1. Fact authority matrix

| Authority | Owns | Truth kind | Consulted by |
|---|---|---|---|
| Control-plane SQLite | Current mutable lifecycle state: command/candidate/object/revision rows, deletion phase, ARK custody pointers, local floor row | Cache of last-authenticated state, WAL checked-snapshot read | All reads/writes before CAS/Keychain confirmation |
| CAS / Git | Ciphertext bytes and signed generation/bundle artifacts | Immutable content-addressed, signed at generation boundary | Publication, restore, evidence bundles |
| Binding registry (signed history + sparse current map + checkpoint) | Canonical per-`(namespace,provider_handle)` status truth (`PREPARED/ACTIVE/LOSER/EXPIRED/DELETION_VETOED/DESTROYED`) | Append-only signed Merkle history plus 256-level sparse current map, checkpointed | Reconciliation, destroy gating, restore classification |

SQLite is a cache, never a destroy or restore authority on its own: `QUARANTINE_UNKNOWN` is the outcome whenever the DB owner row cannot be joined against a current signed checkpoint and exact registry proof (frozen Core contracts, "Corrupt-row-safe reconciliation"). CAS/Git bytes are opaque and immutable once written; only the binding registry's signed checkpoint decides whether a given artifact revision is currently active, superseded, or destroyable. No authority may be inferred by majority vote across the three stores — disagreement always resolves toward the more conservative (non-destructive) outcome.

### 2. Canonical identity messages and HMAC framing

Five identity message families are frozen, each HMAC-SHA-256 framed over versioned canonical JSON with an explicit `schema`/`domain`/`version` discriminator and zero raw numeric tokens:

1. **Command identity** — canonical command envelope (kind, options, body/input digest).
2. **Manifest identity** — artifact/object/role/ordinal-sorted manifest entries feeding `manifest_digest_key_v1`.
3. **Artifact/semantic identity** — `MemoryRevisionSemanticV1`, `EvidenceFragmentSemanticV1` (restated in full with required `locator_text`), `AssertionSemanticV1`, `EvidenceEdgeSemanticV1`.
4. **Subject/locator identity** — `StableSubjectRefMessageV1` and `LocatorDigestMessageV1`, keyed by `stable_subject_key_v1` and `locator_identity_key_v1` respectively.
5. **Object/revision identity** — `LogicalObjectId` and `RevisionId`, unchanged from Revision 6/7 field sets, required nulls, and role/order rules.

Every message is validated by `canonical_identity_bytes_v1`: closed schema, reject every JSON numeric token, reject unknown/omitted fields, reject invalid null, then call unchanged `memory_core.contracts.canonical_bytes` (`src/wiki_spike/memory_core/contracts.py:44`). This is the single canonicalization path for all identity bytes in this system; no parallel encoder exists.

`input_content_digest = SHA-256(normalized_body_bytes)`. For a REMEMBER source, `source_content_digest` is exactly the same 32 digest bytes/hex64 representation — no second HMAC, no source-instance salt, no raw-byte digest, no path input. This equality is a literal-vector-checked invariant, not an implementation convenience.

### 3. HKDF-SHA-256 key derivation labels

Exactly eight HKDF-SHA-256 (RFC 5869) labels exist, each with unchanged salt, PRK, NUL-delimited info string, key version, and 32-byte output:

`command_digest_key_v1`, `manifest_digest_key_v1`, `artifact_identity_key_v1`, `subject_identity_key_v1`, `object_identity_key_v1`, `revision_identity_key_v1`, `stable_subject_key_v1`, `locator_identity_key_v1`.

No ninth label, no label reuse across message families, and no ad hoc derivation path is permitted. 256-bit derived keys are lowercase hex64 but are key types, never accepted as nonce values (see §5).

### 4. Single signature-input construction rule (R10-2, binding)

All signatures in the encrypted-lifecycle and binding-authority trust chain use exactly one construction:

```
signature_input = domain_prefix_bytes + canonical_bytes(payload_object)
```

`domain_prefix_bytes` is the ASCII domain string terminated by one NUL byte (`\0`); `payload_object` is the complete versioned payload including its own `schema` field. This mirrors the existing Core generation-signing pattern (`wiki.generation.v1` domain separator) and is now the *only* signing construction in the system — there is no second, wrapper-object framing.

Registered domains (non-exhaustive, all present in scope):

- `wiki.binding.latest-read-attestation.v1\0` — `BindingLatestReadAttestationPayloadV1` (unchanged from R9-3).
- `wiki.binding.history-leaf.v1\0` — binding history leaf signatures.
- `wiki.binding.checkpoint.v1\0` — binding checkpoint signatures.

**Errata correction (LOW, consensus pass 10):** the Stage 8 wrapper-object framing `{domain,version,workspace_id,key_id,hash}` as a *separate* hashed message wrapped around the leaf/checkpoint hash is struck. Those fields move **into** the leaf/checkpoint payload objects themselves, which are then signed once under the single rule above — there is no residual two-layer signing path, and no text in this ADR echoes the struck wrapper as a valid alternative construction.

Every future artifact class MUST declare its ASCII domain string in its schema; signing without a registered domain is a defect. Cross-domain vectors are mandatory: a signature valid under its own domain MUST fail verification under any other registered domain, including domains that differ only by version suffix.

### 5. Nonce type split

Two disjoint, non-interchangeable nonce scalar types exist:

- `AesGcmNonceHex24 = ^[0-9a-f]{24}$` — exactly 12 random bytes, the only nonce type accepted by AES-GCM envelopes and AAD fixtures.
- `ChallengeNonceHex64 = ^[0-9a-f]{64}$` — exactly 32 random bytes, the only nonce type accepted by challenge reservation/request/attestation fixtures.

Cross-use of either type rejects even where a generic hex string of matching width would otherwise parse; this is enforced at every schema boundary that accepts a nonce, not only at construction time. Literal vectors cover both types and their cross-boundary rejection.

### 6. Per-artifact-revision ARK granularity

Each canonical artifact revision (owner decision 4, carried forward unchanged) has its own independent Artifact Recovery Key (ARK). ARK scope is exactly one artifact revision — never an object, a workspace, or a batch of revisions. This granularity is what makes targeted crypto-shred possible without collateral loss of unrelated revisions, and is a precondition the recovery/deletion contract in ADR-0027 depends on but does not redefine.

### 7. Command/manifest/junction cardinality model

Convergent per-`(workspace, artifact_kind, revision_id)` election yields exactly one canonical winner: `UNIQUE(workspace, artifact_kind, revision_id)` at the manifest/junction layer, with any additional persisted reference to the same tuple represented strictly as a command alias — never a second competing manifest entry. Manifest entries use the frozen role/ordinal/kind/revision sort; one primary memory ordinal `0` is required; evidence role entries deduplicate by semantic digest and receive contiguous ordinals after raw-digest sorting. This cardinality rule is closed: no schema, code path, or migration may create two live manifest entries for the same canonical tuple.

### 8. Envelope identity

AES-256-GCM envelopes use a randomized nonce (`AesGcmNonceHex24`) per encryption operation. The envelope is persisted once and reused verbatim for every subsequent read of that ciphertext — envelopes are never re-encrypted or re-derived on read. `blob_id = SHA-256(envelope_bytes)`, computed over the exact persisted envelope byte sequence (ciphertext + nonce + tag framing as canonically serialized), giving content-addressed identity that is stable across process restarts and independent of any in-memory representation.

### 9. Acyclic bundle identity (self-field projection)

Bundle envelope identity avoids a self-referential fixed point by replacing exactly two fields — `artifact_name` and `bundle_sha256` — with fixed JSON empty strings (`""`, never `null`) before computing `projected_envelope_bytes` for the digest projection. No other envelope field or byte-level value changes under projection. One-pass construction is exact:

1. Validate payloads and all non-self envelope fields; build a template with both self-fields `""`.
2. Canonicalize the template once to `projected_envelope_bytes`; build and canonicalize the manifest once (manifest excludes itself; its `artifact-envelope.json` entry records the SHA-256/size of `projected_envelope_bytes`, not stored envelope bytes).
3. `bundle_sha256 = SHA-256(canonical manifest bytes)`.
4. `artifact_name = encrypted-lifecycle-<lower-kind>-<run>-<attempt>-<first16(bundle_sha256)>`.
5. Replace the two self-fields in the template with their real values and canonicalize the stored envelope; store it with the unchanged manifest/payloads. The manifest and digest are never recomputed after this step.

Import independently re-derives the same projection (parse strict stored envelope → project both self-fields back to `""` → canonicalize → verify projected hash/size entry → verify payload hashes → recompute full bundle digest → require stored digest/name equality) without any shared code path with the builder. Builder and importer must reproduce identical final bytes, digest, and name from two independent implementations.

### 10. R10-1 supersession enumeration (binding, exhaustive)

Revision 10 struck exactly three Stage 8 provisions in full; no other Stage 8 clause is superseded by R9-1, and this ADR states the replacement text verbatim so no derivative or paraphrased "adoption" language survives anywhere in the identity/authority contract:

1. **Stage 8 §7 direct-child adoption paragraph** (authenticated direct-child B adoption when `prior_floor_hash`/counter match and local ledger validates) — struck in full.
2. **Stage 8 Acceptance Criterion 11** ("Exact/direct-child CAS winners converge only with local signed evidence") — struck. Replacement AC 11 (binding text, verbatim): *"A prepared floor candidate completes only as its exact recorded bytes. Any Keychain value other than the expected old floor or byte-identical candidate A — including an otherwise valid authenticated direct child — transitions the attempt to `QUARANTINED_FLOOR_CONFLICT`, retains authenticated A/B digests for audit, disables restore, key staging, and serve, and requires operator recovery. No adoption, supersession, or convergence path exists."*
3. **Stage 8 Options-table row "Floor winner adoption"** — struck. The option table now records adoption as **Rejected**, rationale: "CAS loser cannot both complete exact bytes and adopt a different winner; adoption creates unverifiable in-flight races."

**Errata correction (LOW, consensus pass 10):** any derived phrasing that echoes the struck adoption paragraph as though it remained a valid path (e.g. summarizing floor identity as "direct-child wins converge") is prohibited in this and all downstream documents. Test suites MUST be constructed from the replacement AC 11 only; a convergence/adoption test is itself a defect.

## Consequences

- Every identity, key, and signature in the system is reproducible by an independent verifier from documented bytes alone, with zero dependency on implementation-specific serialization quirks, because all paths funnel through the unchanged Core `canonical_bytes`.
- The single signature-input rule (R10-2) removes an entire class of framing-mismatch bugs between leaf/checkpoint signing and verification, at the cost of moving previously wrapper-level fields into payload objects — every existing leaf/checkpoint schema consumer must read those fields from the payload, not a wrapper.
- Nonce type separation prevents challenge-nonce/AES-nonce confusion at the schema boundary, at the cost of maintaining two disjoint regex-validated scalar types instead of one generic hex nonce.
- Bundle self-field projection guarantees acyclic identity at the cost of a stricter, less "obvious" digest computation that importers must replicate exactly; any importer that hashes the stored envelope directly will silently diverge and must be rejected by the strict pipeline.
- Per-artifact-revision ARK granularity is a precondition for crypto-shred (ADR-0027) and increases custody bookkeeping compared to per-object or per-workspace keys.
- The R10-1 supersession is authoritative and exhaustive: no test, schema, or prose anywhere in Gate 1+ artifacts may reintroduce direct-child adoption without a new ADR.

## Non-goals

Recovery phases, dual-custody destruction sequencing, freshness serve-gate enum contents, floor CAS/readback protocol mechanics, WAL linearization, and backup residual bounds are owned by ADR-0027 and are not restated here beyond the identity dependencies above (ARK granularity, signature-input rule, nonce types).
