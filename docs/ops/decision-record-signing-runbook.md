# DB-01..DB-08 decision record signing runbook

How to produce a signed decision record that `resolve_second_brain_contract` accepts.

Every command below was executed end to end against throwaway keys before this
document was written; the outputs shown are real, not illustrative.

---

## What the contract actually demands

| requirement | enforced by |
|---|---|
| Ed25519, 64-byte detached signature, 32-byte raw public key | `Ed25519SignatureEnvelopeV1` |
| signed over `wiki-spike.second-brain.decision.v1\0` + `canonical_bytes(record minus signatures)` | `detached_signing_bytes` |
| exactly **two** signatures | `_signature_set` |
| ordered **approver then owner** | `_signature_set` |
| distinct `key_id` **and** distinct public keys | `_signature_set` |
| record schema-valid, unexpired, correct `scope_kind` for the `decision_id` | `DecisionRecordV1.from_mapping` |
| keys bound to the trusted owner/approver identities | `TrustedDecisionKeyBindingsV1` |

`canonical_bytes` is this repository's own normalisation, so the signing bytes
cannot be reproduced by hand. `scripts/second_brain_decision.py` emits them.

Two distinct keys is a separation-of-duties control, not a formality. One person
holding both keys satisfies the validator and defeats the control.

---

## 0. Keys

Generate on the machine that will hold the key, never in the repository.

```sh
openssl genpkey -algorithm ed25519 -out ~/keys/owner.pem
chmod 600 ~/keys/owner.pem
openssl pkey -in ~/keys/owner.pem -pubout -outform DER | tail -c 32 > ~/keys/owner.pub.raw
```

The approver runs the same on their own machine with their own key.

`openssl pkey -pubout -outform DER` emits a 44-byte SubjectPublicKeyInfo; the
trailing 32 bytes are the raw key. Passing the 44-byte form is the classic
mistake and the tool rejects it by length with that explanation.

Only `*.pub.raw` is ever exchanged. The `.pem` private keys never leave their
machine, never enter the repository, and are never sent to the other party.

---

## 1. Owner writes the body

```sh
python3.12 scripts/second_brain_decision.py skeleton \
  --decision-id DB-05 > body.json
```

`python3` on this workstation is 3.11; use `python3.12`.

DB-02, DB-03, DB-06 and DB-08 are scoped and additionally require
`--scope-name`; DB-01, DB-04, DB-05 and DB-07 are global and reject it. The
skeleton fills `scope_kind` correctly and fails closed if the pairing is wrong.

Replace every `REPLACE-WITH-*` placeholder. `evidence_digest` must be the sha256
of the evidence bundle the decision attests to; `evidence_refs` must list at
least one real path. `expires_at` must precede any change to the behaviour the
record pins.

---

## 2. Owner emits the signing bytes

```sh
python3.12 scripts/second_brain_decision.py signing-bytes \
  --body body.json --out DB-05.signing.bin
```

```json
{
  "bytes": 571,
  "domain": "wiki-spike.second-brain.decision.v1",
  "sha256": "6c8b50f2808637b990c1a2b1b968e841d301f5ae60ff3ff8bb7c3a9548acc5b6",
  "written_to": "DB-05.signing.bin"
}
```

Send `DB-05.signing.bin` to the approver. It carries digests and references, not
source bodies, so it is safe to transmit under DB-08. Report the sha256 over a
separate channel.

---

## 3. Approver reads what they are about to sign

Do not review a companion JSON file. The file and the bytes can disagree, and
the signature covers the bytes.

```sh
python3.12 scripts/second_brain_decision.py inspect \
  --signing-bytes DB-05.signing.bin
```

This decodes the bytes themselves, re-derives the canonical encoding from what
it decoded, and refuses anything that is not an exact canonical record:

| tampering | result |
|---|---|
| one byte appended | refused |
| signing domain stripped | refused |
| re-indented, non-canonical JSON | refused |
| unknown field inserted | refused |
| unmodified bytes | printed, exit `0` |

Confirm the printed sha256 matches the one received out of band, and read the
decoded body. If either check fails, stop; do not sign.

---

## 4. Each party signs independently

Ed25519 requires `-rawin`.

```sh
openssl pkeyutl -sign -inkey ~/keys/owner.pem \
  -rawin -in DB-05.signing.bin -out owner.sig
```

The result is exactly 64 bytes. The approver does the same with their key on
their own machine.

---

## 5. Wrap each signature in an envelope

```sh
python3.12 scripts/second_brain_decision.py envelope \
  --role owner --key-id wiki-owner-2026 \
  --public-key ~/keys/owner.pub.raw --signature owner.sig > owner.env.json
```

`--key-id` is the durable identity that `TrustedDecisionKeyBindingsV1` binds.
The owner and approver ids must differ, as must their public keys.

---

## 6. Assemble

```sh
python3.12 scripts/second_brain_decision.py assemble --body body.json \
  --signature owner.env.json --signature approver.env.json \
  --out artifacts/product-release/second-brain-v1/decisions/DB-05.json
```

Assemble orders the envelopes approver-then-owner, verifies both signatures
against the body, and runs the full contract before writing. It refuses:

- a body edited after signing, reporting the signing-bytes digest so the
  divergence is diagnosable
- anything other than exactly one owner and one approver
- a reused key identity or public key across the two roles

---

## 7. Verify

```sh
python3.12 scripts/second_brain_decision.py verify --record .../DB-05.json
```

Exit `0` with `"signatures_verified": true`. Exit `1` means the record was
edited after signing.

`verify` checks the signatures against the keys embedded in the record. Binding
those keys to the trusted owner and approver identities is a separate check,
performed by `resolve_second_brain_contract` with `TrustedDecisionKeyBindingsV1`;
the tool prints that caveat on stderr rather than implying more than it checked.

---

## Exit codes

| code | meaning |
|---|---|
| `0` | accepted |
| `1` | record parsed, signatures do not verify |
| `2` | rejected before verification: malformed input, contract violation, wrong lengths, wrong scope pairing |

---

## Producing the DB-05 evidence bundle

`evidence_digest` is not free text. For DB-05 it is the `governance_digest` of
an `EvaluationGovernanceV1`, which binds the five things DB-05's evidence list
demands. `scripts/second_brain_evaluation_governance.py` builds it.

No benchmark or holdout manifest existed in this repository, which is what made
DB-05 unsignable regardless of who consented.

Freeze the SLOs. The defaults are the enforced floors; raise them if you intend
to, never lower them.

```sh
python3.12 scripts/second_brain_evaluation_governance.py slo \
  --parity-min-bps 9000 --citation-min-bps 9000 \
  --completeness-min-bps 9000 --availability-min-bps 9900 \
  --out out/slo.json
```

Build the benchmark manifest from the labelled corpus. Only digests enter the
manifest; no corpus content does, which is what keeps the evidence body-free.

```sh
python3.12 scripts/second_brain_evaluation_governance.py benchmark-manifest \
  --corpus-dir ~/benchmark-corpus \
  --workspace-ref "workspace:second-brain-final" \
  --corpus-key-ref "key:benchmark-corpus-2026" \
  --capability-ref "capability:benchmark-read-2026" \
  --label-review-digest LABEL_REVIEW_SHA256 \
  --consent-digest OWNER_CONSENT_SHA256 \
  --out out/benchmark.json
```

Build the holdout manifest from a **separate** corpus under a **separate** key.

```sh
python3.12 scripts/second_brain_evaluation_governance.py holdout-manifest \
  --corpus-dir ~/holdout-corpus \
  --workspace-ref "workspace:second-brain-final" \
  --holdout-key-ref "key:holdout-corpus-2026" \
  --capability-ref "capability:holdout-read-2026" \
  --separation-digest SEPARATION_SHA256 \
  --out out/holdout.json
```

Bind them.

```sh
python3.12 scripts/second_brain_evaluation_governance.py governance \
  --benchmark out/benchmark.json --holdout out/holdout.json --slo out/slo.json \
  --workspace-ref "workspace:second-brain-final" \
  --encryption-isolation-digest ISOLATION_DESIGN_SHA256 \
  --serving-corpus-digest SERVING_CORPUS_SHA256 \
  --out out/governance.json
```

The printed `governance_digest` is DB-05's `evidence_digest`.

Separation is enforced, not assumed. Refused: an item digest present in both
corpora, one key used under two names, either corpus digest reused as the
serving corpus digest, an empty corpus, and byte-identical duplicates within a
corpus.

The four attestation digests - label review, consent, separation, encryption
isolation - come from human processes. The tool takes them as input and refuses
to invent them.

---

## Producing a DB-03 evidence bundle

DB-03 resolves one source at a time, so each of `legacy Mem0/RAG`, `me-wiki` and
`unified-db` needs its own bundle and its own record. For a migration source the
`evidence_digest` is the `evidence_digest` of a `MigrationSourceEvidenceV1`,
which binds the five things a source-specific `GO` requires.
`scripts/second_brain_migration_source_evidence.py` builds it.

`artifacts/product-release/second-brain-v1/unified-db-inventory-v1.json` recorded
`STOP_PENDING_IMMUTABLE_SNAPSHOT_AND_DIFF` and named five missing items. Three of
them are yours, not the tool's: the immutable snapshot taken after writers are
quiesced, the before/after zero-write proof, and the owner key binding. The tool
takes their digests and refuses to invent them. The other two - the uniqueness
diff and the deletion/history treatment - it computes from that snapshot.

### 1. Bind the snapshot

The zero-write proof is the equality of the source-root digest observed before
and after the export window. Unequal roots mean writers were still running, and
the contract refuses the snapshot rather than recording a weaker claim.

```sh
python3.12 scripts/second_brain_migration_source_evidence.py snapshot \
  --source-name unified-db \
  --snapshot-ref "snapshot:unified-db-2026-07-30" \
  --writers-quiesced-at 2026-07-30T00:00:00Z \
  --snapshot-taken-at 2026-07-30T00:05:00Z \
  --source-root-digest-before ROOT_SHA256 \
  --source-root-digest-after ROOT_SHA256 \
  --snapshot-package-digest PACKAGE_SHA256 \
  --owner-key-ref "key:migration-owner-2026" \
  --owner-attestation-digest OWNER_ATTESTATION_SHA256 \
  --out out/snapshot.json
```

`active_run_observed` is not an argument. It is written `false` and enforced
`false`, because the inventory refused to derive a package from a live instance
and no flag should be able to undo that.

### 2. Pin the read-only export

Every later command reads the source name out of the snapshot, so a profile,
diff or treatment can never disagree with the snapshot it claims to describe.

```sh
python3.12 scripts/second_brain_migration_source_evidence.py export-profile \
  --snapshot out/snapshot.json \
  --export-method read-only-transaction \
  --write-capability-probe-digest WRITE_PROBE_SHA256 \
  --schema-version unified-db-2026-07 --schema-digest SCHEMA_SHA256 \
  --native-identity-field source_id \
  --native-identity-field native_id \
  --native-identity-field content_hash \
  --identity-mapping-digest IDENTITY_MAPPING_SHA256 \
  --revision-semantics content-hash-revision \
  --revision-mapping-digest REVISION_MAPPING_SHA256 \
  --watermark-cursor-field source_cursor \
  --overlap-behavior replay-overlap \
  --restart-evidence-digest RESTART_SHA256 \
  --page-size-limit 500 --retention-days 90 \
  --source-fixture-digest FIXTURE_SHA256 \
  --out out/profile.json
```

`--export-method` accepts only read-only methods, and `write_capability_absent`
is enforced true against `--write-capability-probe-digest`, which must be the
digest of evidence that a write through the export credential was actually
attempted and refused. A read-only query run under a credential that still holds
write capability is not a read-only export, and DB-03's strongest requirement is
not allowed to rest on a bare boolean. The six evidence digests - schema,
identity mapping, revision mapping, restart, write-capability probe and fixture -
must be six distinct documents. `--overlap-behavior` has no "unknown" value: a
source that cannot say whether its cursor replays or is exactly-once has not
produced watermark evidence.

### 3. Diff for uniqueness, body-free

Hash the exported snapshot and the supported canonical corpus into digests, then
diff. Only digests enter the artifact; no exported record content does.

```sh
python3.12 scripts/second_brain_migration_source_evidence.py digests \
  --dir ~/snapshot-export --out out/candidates.json
python3.12 scripts/second_brain_migration_source_evidence.py digests \
  --dir ~/canonical-export --out out/canonical.json

python3.12 scripts/second_brain_migration_source_evidence.py uniqueness-diff \
  --snapshot out/snapshot.json \
  --candidates out/candidates.json --canonical out/canonical.json \
  --out out/diff.json
```

Byte-identical duplicates are refused on input: a content-digest comparison
cannot tell them apart, so deduplicate deliberately rather than silently.
Symlinks under `--dir` are refused rather than followed, so bytes from outside
the declared export tree can never enter the digest set. If no candidate
survives the diff the tool says so on stderr - a source that adds nothing is a
`NO_GO` candidate, and the artifact records that honestly instead of hiding it.

Confirm the export directory is the snapshot before you diff. The diff binds
`canonical_corpus_digest`, but the candidate side is bound only transitively
through the snapshot's `snapshot_package_digest`: check that your export
directory is the package that digest names. Nothing in the tool can do that
check for you.

### 4. Record deletion and history without inferring it

Three states, never collapsed into two: tombstoned, retained, and unavailable.

```sh
python3.12 scripts/second_brain_migration_source_evidence.py history-treatment \
  --snapshot out/snapshot.json \
  --tombstone-representation absent \
  --history-availability partial-with-proof \
  --retained-sample RETAINED_SHA256 \
  --unavailable-sample UNAVAILABLE_SHA256 \
  --out out/treatment.json
```

The inventory recorded `explicitTombstoneColumn: false` and
`absenceMayNotBeInterpretedAsDeletion: true` for unified-db, so its
representation is `absent` - and with `absent` the tool refuses tombstone
samples outright, because producing one would require inferring a deletion from
a missing row. Conversely a declared representation requires at least one real
sample. `unavailable` history may not also present retained samples, `complete`
may not also present unavailable ones, `partial-with-proof` needs both, and the
three sample sets must not overlap.

### 5. Bind the bundle

```sh
python3.12 scripts/second_brain_migration_source_evidence.py evidence \
  --snapshot out/snapshot.json --export-profile out/profile.json \
  --uniqueness-diff out/diff.json --history-treatment out/treatment.json \
  --workspace-ref "workspace:second-brain-final" \
  --security-review-digest SECURITY_REVIEW_SHA256 \
  --out out/evidence.json
```

The printed `evidence_digest` is DB-03's `evidence_digest` for that source.

Splices are refused: components from another source, components from a different
snapshot of the same source, one digest reused for two of the six bound slots,
and the owner attestation reused as the Security review. DB-03's owner is
Migration and its approver is Security; one document cannot be both.

Before signing, confirm the owner envelope's `key_id` matches the bundle's
`owner_key_ref`. Nothing enforces that join: `owner_key_ref` is an opaque
identity inside the evidence, and the signature keys are checked separately by
`TrustedDecisionKeyBindingsV1`. A bundle naming one owner key signed by another
verifies today.

`verify --file` revalidates any of the five artifacts and reports that
artifact's own binding digest, never one of the four it carries.

Building a bundle is not approving a source. It makes DB-03 signable; the `GO` or
`NO_GO` lives in the signed record, and registration additionally requires the
resolved scope to carry that source as enabled.

---

## Order of work

Signing is the last step, not the first. `evidence_digest` must already point at
evidence that exists.

```
quiesce writers -> immutable snapshot -> zero-write proof
                -> body-free per-source uniqueness diff
                -> per-source deletion/history treatment
                         |
                         v
                   evidence bundle digest
                         |
              +----------+----------+
              |                     |
        DB-03 per source        DB-05 global
        (registers a source)    (freezes the SLOs)
                                      |
                                      v
                            3-day shadow observation
                            200 parity cases/source
                            500 cohort E2E queries
                            one-sided 95% Wilson
                                      |
                                      v
                            CutoverDecisionV1 -> Stage 6
```

DB-05 does not wait on the unified-db snapshot: it freezes SLOs **before**
observation, so signing it starts the 3-day clock. It is not free of
prerequisites, though. Its `evidence_digest` binds a benchmark manifest and a
holdout manifest, so both corpora must exist, be labelled and consented, sit
under separate keys, and share no item. Build the bundle above first; consent
alone does not make DB-05 signable.

DB-03 is where the snapshot chain lands. Each source needs its own bundle from
step 1 above before its record can be signed, and `unified-db` in particular
cannot be signed from the live instance the inventory observed.

DB-01, DB-04, DB-05 and DB-07 are globally fatal; an invalid or missing record
blocks the whole product plan. DB-02, DB-03, DB-06 and DB-08 are scoped and
exclude only their named source, route, or destination.
