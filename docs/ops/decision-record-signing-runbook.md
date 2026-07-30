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

DB-01, DB-04, DB-05 and DB-07 are globally fatal; an invalid or missing record
blocks the whole product plan. DB-02, DB-03, DB-06 and DB-08 are scoped and
exclude only their named source, route, or destination.
