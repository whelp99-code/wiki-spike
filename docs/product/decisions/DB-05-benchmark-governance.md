# DB-05: Benchmark governance

- Status: **UNRESOLVED — evidence and signatures required**
- Scope: **Global**
- Owner → approver: Quality → Product
- Decision version: 1
- Date: 2026-07-28
- Expiry: Must be set in the signed decision record; an expired record is unresolved.

## Question

May the first-release product make quality and cutover claims from a personal benchmark?

## Reconciled proposed decision

Use an encrypted, local personal benchmark corpus. Labels require owner review. Keep a separate private, encrypted, non-public holdout with separate keys, capabilities, and access controls from the serving corpus and benchmark-development set. Evaluation governance is not serving-memory authority: benchmark material must never become recall candidates, generation input, or serving projections. Release evidence is aggregate and body-free.

The signed record must freeze numerical SLOs, denominators, confidence method, and the benchmark/holdout manifests before observation. For cutover, the plan requires at least 1 full shadow days, at least 200 independently labeled parity cases per active source, at least 500 cohort E2E queries, one-sided 95% Wilson bounds satisfying the signed minima, and zero safety violations; invalid, abstained, and source-unavailable cases remain in denominators.

These four floors are the ones `RecallSloV1` enforces; a signed record may raise them but never lower them. The shadow window was reduced from 3 days to 1 by the one-day cutover decision, which updated ADR-0028, DB-07, and the enforcing code (earlier reduction: 14 days to 3).

## Required evidence and signatures

A GO or NO_GO is valid only when the versioned record is schema-valid, canonical, signed by the named owner and approver, unexpired, and binds digests for:

- local encryption/key and capability-isolation design;
- owner consent, label-review, and redaction review;
- development and holdout manifests proving separation and non-public handling;
- baseline measurements, frozen SLOs, denominator rules, and confidence calculation; and
- benchmark isolation fixtures proving no corpus content can serve recall or enter product evidence.

No current document supplies those signatures or evidence. Gate 8 is not benchmark or product proof and must not be cited as a substitute.

## GO / NO_GO effect

This is a global decision. A valid GO permits only the governed benchmark and later cutover evaluation described above; it does not approve live capture, egress, publication, or cutover by itself. A valid NO_GO, missing record, invalid digest/signature/schema, or expiry blocks benchmark claims, cutover, and product progression. It does not downgrade to a scoped feature refusal.

## Supersession

Changes to corpus class, label process, holdout separation, SLOs, or thresholds require a new signed version that explicitly supersedes this one and a refreshed resolved-scope/contract digest. Until then the decision remains unresolved and no quality or cutover claim is authorized.
