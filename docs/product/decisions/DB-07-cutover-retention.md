# DB-07: Cutover, rollback, and legacy retention

- Status: **UNRESOLVED — evidence and signatures required**
- Scope: **Global** (with source-by-source cohort execution)
- Owner → approver: Migration → Product
- Decision version: 1
- Date: 2026-07-28
- Expiry: Must be set in the signed decision record; an expired record is unresolved.

## Question

Under what conditions may sources move to wiki-spike, and what happens to the prior systems?

## Reconciled proposed decision

Migrate one source at a time into final-workspace, non-serving cohorts. Each cohort must complete a source-specific 3-day measured shadow period before cutover. Once the period, quantitative cutover formula, and required external approvals are satisfied, that cohort moves directly to live serving. Prior systems remain read-only for 90 days after that cohort's activation; they are migration inputs, never peer serving gateways or query-time fallback.

A signed cutover transaction binds the cohort roster, resolved-scope and contract digests, source/capability and benchmark/holdout manifests, generation/checkpoint, route version, capability epoch, observation period, thresholds, aggregates, formula, and approvers. Before the first canonical mutation, a signed emergency rollback may route the whole cohort to the exact read-only pre-cutover UI/API with a banner and write freeze; wiki-spike stops capture and promotion.

The `approvers` field binds exactly four external approver roles: `migration`, `quality`, `security`, and `product`. `CutoverDecisionV1` rejects any other set, including a missing role, an extra role, and a duplicate role; role names are compared case-insensitively. This is a fixed set, not a minimum, so a cohort cannot be activated by a narrower or a broader approval panel.

A cohort advances through exactly these states: `DISCOVERED`, `IMPORTING`, `QUARANTINED_ITEM`, `RECONCILING`, `READY_NON_SERVING`, `CUTOVER_READY`, `ROUTE_SWITCHED_NO_MUTATION`, `CANONICAL_MUTATED`, `ROLLBACK_CLOSED`, `ROLLED_BACK_RECONCILE`, `DECOMMISSIONED`. `ROUTE_SWITCHED_NO_MUTATION` is the only state from which the emergency rollback above is legal. External rollback is closed in `CANONICAL_MUTATED`, `ROLLBACK_CLOSED`, and `DECOMMISSIONED`. Decommission is legal only from `ROLLBACK_CLOSED`, and only after the 90-day read-only retention has elapsed.

The first canonical mutation closes rollback. Mutation includes remember, capture acceptance, review, correction, promotion, revoke, forget, consent, or route-authority mutation. After that point, failure is fail-closed disable/read-abstention: never legacy routing, resurrection of keys/history, dual-write, or query merge.

## Required evidence and signatures

A GO or NO_GO is valid only when the versioned record is schema-valid, canonical, signed by Migration and Product, unexpired, and binds digests for:

- cohort inventory and enabled migration-source eligibility;
- legal retention and decommission requirements;
- source reconciliation, deletion, count/dedupe-root, and citation comparisons;
- route and recovery rehearsals, rollback window, and post-mutation fail-closed proof; and
- the frozen DB-05 benchmark/holdout manifests, thresholds, and shadow-observation evidence.

No cutover approval, route rehearsal, legal retention evidence, or product proof is claimed by this document. Gate 8 is immutable and separate; it is not cutover evidence.

## GO / NO_GO effect

This is global. A valid GO authorizes only evidence-complete, source-by-source cohort cutovers under the signed controls; it does not activate a cohort automatically. A valid NO_GO, missing record, invalid signature/schema/digest, or expiry blocks activation, route switch, and product progression. A cohort with absent or non-GO source eligibility cannot be imported, routed, or retried through configuration.

## Supersession

Changes to cohort order, shadow window, 90-day retention, route semantics, mutation boundary, or decommission terms require a signed superseding version and refreshed resolved-scope/contract digest. A supersession does not reopen rollback after canonical mutation.
