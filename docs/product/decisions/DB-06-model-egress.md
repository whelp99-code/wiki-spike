# DB-06: Model and reflection egress

- Status: **UNRESOLVED — evidence and signatures required**
- Scope: **Feature-scoped: each external reflection/model-egress route and provider**
- Owner → approver: Privacy → Security
- Decision version: 1
- Date: 2026-07-28
- Expiry: Must be set in the signed decision record; an expired record is unresolved.

## Question

May an external provider receive product material for extraction or reflection?

## Reconciled proposed decision

Processing is local-first. An external provider may receive only data classes explicitly opted in by the owner for that named provider and route. Consent, disclosure, capabilities, retention, deletion-residual handling, and provider approval are route- and data-class-specific. The provider receives no unapproved class.

There is no provider fallback. A refusal, outage, revoked consent, expired capability, unknown classification, or disabled route fails closed for that route; it must not select another provider, broaden a class, or use a local result as an undisclosed substitute for an external feature. Reflection output is a proposal receipt and becomes memory only through the ordinary reviewed changeset path. Hidden reasoning is never persisted.

## Required evidence and signatures

A GO or NO_GO is valid only when the versioned record is schema-valid, canonical, signed by the named owner and approver, unexpired, and binds digests for:

- the named provider, exact route, approved data classes, and capability boundary;
- DPA/egress assessment and provider terms;
- owner consent and disclosure fixture;
- deletion request, residual-copy policy, retention, and incident handling; and
- fixtures proving class filtering, consent revocation, provider failure, and no-provider-fallback behavior.

No provider is currently approved by this specification. No external approval, DPA, consent fixture, deletion evidence, or Gate 8 product proof is asserted here.

## GO / NO_GO effect

This is scoped, not global. A valid GO enables only the signed provider/route/data-class combination. A valid NO_GO disables only that combination and leaves the product local-only for it. It cannot enable a substitute provider or block unrelated approved routes. Missing, invalid, unsigned, stale, or expired records are unresolved and default to disabled.

## Supersession

Changing provider, route, data classes, terms, retention, or residual policy requires a new signed record and refreshed resolved-scope/contract digest. The former scope remains disabled unless its existing unexpired approval still exactly matches the request.
