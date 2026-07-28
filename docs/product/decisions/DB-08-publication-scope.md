# DB-08: Publication and export scope

- Status: **UNRESOLVED — evidence and signatures required**
- Scope: **Feature/destination-scoped: each external export destination**
- Owner → approver: Product → Privacy
- Decision version: 1
- Date: 2026-07-28
- Expiry: Must be set in the signed decision record; an expired record is unresolved.

## Question

What publication is permitted in the first release?

## Reconciled proposed decision

The first release permits only wiki-spike managed internal projections. Those projections are rebuildable and withholdable; they are not competing memory authority. External export and publication are disabled and deferred. A future external destination needs its own destination-specific decision and may not be enabled by a generic publication flag.

Any future external payload and receipt must be encrypted. A deletion receipt may record a request and provider response but must never assert remote erasure where residual copies or destination terms prevent that conclusion.

## Required evidence and signatures

A GO or NO_GO is valid only when the versioned record is schema-valid, canonical, signed by Product and Privacy, unexpired, and binds digests for:

- the exact destination, payload classes, and irreversible-egress disclosure;
- destination API and delete-receipt fixture;
- residual-copy, retention, and deletion terms;
- owner consent and capability scope; and
- projection withholding, export revocation, and remote-failure fixtures.

No external destination is approved by this document. No external approval, delete receipt, publication evidence, or Gate 8 product proof exists or is implied here.

## GO / NO_GO effect

This is scoped. A valid NO_GO disables only the named external destination/export and does not block managed internal projections or unrelated destinations. A valid GO enables only the exact destination and payload scope in its signed record. Missing, unsigned, invalid, stale, or expired records are unresolved and keep that destination disabled; they cannot cause fallback to another destination.

## Supersession

A change to destination, payload class, disclosure, retention, residual-copy terms, or deletion behavior requires a signed superseding record and refreshed resolved-scope/contract digest. Until that evidence exists, external export remains deferred.
