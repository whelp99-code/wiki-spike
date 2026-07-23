# ADR-0013: Deterministic Intent and IANA Temporal Resolution

- Status: Accepted for P4-02
- Date: 2026-07-23
- Scope: conservative intent classification, relative-time resolution, precision and as-of metadata

## Context

P4-01 established deterministic Runtime operation and stage execution. The first
planned-stage decision must determine what class of Runtime work was requested and
which absolute time domain it refers to. That decision cannot depend on server locale,
naive timestamps, or an LLM guess. A phrase such as “today” has different UTC bounds in
Seoul and New York, and a local timestamp may be ambiguous or nonexistent at a daylight-
saving transition.

The resolver also handles sensitive query text. Public Runtime metadata must not contain
that text, while later stages still need a stable way to bind their result to the exact
input.

## Decision

### 1. Conservative intent classification

Known request types map to explicit intent classes:

```text
recall | ask | extract_decision | clarify | proactive_evaluate
```

A generic request type requires an explicit compatible hint. Unknown or insufficient
requests become `ambiguous`; they are never guessed into a stronger intent. A hint may
refine a generic route but may not override a known route.

### 2. Content-bound, privacy-minimized contracts

`IntentTemporalInput`, `IntentResolution`, `TemporalResolution`, and the combined
`IntentTemporalResolution` have exact field sets, known versions, canonical UTF-8 JSON,
and domain-separated SHA-256 IDs. Resolver entry reparses canonical bytes so caller-
owned mutation cannot change meaning behind an established ID.

The query body is used only inside the resolver. Public results contain a query digest,
not the text itself.

### 3. Explicit temporal reference frame

Every resolution receives:

- canonical UTC `as_of_at` at second precision;
- canonical IANA timezone;
- optional explicit temporal expression;
- optional ambiguity fold for a local timestamp.

Resolved instants and intervals are emitted only as canonical UTC timestamps. The output
records the selected timezone and the TZDB version used.

### 4. Relative interval semantics

The deterministic vocabulary includes bounded Korean and English aliases for current,
today, yesterday, tomorrow, this/last/next week, month, and year. Explicit structured
forms support dates, months, years, inclusive date ranges, local instants, UTC instants,
and bounded rolling elapsed intervals.

Calendar intervals are created in the user timezone and then converted to UTC. Therefore
DST days may contain 23 or 25 elapsed hours. Weeks use ISO Monday. Date ranges include
the supplied end date by using the following local midnight as the exclusive endpoint.
Precision (`day`, `week`, `month`, `year`, `second`, `rolling`) is retained separately
from the absolute interval.

### 5. Ambiguity and conflict

- Two distinct temporal expressions in query text produce an ambiguous result.
- Repeated instances of the same expression do not.
- A conflicting explicit expression and query expression are rejected.
- A local timestamp with two valid instants requires `temporal_fold`.
- A nonexistent local timestamp is rejected; it is not shifted automatically.
- No recognized temporal expression yields mode `none`, not an inferred current range.

### 6. Stage integration

`IntentTemporalStageHandler` runs only at the `planned` stage and emits a metadata-only
`RuntimeStageResult`. It performs no model call, Storage read, connector call, or external
action. Invalid contracts are translated to a stable fatal stage reason.

## Consequences

- Temporal behavior is repeatable across retries when the same TZDB is available.
- DST and calendar precision remain auditable.
- Ambiguity is visible and can be routed to a later Clarification Engine.
- The planned-stage output can feed retrieval without exposing query text through public
  status or response contracts.

## Limitations and deferred work

- This is a conservative resolver, not unrestricted natural-language parsing.
- A deployment must keep TZDB packages patched and consistent; P4-02 only records the
  version observed.
- Locale-specific business calendars, holidays, fiscal periods, and recurrence are not
  included.
- Retrieval, EvidencePack construction, model generation, and clarification interaction
  are later Phase 4 PRs.

## Rollback

P4-02 is additive. Reverting it removes intent/temporal contracts, stage handler, schema,
tests, and documentation without modifying signed Phase 3 artifacts, Storage schemas,
or P4-01 operation records.
