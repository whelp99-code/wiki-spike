# P4-02 Conformance Report

## Scope

P4-02 implements deterministic Intent classification and IANA-timezone Temporal
resolution at the P4-01 `planned` stage.

Included:

- content-bound input, intent, temporal, and combined-resolution contracts;
- explicit request-type and compatible hint resolution;
- query-digest privacy boundary;
- canonical UTC as-of, instant, and interval output;
- IANA timezone and TZDB-version metadata;
- DST-aware day boundaries and strict local-time fold handling;
- day/week/month/year/rolling precision retention;
- ambiguity and explicit/query conflict handling;
- metadata-only planned-stage handler.

Excluded:

- model-based intent parsing;
- retrieval, ranking, EvidencePack, recall, or decision evaluation;
- clarification conversation policy;
- application connector, UI, or external action behavior.

## Requirement mapping

| Requirement | Evidence | Status |
|---|---|---|
| P4-F-002 deterministic intent | request-type/hint mapping and ambiguity tests | PASS |
| P4-F-002 explicit as-of | canonical UTC `as_of_at` and result binding | PASS |
| P4-F-002 IANA timezone | invalid zone/path rejection and key equality | PASS |
| P4-F-002 relative intervals | today/week/month/year/range/rolling tests | PASS |
| P4-F-002 DST | 23-hour and 25-hour day tests | PASS |
| P4-F-002 local ambiguity | fold and nonexistent-time tests | PASS |
| P4-F-002 precision | day/week/month/year/rolling output fields | PASS |
| privacy | query digest only; no query body in public result | PASS |
| P4-F-020 boundary | Runtime imports only allowed Core contracts/ports | PASS when CI is Green |

## Security and privacy

The stage result contains intent codes, hashes, UTC bounds, timezone/TZDB identifiers,
precision, and reason codes. It excludes query text, source records, prompts, model
responses, credentials, and provider clients. Unknown versions, fields, and inconsistent
nested resolution IDs fail closed.

## Failure semantics

- unknown or generic intent without hint: ambiguity, not guessing;
- conflicting intent hint/request route: fatal invalid input;
- unknown timezone or malformed date/time: fatal invalid input;
- multiple temporal expressions: clarification-required resolution;
- conflicting explicit/query time: fatal invalid input;
- ambiguous local time without fold or nonexistent local time: fatal invalid input;
- no temporal phrase: mode `none` with no fabricated interval.

## Completion semantics

P4-02 is complete only after the targeted suite, full warnings-as-errors regression,
G3 contract pin, Runtime and architecture boundaries, secret scan, compileall, package
smoke, and all three GitHub CI checks pass on the exact PR head. It does not create G4
and does not authorize P4-03 or Phase 5 until merged.

## Local validation before PR

```text
P4-02 targeted + tooling     51 passed
Full warnings-as-errors      527 passed
G3 contract pin              PASS
Runtime boundary             PASS
Architecture boundary        PASS
Secret scan                  PASS
Python compileall            PASS
Wheel install / CLI smoke    PASS
JSON Schema samples          4 / 4 PASS
Adversarial rounds           20 / 20
```

GitHub CI on the exact PR head remains the authoritative acceptance evidence.
