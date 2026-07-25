"""Frozen 30-query recall corpus and Top-3 evaluation for the Encrypted
Single-Memory Lifecycle (Gate 8, owner intent #10).

Mirrors the extraction corpus pattern (``extraction.py``): a frozen in-code
corpus with gold labels plus a deterministic evaluation that computes the
relevant-query Top-3 hit rate (``H/15 >= 0.80``) and asserts that every
forbidden category -- unrelated, deleted/superseded, wrong project/sensitivity
-- returns EXACTLY zero results.

The recall contract models the authoritative serve-filtering that every real
recall path applies (ADR-0026/ADR-0027): a candidate object is recallable only
if it is within the query's project, at or below the query's sensitivity, not
under deletion veto, and not superseded. Matching uses frozen canonical
semantic keys (the gold labels), not post-hoc fuzzy judgment. Ties are ordered
by channel, then descending score, then object ID.

Architecture-boundary contract: infrastructure layer; stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

RELEVANT = "relevant"
UNRELATED = "unrelated"
DELETED_SUPERSEDED = "deleted_superseded"
WRONG_SCOPE = "wrong_scope"

_SENSITIVITY_ORDER = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}

TOP_K = 3
RELEVANT_HIT_THRESHOLD = 0.80  # H/15 >= 0.80


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecallCandidate:
    """One object a retrieval layer would surface for a query, annotated with
    the authoritative state the serve filters check."""

    object_id: str
    channel: str
    score: float
    project_id: str
    sensitivity: str
    matches_query: bool = True
    vetoed: bool = False
    superseded: bool = False


@dataclass(frozen=True)
class RecallQuery:
    query_id: str
    category: str  # relevant | unrelated | deleted_superseded | wrong_scope
    query_text: str
    project_id: str
    sensitivity: str
    candidates: tuple[RecallCandidate, ...] = ()
    expected_object_ids: tuple[str, ...] = ()  # gold label (relevant only)


@dataclass(frozen=True)
class RecallQueryResult:
    query_id: str
    category: str
    returned_object_ids: tuple[str, ...]  # ranked, top-first
    hit: bool  # relevant: an expected object landed in the top-K
    forbidden_return: bool  # forbidden category returned > 0 results


@dataclass(frozen=True)
class RecallCorpusEval:
    total_queries: int
    relevant_count: int
    unrelated_count: int
    deleted_superseded_count: int
    wrong_scope_count: int
    relevant_hits: int
    top3_hit_rate: float  # relevant_hits / relevant_count
    zero_forbidden_returns: bool
    results: tuple[RecallQueryResult, ...]


# ---------------------------------------------------------------------------
# Authoritative serve-filtering recall (the contract under test)
# ---------------------------------------------------------------------------


def _sensitivity_allows(query_sensitivity: str, candidate_sensitivity: str) -> bool:
    """A query may recall objects at its own sensitivity or lower; a candidate
    whose sensitivity exceeds the query's is out of scope (wrong-scope)."""
    return _SENSITIVITY_ORDER[candidate_sensitivity] <= _SENSITIVITY_ORDER[query_sensitivity]


def recall_top3(query: RecallQuery) -> tuple[str, ...]:
    """Apply the authoritative serve filters to a query's candidates and return
    the top-3 recallable object IDs. A candidate is recallable only if it
    matches the query, is in the query's project, is at/below the query's
    sensitivity, and is neither deletion-vetoed nor superseded. Recallable
    candidates are ranked by (channel asc, score desc, object_id asc)."""
    recallable: list[RecallCandidate] = []
    for c in query.candidates:
        if not c.matches_query:
            continue
        if c.project_id != query.project_id:
            continue
        if not _sensitivity_allows(query.sensitivity, c.sensitivity):
            continue
        if c.vetoed or c.superseded:
            continue
        recallable.append(c)
    recallable.sort(key=lambda c: (c.channel, -c.score, c.object_id))
    return tuple(c.object_id for c in recallable[:TOP_K])


# ---------------------------------------------------------------------------
# Corpus construction helpers (deterministic; frozen at import time)
# ---------------------------------------------------------------------------


def _relevant(query_id: str, topic: str, obj: str, project_id: str = "proj-1") -> RecallQuery:
    """A relevant query: the gold object is in-scope and ranks in the top-3
    alongside lower-ranked in-scope distractors."""
    return RecallQuery(
        query_id=query_id,
        category=RELEVANT,
        query_text=f"What did we decide about {topic}?",
        project_id=project_id,
        sensitivity="INTERNAL",
        candidates=(
            RecallCandidate(obj, "primary", 0.95, project_id, "INTERNAL"),
            RecallCandidate(f"{obj}-distractor-a", "primary", 0.40, project_id, "INTERNAL"),
            RecallCandidate(f"{obj}-distractor-b", "secondary", 0.30, project_id, "PUBLIC"),
        ),
        expected_object_ids=(obj,),
    )


def _unrelated(query_id: str, topic: str) -> RecallQuery:
    """An unrelated query: surfaced candidates do not match the query, so the
    authoritative result is empty."""
    return RecallQuery(
        query_id=query_id,
        category=UNRELATED,
        query_text=f"Anything about {topic}?",
        project_id="proj-1",
        sensitivity="INTERNAL",
        candidates=(
            RecallCandidate("obj-unrelated-1", "primary", 0.50, "proj-1", "INTERNAL", matches_query=False),
            RecallCandidate("obj-unrelated-2", "secondary", 0.20, "proj-1", "PUBLIC", matches_query=False),
        ),
        expected_object_ids=(),
    )


def _deleted_superseded(query_id: str, topic: str, obj: str, *, superseded: bool) -> RecallQuery:
    """A deleted/superseded query: the matching object is under deletion veto
    or superseded, so the authoritative filter removes it -> zero returns."""
    return RecallQuery(
        query_id=query_id,
        category=DELETED_SUPERSEDED,
        query_text=f"Recall the decision on {topic}.",
        project_id="proj-1",
        sensitivity="INTERNAL",
        candidates=(
            RecallCandidate(
                obj, "primary", 0.95, "proj-1", "INTERNAL",
                vetoed=not superseded, superseded=superseded,
            ),
        ),
        expected_object_ids=(),
    )


def _wrong_scope(query_id: str, topic: str, obj: str, *, project_id: str, sensitivity: str) -> RecallQuery:
    """A wrong-scope query: the matching object lives in a different project or
    above the query's sensitivity, so the authoritative filter removes it."""
    return RecallQuery(
        query_id=query_id,
        category=WRONG_SCOPE,
        query_text=f"Recall the note on {topic}.",
        project_id="proj-1",
        sensitivity="INTERNAL",
        candidates=(
            RecallCandidate(obj, "primary", 0.95, project_id, sensitivity),
        ),
        expected_object_ids=(),
    )


# ---------------------------------------------------------------------------
# Frozen 30-query recall corpus: 15 relevant / 5 unrelated /
# 5 deleted-superseded / 5 wrong-scope.
# ---------------------------------------------------------------------------

RECALL_CORPUS_30: tuple[RecallQuery, ...] = (
    # 15 relevant queries (gold object recallable, ranks in top-3).
    _relevant("rq_01", "the database engine choice", "obj-rel-01"),
    _relevant("rq_02", "the authentication model", "obj-rel-02"),
    _relevant("rq_03", "the caching strategy", "obj-rel-03"),
    _relevant("rq_04", "the deployment topology", "obj-rel-04"),
    _relevant("rq_05", "the rate limiting policy", "obj-rel-05"),
    _relevant("rq_06", "the logging format", "obj-rel-06"),
    _relevant("rq_07", "the error taxonomy", "obj-rel-07"),
    _relevant("rq_08", "the schema migration plan", "obj-rel-08"),
    _relevant("rq_09", "the feature flag rollout", "obj-rel-09"),
    _relevant("rq_10", "the backup schedule", "obj-rel-10"),
    _relevant("rq_11", "the API versioning scheme", "obj-rel-11"),
    _relevant("rq_12", "the observability stack", "obj-rel-12"),
    _relevant("rq_13", "the secrets management approach", "obj-rel-13"),
    _relevant("rq_14", "the testing pyramid", "obj-rel-14"),
    _relevant("rq_15", "the incident response runbook", "obj-rel-15"),
    # 5 unrelated queries (no matching candidate -> zero).
    _unrelated("rq_16", "quantum chromodynamics"),
    _unrelated("rq_17", "renaissance oil painting"),
    _unrelated("rq_18", "deep sea vent ecology"),
    _unrelated("rq_19", "medieval guild economics"),
    _unrelated("rq_20", "orbital mechanics of comets"),
    # 5 deleted/superseded queries (matching object vetoed/superseded -> zero).
    _deleted_superseded("rq_21", "the retired billing vendor", "obj-del-01", superseded=False),
    _deleted_superseded("rq_22", "the old onboarding flow", "obj-del-02", superseded=True),
    _deleted_superseded("rq_23", "the revoked API token plan", "obj-del-03", superseded=False),
    _deleted_superseded("rq_24", "the superseded pricing model", "obj-del-04", superseded=True),
    _deleted_superseded("rq_25", "the forgotten retention rule", "obj-del-05", superseded=False),
    # 5 wrong project/sensitivity queries (out of scope -> zero).
    _wrong_scope("rq_26", "the partner-only roadmap", "obj-ws-01", project_id="proj-other", sensitivity="INTERNAL"),
    _wrong_scope("rq_27", "the restricted audit finding", "obj-ws-02", project_id="proj-1", sensitivity="RESTRICTED"),
    _wrong_scope("rq_28", "the confidential payroll note", "obj-ws-03", project_id="proj-1", sensitivity="CONFIDENTIAL"),
    _wrong_scope("rq_29", "the other-team architecture", "obj-ws-04", project_id="proj-2", sensitivity="PUBLIC"),
    _wrong_scope("rq_30", "the restricted key ceremony", "obj-ws-05", project_id="proj-1", sensitivity="RESTRICTED"),
)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def run_recall_evaluation() -> RecallCorpusEval:
    """Run ``recall_top3`` over all 30 queries in ``RECALL_CORPUS_30`` and
    compute the frozen recall metrics: relevant-query Top-3 hit rate
    (``H/15 >= 0.80``) and exactly-zero forbidden returns across the unrelated,
    deleted/superseded, and wrong-scope categories."""
    results: list[RecallQueryResult] = []
    relevant_count = unrelated_count = deleted_count = wrong_scope_count = 0
    relevant_hits = 0
    forbidden_returns = 0

    for query in RECALL_CORPUS_30:
        returned = recall_top3(query)
        if query.category == RELEVANT:
            relevant_count += 1
            hit = any(obj in returned for obj in query.expected_object_ids)
            if hit:
                relevant_hits += 1
            results.append(RecallQueryResult(query.query_id, query.category, returned, hit, False))
        else:
            if query.category == UNRELATED:
                unrelated_count += 1
            elif query.category == DELETED_SUPERSEDED:
                deleted_count += 1
            elif query.category == WRONG_SCOPE:
                wrong_scope_count += 1
            forbidden = len(returned) > 0
            if forbidden:
                forbidden_returns += 1
            results.append(RecallQueryResult(query.query_id, query.category, returned, False, forbidden))

    total_queries = len(results)
    assert total_queries == 30, f"expected 30 queries, got {total_queries}"
    assert relevant_count == 15, f"expected 15 relevant, got {relevant_count}"
    assert unrelated_count == 5, f"expected 5 unrelated, got {unrelated_count}"
    assert deleted_count == 5, f"expected 5 deleted_superseded, got {deleted_count}"
    assert wrong_scope_count == 5, f"expected 5 wrong_scope, got {wrong_scope_count}"

    top3_hit_rate = relevant_hits / relevant_count
    return RecallCorpusEval(
        total_queries=total_queries,
        relevant_count=relevant_count,
        unrelated_count=unrelated_count,
        deleted_superseded_count=deleted_count,
        wrong_scope_count=wrong_scope_count,
        relevant_hits=relevant_hits,
        top3_hit_rate=top3_hit_rate,
        zero_forbidden_returns=(forbidden_returns == 0),
        results=tuple(results),
    )
