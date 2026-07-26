"""Gate 8 recall corpus tests: frozen 30-query corpus (15/5/5/5), Top-3 hit
rate >= 0.80 on relevant queries, and exactly-zero forbidden returns.

Mirrors the Gate 6 extraction corpus test pattern.
"""
from __future__ import annotations

from wiki_spike.infrastructure.recall import (
    DELETED_SUPERSEDED,
    RECALL_CORPUS_30,
    RELEVANT,
    RELEVANT_HIT_THRESHOLD,
    UNRELATED,
    WRONG_SCOPE,
    RecallCandidate,
    RecallQuery,
    recall_top3,
    run_recall_evaluation,
)


class TestCorpusComposition:
    def test_corpus_has_30_queries(self):
        assert len(RECALL_CORPUS_30) == 30

    def test_corpus_composition_15_5_5_5(self):
        counts: dict[str, int] = {}
        for q in RECALL_CORPUS_30:
            counts[q.category] = counts.get(q.category, 0) + 1
        assert counts[RELEVANT] == 15
        assert counts[UNRELATED] == 5
        assert counts[DELETED_SUPERSEDED] == 5
        assert counts[WRONG_SCOPE] == 5

    def test_query_ids_unique(self):
        ids = [q.query_id for q in RECALL_CORPUS_30]
        assert len(ids) == len(set(ids))

    def test_relevant_queries_carry_gold_label(self):
        for q in RECALL_CORPUS_30:
            if q.category == RELEVANT:
                assert q.expected_object_ids, q.query_id
            else:
                assert q.expected_object_ids == (), q.query_id


class TestRecallEvaluation:
    def test_top3_hit_rate_meets_threshold(self):
        ev = run_recall_evaluation()
        assert ev.relevant_count == 15
        assert ev.top3_hit_rate >= RELEVANT_HIT_THRESHOLD

    def test_zero_forbidden_returns(self):
        ev = run_recall_evaluation()
        assert ev.zero_forbidden_returns is True
        for r in ev.results:
            if r.category != RELEVANT:
                assert r.returned_object_ids == (), r.query_id
                assert r.forbidden_return is False

    def test_relevant_hits_return_the_gold_object(self):
        ev = run_recall_evaluation()
        by_id = {q.query_id: q for q in RECALL_CORPUS_30}
        for r in ev.results:
            if r.category == RELEVANT and r.hit:
                gold = by_id[r.query_id].expected_object_ids
                assert any(obj in r.returned_object_ids for obj in gold)


class TestAuthoritativeFiltering:
    def _query(self, **overrides) -> RecallQuery:
        base = dict(
            query_id="q",
            category=RELEVANT,
            query_text="q",
            project_id="proj-1",
            sensitivity="INTERNAL",
        )
        base.update(overrides)
        return RecallQuery(**base)

    def test_vetoed_candidate_excluded(self):
        q = self._query(candidates=(
            RecallCandidate("vetoed", "primary", 0.9, "proj-1", "INTERNAL", vetoed=True),
        ))
        assert recall_top3(q) == ()

    def test_superseded_candidate_excluded(self):
        q = self._query(candidates=(
            RecallCandidate("old", "primary", 0.9, "proj-1", "INTERNAL", superseded=True),
        ))
        assert recall_top3(q) == ()

    def test_wrong_project_excluded(self):
        q = self._query(candidates=(
            RecallCandidate("other-proj", "primary", 0.9, "proj-other", "INTERNAL"),
        ))
        assert recall_top3(q) == ()

    def test_higher_sensitivity_excluded(self):
        q = self._query(sensitivity="INTERNAL", candidates=(
            RecallCandidate("restricted", "primary", 0.9, "proj-1", "RESTRICTED"),
        ))
        assert recall_top3(q) == ()

    def test_lower_sensitivity_allowed(self):
        q = self._query(sensitivity="INTERNAL", candidates=(
            RecallCandidate("public-ok", "primary", 0.9, "proj-1", "PUBLIC"),
        ))
        assert recall_top3(q) == ("public-ok",)

    def test_unmatched_candidate_excluded(self):
        q = self._query(candidates=(
            RecallCandidate("no-match", "primary", 0.9, "proj-1", "INTERNAL", matches_query=False),
        ))
        assert recall_top3(q) == ()

    def test_top3_ranking_channel_score_object_id(self):
        q = self._query(candidates=(
            RecallCandidate("d", "secondary", 0.99, "proj-1", "INTERNAL"),
            RecallCandidate("b", "primary", 0.50, "proj-1", "INTERNAL"),
            RecallCandidate("a", "primary", 0.50, "proj-1", "INTERNAL"),
            RecallCandidate("c", "primary", 0.70, "proj-1", "INTERNAL"),
            RecallCandidate("e", "primary", 0.10, "proj-1", "INTERNAL"),
        ))
        # channel asc (primary before secondary), then score desc, then id asc.
        assert recall_top3(q) == ("c", "a", "b")

    def test_top3_caps_at_three(self):
        q = self._query(candidates=tuple(
            RecallCandidate(f"obj-{i}", "primary", 0.5, "proj-1", "INTERNAL") for i in range(5)
        ))
        assert len(recall_top3(q)) == 3
