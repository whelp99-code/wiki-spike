"""Search with staleness compatibility (SUB-07, v3.3 §11).

The search read model has its OWN pointer that may lag the wiki pointer. A query:
- reports indexed vs current wiki generation and a `stale` flag,
- POST-FILTERS every hit against the CURRENT wiki generation's claim resolution so
  retracted/superseded claims are never returned,
- disables results when the generation lag exceeds max_generation_lag.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .controlplane import ControlPlane


@dataclass
class SearchHit:
    claim_id: str
    subject: str
    predicate: str
    obj: str


@dataclass
class SearchResponse:
    hits: list[SearchHit] = field(default_factory=list)
    indexed_generation_id: str | None = None
    current_wiki_generation_id: str | None = None
    stale: bool = False
    disabled: bool = False


class SearchService:
    def __init__(self, cp: ControlPlane, max_generation_lag: int = 5) -> None:
        self.cp = cp
        self.max_generation_lag = max_generation_lag

    def query(self, term: str) -> SearchResponse:
        s = self.cp.current_search_pointer()
        w = self.cp.current_pointer()
        if s is None or w is None:
            return SearchResponse(indexed_generation_id=s, current_wiki_generation_id=w)

        lag = self.cp.generation_seq(w) - self.cp.generation_seq(s)
        if lag > self.max_generation_lag:
            return SearchResponse(
                indexed_generation_id=s, current_wiki_generation_id=w, stale=True, disabled=True
            )

        hits: list[SearchHit] = []
        for claim_id, subject, predicate, obj in self.cp.search_index_lookup(s, term):
            # Post-filter against the CURRENT wiki generation resolution.
            if self.cp.resolution_state(w, claim_id) == "accepted":
                hits.append(SearchHit(claim_id, subject, predicate, obj))
        return SearchResponse(
            hits=hits,
            indexed_generation_id=s,
            current_wiki_generation_id=w,
            stale=(s != w),
            disabled=False,
        )
