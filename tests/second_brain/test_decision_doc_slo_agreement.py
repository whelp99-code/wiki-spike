"""Pin the DB-05 decision record against the SLO floors the code enforces.

The three-day cutover decision lowered the shadow window from 14 days to 3 and
updated ADR-0028, DB-07 and RecallSloV1, but left DB-05 stating 14. DB-05 is a
globally fatal decision, so a signed record frozen against the stale number
would have contradicted the code that validates it.

These tests read the numbers out of the prose and assert the code accepts a
record at exactly those floors and rejects one below them, so the document and
the validator cannot drift apart again.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from wiki_spike.memory_core.contracts import InvalidContractValue
from wiki_spike.memory_core.second_brain_evaluation_contracts import (
    RECALL_SLO_V1,
    RecallSloV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest

DB05 = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "product"
    / "decisions"
    / "DB-05-benchmark-governance.md"
)

CLAIM = re.compile(
    r"at least (?P<days>\d+) full shadow days, "
    r"at least (?P<parity>\d+) independently labeled parity cases per active source, "
    r"at least (?P<e2e>\d+) cohort E2E queries, "
    r"(?P<confidence>one-sided 95% Wilson) bounds"
)


def documented() -> dict[str, int | str]:
    match = CLAIM.search(DB05.read_text(encoding="utf-8"))
    assert match, "DB-05 no longer states its cutover minima in the expected form"
    return {
        "min_shadow_days": int(match["days"]),
        "min_parity_cases_per_source": int(match["parity"]),
        "min_cohort_e2e_queries": int(match["e2e"]),
        "confidence_method": match["confidence"],
    }


def slo_mapping(**overrides) -> dict[str, object]:
    body = {
        "slo_version": RECALL_SLO_V1,
        "parity_min_bps": 9000,
        "citation_min_bps": 9000,
        "completeness_min_bps": 9000,
        "availability_min_bps": 9000,
        "max_safety_violations": 0,
        "min_shadow_days": 3,
        "min_parity_cases_per_source": 200,
        "min_cohort_e2e_queries": 500,
        "confidence_method": "one-sided-wilson-95",
        "include_invalid_in_denominator": True,
        "include_abstained_in_denominator": True,
        "include_source_unavailable_in_denominator": True,
    }
    body.update(overrides)
    digest = canonical_ledger_digest("recall-slo-v1", body)
    return {**body, "slo_digest": digest}


@pytest.mark.parametrize(
    "field", ["min_shadow_days", "min_parity_cases_per_source", "min_cohort_e2e_queries"]
)
def test_documented_minimum_is_exactly_the_enforced_floor(field):
    floor = documented()[field]
    assert isinstance(floor, int)
    # Accepted at the documented floor.
    accepted = RecallSloV1.from_mapping(slo_mapping(**{field: floor}))
    assert getattr(accepted, field) == floor
    # Rejected one below it, which is what makes it a floor rather than a hint.
    with pytest.raises(InvalidContractValue):
        RecallSloV1.from_mapping(slo_mapping(**{field: floor - 1}))


def test_documented_confidence_method_is_the_only_one_accepted():
    assert documented()["confidence_method"] == "one-sided 95% Wilson"
    assert RecallSloV1.from_mapping(slo_mapping()).confidence_method == "one-sided-wilson-95"
    with pytest.raises(InvalidContractValue):
        RecallSloV1.from_mapping(slo_mapping(confidence_method="two-sided-wilson-95"))


def test_db05_no_longer_states_the_superseded_fourteen_day_window():
    text = DB05.read_text(encoding="utf-8")
    assert "at least 14 full shadow days" not in text
    # The prose may explain the reduction; it must not restate 14 as a requirement.
    assert "14 days to 3" in text
