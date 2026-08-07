"""DB-04 requirement 1: the user-facing surface for conflict presentation.

Each scene below is rendered to an immutable golden sample under
artifacts/product-release/second-brain-v1/ux/. The goldens are the UX evidence
the signed DB-04 record binds, so a drifting renderer fails here rather than
silently changing what the decision was signed against.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from wiki_spike.memory_runtime.second_brain_recall import (
    RuntimeCandidateV2, RuntimeCitationV2, RuntimeConflictV2,
    RuntimePinnedRecallSnapshotV2, RuntimeRecallRequestV2, SecondBrainRecallRuntime,
)
from wiki_spike.ui.recall_conflict_view import render_recall_answer

D = "a" * 64
A, B, C = "candidate:" + "b" * 64, "candidate:" + "c" * 64, "candidate:" + "f" * 64
GOLDEN_DIR = Path("artifacts/product-release/second-brain-v1/ux")


def _snapshot(*, candidates=(), citations=(), conflicts=()):
    return RuntimePinnedRecallSnapshotV2(
        D, "workspace:" + D, "capability:" + D, "1", D, "1", "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z", D, "generation:" + D, D, "checkpoint:" + D, D, D, D,
        "ALLOW", "PASS", "PASS", "PASS", "PASS", "PASS", "PASS", "PASS",
        candidates, conflicts, citations,
    )


def _request(value):
    return RuntimeRecallRequestV2(value.snapshot_digest, value.workspace_ref, value.capability_ref,
        value.authority_epoch, value.query_digest, value.valid_at, value.recorded_at, value.scope_digest)


def _open_conflict_with_clear_winner():
    return _snapshot(
        candidates=(RuntimeCandidateV2(A, "revision:" + D, "APPROVED", D, (B, "candidate:" + "e" * 64)),
                    RuntimeCandidateV2(B, "revision:" + "d" * 64, "APPROVED", D, ())),
        citations=(RuntimeCitationV2(A, "source:" + D, D), RuntimeCitationV2(B, "source:" + "d" * 64, D)),
        conflicts=(RuntimeConflictV2(A, B, "OPEN"),))


def _resolved_conflict():
    return _snapshot(
        candidates=(RuntimeCandidateV2(A, "revision:" + D, "APPROVED", D, (B,)),
                    RuntimeCandidateV2(B, "revision:" + "d" * 64, "APPROVED", D, ())),
        citations=(RuntimeCitationV2(A, "source:" + D, D), RuntimeCitationV2(B, "source:" + "d" * 64, D)),
        conflicts=(RuntimeConflictV2(A, B, "RESOLVED"),))


def _uncited_counterpart():
    return _snapshot(
        candidates=(RuntimeCandidateV2(A, "revision:" + D, "APPROVED", D, ()),
                    RuntimeCandidateV2(C, "revision:" + "d" * 64, "APPROVED", D, ())),
        citations=(RuntimeCitationV2(A, "source:" + D, D),),
        conflicts=(RuntimeConflictV2(A, C, "OPEN"),))


def _equal_support_conflict():
    return _snapshot(
        candidates=(RuntimeCandidateV2(A, "revision:" + D, "APPROVED", D, ()),
                    RuntimeCandidateV2(B, "revision:" + "d" * 64, "APPROVED", D, ())),
        citations=(RuntimeCitationV2(A, "source:" + D, D), RuntimeCitationV2(B, "source:" + "d" * 64, D)),
        conflicts=(RuntimeConflictV2(A, B, "OPEN"),))


def _nothing_approved():
    return _snapshot(candidates=(RuntimeCandidateV2(A, "revision:" + D, "PENDING", D, ()),),
                     citations=(RuntimeCitationV2(A, "source:" + D, D),))


def _no_citation_evidence():
    return _snapshot(candidates=(RuntimeCandidateV2(A, "revision:" + D, "APPROVED", D, ()),))


SCENES = {
    "winner-with-retained-contrary-evidence": _open_conflict_with_clear_winner,
    "superseded-evidence-remains-visible": _resolved_conflict,
    "contested-result-with-uncited-counterpart": _uncited_counterpart,
    "abstention-equal-support-conflict": _equal_support_conflict,
    "abstention-no-approved-candidate": _nothing_approved,
    "abstention-no-citation-evidence": _no_citation_evidence,
}


def render(name: str) -> str:
    value = SCENES[name]()
    return render_recall_answer(SecondBrainRecallRuntime().recall(value, _request(value)))


@pytest.mark.parametrize("name", sorted(SCENES))
def test_rendered_scene_matches_its_golden_ux_sample(name: str):
    assert render(name) == (GOLDEN_DIR / f"{name}.txt").read_text(encoding="utf-8")


def test_winner_is_marked_and_the_evidence_it_beat_stays_on_screen():
    text = render("winner-with-retained-contrary-evidence")
    assert "WINNER OF AN OPEN CONFLICT" in text
    assert "contrary evidence it was ranked above (retained, not erased):" in text
    assert B in text


def test_superseded_side_stays_visible_and_neither_side_is_crowned():
    text = render("superseded-evidence-remains-visible")
    assert "WINNER" not in text
    assert A in text and B in text


def test_contested_result_is_never_presented_as_unopposed():
    text = render("contested-result-with-uncited-counterpart")
    assert "conflicting approved candidates withheld for missing citations:" in text
    assert "this result is contested; it is not an unopposed answer" in text
    assert C in text


@pytest.mark.parametrize("name,reason", [
    ("abstention-equal-support-conflict", "conflict"),
    ("abstention-no-approved-candidate", "approval_verification"),
    ("abstention-no-citation-evidence", "citation_verification"),
])
def test_abstention_states_name_a_distinct_reason_and_serve_nothing(name: str, reason: str):
    text = render(name)
    assert "ABSTAINED - no winner was selected and no result is served" in text
    assert f"reason: {reason}" in text
    assert "WINNER" not in text


def test_every_abstention_reason_the_runtime_can_emit_is_explained():
    from wiki_spike.ui.recall_conflict_view import _ABSTENTION_REASONS
    source = Path("src/wiki_spike/memory_runtime/second_brain_recall.py").read_text(encoding="utf-8")
    emitted = {line.split('True, "')[1].split('"')[0]
               for line in source.splitlines() if 'RuntimeRecallAnswerV2((), True, "' in line}
    assert emitted and emitted <= set(_ABSTENTION_REASONS)
