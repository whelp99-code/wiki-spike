from __future__ import annotations

from dataclasses import replace

from pathlib import Path

from wiki_spike.memory_runtime.second_brain_recall import (
    RuntimeCandidateV2, RuntimeCitationV2, RuntimeConflictV2, RuntimeContinuationV2,
    RuntimePinnedRecallSnapshotV2, RuntimeRecallRequestV2, SecondBrainRecallRuntime,
)

D = "a" * 64


def snapshot(*, candidates=(), citations=(), conflicts=(), deletion="PASS", recorded_at="2026-01-01T00:00:00Z"):
    return RuntimePinnedRecallSnapshotV2(
        D, "workspace:" + D, "capability:" + D, "1", D, "1", "2026-01-01T00:00:00Z",
        recorded_at, D, "generation:" + D, D, "checkpoint:" + D, D, D, D,
        "ALLOW", "PASS", "PASS", "PASS", "PASS", "PASS", deletion, "PASS",
        candidates, conflicts, citations,
    )


def request(value):
    return RuntimeRecallRequestV2(value.snapshot_digest, value.workspace_ref, value.capability_ref,
        value.authority_epoch, value.query_digest, value.valid_at, value.recorded_at, value.scope_digest)


def test_deterministic_multi_result_ordering_and_citations():
    a, b = "candidate:" + "b" * 64, "candidate:" + "c" * 64
    value = snapshot(candidates=(RuntimeCandidateV2(a, "revision:" + D, "APPROVED", D, (b,)), RuntimeCandidateV2(b, "revision:" + "d" * 64, "APPROVED", D, ())), citations=(RuntimeCitationV2(a, "source:" + D, D), RuntimeCitationV2(b, "source:" + "d" * 64, D)))
    answer = SecondBrainRecallRuntime().recall(value, request(value))
    assert [item.candidate_ref for item in answer.results] == [a, b]
    assert answer.results[0].citations[0].source_ref == "source:" + D


def test_open_conflict_uses_support_winner_and_codisplays_contrary_citation():
    a, b = "candidate:" + "b" * 64, "candidate:" + "c" * 64
    value = snapshot(candidates=(RuntimeCandidateV2(a, "revision:" + D, "APPROVED", D, (b, "candidate:" + "e" * 64)), RuntimeCandidateV2(b, "revision:" + "d" * 64, "APPROVED", D, ())), citations=(RuntimeCitationV2(a, "source:" + D, D), RuntimeCitationV2(b, "source:" + "d" * 64, D)), conflicts=(RuntimeConflictV2(a, b, "OPEN"),))
    answer = SecondBrainRecallRuntime().recall(value, request(value))
    assert [item.candidate_ref for item in answer.results] == [a]
    assert answer.results[0].contrary_citations[0].candidate_ref == b
def test_open_conflict_accumulates_all_contrary_citations_without_overwriting():
    winner = "candidate:" + "b" * 64
    loser_a, loser_b = "candidate:" + "c" * 64, "candidate:" + "e" * 64
    value = snapshot(
        candidates=(
            RuntimeCandidateV2(winner, "revision:" + D, "APPROVED", D, ("support:" + D, "support:" + "1" * 64)),
            RuntimeCandidateV2(loser_a, "revision:" + "d" * 64, "APPROVED", D, ()),
            RuntimeCandidateV2(loser_b, "revision:" + "f" * 64, "APPROVED", D, ()),
        ),
        citations=(
            RuntimeCitationV2(winner, "source:" + D, D),
            RuntimeCitationV2(loser_a, "source:" + "d" * 64, D),
            RuntimeCitationV2(loser_b, "source:" + "f" * 64, D),
        ),
        conflicts=(RuntimeConflictV2(winner, loser_a, "OPEN"), RuntimeConflictV2(winner, loser_b, "OPEN")),
    )
    answer = SecondBrainRecallRuntime().recall(value, request(value))
    assert [item.candidate_ref for item in answer.results] == [winner]
    assert [item.candidate_ref for item in answer.results[0].contrary_citations] == [loser_a, loser_b]




def test_deletion_abstains_and_runtime_does_not_import_ledger_contracts():
    value = snapshot(deletion="DENY")
    assert SecondBrainRecallRuntime().recall(value, request(value)).abstained
    source = Path("src/wiki_spike/memory_runtime/second_brain_recall.py").read_text()
    assert "second_brain_ledger" not in source


def test_has_more_and_continuation_are_surfaced_only_past_authorization_gating():
    a = "candidate:" + "b" * 64
    value = snapshot(candidates=(RuntimeCandidateV2(a, "revision:" + D, "APPROVED", D, ()),), citations=(RuntimeCitationV2(a, "source:" + D, D),))
    outgoing = RuntimeContinuationV2(
        "continuation:" + "e" * 64, value.workspace_ref, value.capability_ref, value.authority_epoch,
        value.query_digest, value.scope_digest, "cursor-token-next-page", "2026-01-01T00:10:00Z",
        D, value.transaction_cut, value.generation_ref, value.generation_digest,
        value.checkpoint_ref, value.checkpoint_digest, value.freshness_digest, value.authority_checkpoint_digest,
    )
    paged = replace(value, has_more=True, continuation=outgoing)
    answer = SecondBrainRecallRuntime().recall(paged, request(paged))
    assert not answer.abstained
    assert answer.has_more is True
    assert answer.continuation == outgoing

    terminal = replace(value, has_more=False, continuation=outgoing)
    terminal_answer = SecondBrainRecallRuntime().recall(terminal, request(terminal))
    assert terminal_answer.has_more is False
    assert terminal_answer.continuation is None

    # A blocked/abstained answer must never leak pagination state, even when
    # the underlying snapshot itself claims more pages exist.
    blocked = replace(value, has_more=True, continuation=outgoing, deletion="DENY")
    blocked_answer = SecondBrainRecallRuntime().recall(blocked, request(blocked))
    assert blocked_answer.abstained and blocked_answer.reason == "deletion"
    assert blocked_answer.has_more is False
    assert blocked_answer.continuation is None

# DB-04 requires the record to define behaviour for supersession, absent approval,
# withdrawn support, and unverifiable citations. The cases below pin each one.


def test_resolved_conflict_keeps_both_sides_visible_without_marking_a_winner():
    a, b = "candidate:" + "b" * 64, "candidate:" + "c" * 64
    value = snapshot(
        candidates=(RuntimeCandidateV2(a, "revision:" + D, "APPROVED", D, (b, "candidate:" + "e" * 64)),
                    RuntimeCandidateV2(b, "revision:" + "d" * 64, "APPROVED", D, ())),
        citations=(RuntimeCitationV2(a, "source:" + D, D), RuntimeCitationV2(b, "source:" + "d" * 64, D)),
        conflicts=(RuntimeConflictV2(a, b, "RESOLVED"),),
    )
    answer = SecondBrainRecallRuntime().recall(value, request(value))
    assert [item.candidate_ref for item in answer.results] == [a, b]
    assert all(item.contrary_citations == () for item in answer.results)


def test_unapproved_candidate_is_never_served_and_never_becomes_a_winner():
    approved, pending = "candidate:" + "b" * 64, "candidate:" + "c" * 64
    value = snapshot(
        candidates=(RuntimeCandidateV2(approved, "revision:" + D, "APPROVED", D, ()),
                    RuntimeCandidateV2(pending, "revision:" + "d" * 64, "PENDING", D, (approved, "candidate:" + "e" * 64))),
        citations=(RuntimeCitationV2(approved, "source:" + D, D), RuntimeCitationV2(pending, "source:" + "d" * 64, D)),
        conflicts=(RuntimeConflictV2(approved, pending, "OPEN"),),
    )
    answer = SecondBrainRecallRuntime().recall(value, request(value))
    assert [item.candidate_ref for item in answer.results] == [approved]


def test_no_approved_candidate_abstains_instead_of_serving_review_state():
    pending = "candidate:" + "b" * 64
    value = snapshot(
        candidates=(RuntimeCandidateV2(pending, "revision:" + D, "PENDING", D, ()),),
        citations=(RuntimeCitationV2(pending, "source:" + D, D),),
    )
    answer = SecondBrainRecallRuntime().recall(value, request(value))
    assert answer.abstained and answer.results == ()
    assert answer.reason == "approval_verification"


def test_withdrawn_support_producing_a_tie_abstains_instead_of_fabricating_a_winner():
    a, b = "candidate:" + "b" * 64, "candidate:" + "c" * 64
    supported = snapshot(
        candidates=(RuntimeCandidateV2(a, "revision:" + D, "APPROVED", D, ("candidate:" + "e" * 64,)),
                    RuntimeCandidateV2(b, "revision:" + "d" * 64, "APPROVED", D, ())),
        citations=(RuntimeCitationV2(a, "source:" + D, D), RuntimeCitationV2(b, "source:" + "d" * 64, D)),
        conflicts=(RuntimeConflictV2(a, b, "OPEN"),),
    )
    assert [item.candidate_ref for item in SecondBrainRecallRuntime().recall(supported, request(supported)).results] == [a]

    withdrawn = replace(supported, candidates=(RuntimeCandidateV2(a, "revision:" + D, "APPROVED", D, ()),
                                               RuntimeCandidateV2(b, "revision:" + "d" * 64, "APPROVED", D, ())))
    answer = SecondBrainRecallRuntime().recall(withdrawn, request(withdrawn))
    assert answer.abstained and answer.results == () and answer.reason == "conflict"


def test_candidate_without_citation_evidence_is_not_served():
    cited, uncited = "candidate:" + "b" * 64, "candidate:" + "c" * 64
    value = snapshot(
        candidates=(RuntimeCandidateV2(cited, "revision:" + D, "APPROVED", D, ()),
                    RuntimeCandidateV2(uncited, "revision:" + "d" * 64, "APPROVED", D, ())),
        citations=(RuntimeCitationV2(cited, "source:" + D, D),),
    )
    answer = SecondBrainRecallRuntime().recall(value, request(value))
    assert [item.candidate_ref for item in answer.results] == [cited]

    none_cited = replace(value, citations=())
    empty = SecondBrainRecallRuntime().recall(none_cited, request(none_cited))
    assert empty.abstained and empty.reason == "citation_verification"


def test_uncited_conflicting_candidate_is_surfaced_instead_of_silently_dropped():
    cited, uncited = "candidate:" + "b" * 64, "candidate:" + "c" * 64
    value = snapshot(
        candidates=(RuntimeCandidateV2(cited, "revision:" + D, "APPROVED", D, ()),
                    RuntimeCandidateV2(uncited, "revision:" + "d" * 64, "APPROVED", D, ())),
        citations=(RuntimeCitationV2(cited, "source:" + D, D),),
        conflicts=(RuntimeConflictV2(cited, uncited, "OPEN"),),
    )
    answer = SecondBrainRecallRuntime().recall(value, request(value))
    assert [item.candidate_ref for item in answer.results] == [cited]
    assert answer.results[0].contrary_citations == ()
    assert answer.results[0].unverified_conflicts == (uncited,)
    resolved = replace(value, conflicts=(RuntimeConflictV2(cited, uncited, "RESOLVED"),))
    resolved_answer = SecondBrainRecallRuntime().recall(resolved, request(resolved))
    assert resolved_answer.results[0].unverified_conflicts == (uncited,)

    unapproved = replace(value, candidates=(RuntimeCandidateV2(cited, "revision:" + D, "APPROVED", D, ()),
                                            RuntimeCandidateV2(uncited, "revision:" + "d" * 64, "PENDING", D, ())))
    review_state = SecondBrainRecallRuntime().recall(unapproved, request(unapproved))
    assert review_state.results[0].unverified_conflicts == ()
