from __future__ import annotations

from pathlib import Path

from wiki_spike.memory_runtime.second_brain_recall import (
    RuntimeCandidateV2, RuntimeCitationV2, RuntimeConflictV2, RuntimePinnedRecallSnapshotV2,
    RuntimeRecallRequestV2, SecondBrainRecallRuntime,
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


def test_deletion_abstains_and_runtime_does_not_import_ledger_contracts():
    value = snapshot(deletion="DENY")
    assert SecondBrainRecallRuntime().recall(value, request(value)).abstained
    source = Path("src/wiki_spike/memory_runtime/second_brain_recall.py").read_text()
    assert "second_brain_ledger" not in source
