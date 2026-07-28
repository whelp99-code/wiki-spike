from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_stage3_ledger_persistence import blob, command, create_and_approve, ref, request, store
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority


FIXTURE = json.loads((Path(__file__).parents[1] / "fixtures/second_brain/stage3_journeys.json").read_text())


def test_capture_review_recall_returns_only_approved_synthetic_citation(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    recall = SecondBrainRecallService(LifecycleLedgerAuthority(database, cas))
    candidate = ref("candidate", FIXTURE["candidates"][0])
    service.append(command("CREATE_CANDIDATE", candidate, command_name="journey-capture", workspace=workspace, content_digest=blob(cas, "synthetic-capture")))
    assert recall.recall(request(workspace)).abstained
    service.append(command("REVIEW_APPROVE", candidate, command_name="journey-review", workspace=workspace))
    answer = recall.recall(request(workspace))
    assert not answer.abstained
    assert [result.candidate_ref for result in answer.results] == [candidate]
    assert answer.results[0].citations and answer.results[0].content_digest != "synthetic-capture"
    database.close()


def test_wrong_workspace_and_capability_bindings_fail_closed(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    recall = SecondBrainRecallService(LifecycleLedgerAuthority(database, cas))
    candidate = ref("candidate", "bound")
    create_and_approve(service, cas, candidate, "bound", workspace=workspace)
    answer = recall.recall(request(ref("workspace", "wrong")))
    assert answer.abstained and not answer.results
    database.close()
