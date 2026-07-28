from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_stage3_ledger_persistence import (
    KEY_ID,
    SIGNER_REF,
    blob,
    command,
    create_and_approve,
    ref,
    request,
    signed_snapshot_signer,
    store,
    trust_for_request,
)
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority


FIXTURE = json.loads((Path(__file__).parents[1] / "fixtures/second_brain/stage3_journeys.json").read_text())


def test_capture_review_recall_returns_only_approved_synthetic_citation(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", FIXTURE["candidates"][0])
    service.append(command("CREATE_CANDIDATE", candidate, command_name="journey-capture", workspace=workspace, content_digest=blob(cas, "synthetic-capture")))
    initial_request = request(workspace)
    recall = SecondBrainRecallService(
        LifecycleLedgerAuthority(
            database,
            cas,
            trust_authority=trust_for_request(initial_request),
            snapshot_signer=signed_snapshot_signer,
            signer_ref=SIGNER_REF,
            key_id=KEY_ID,
        )
    )
    assert recall.recall(initial_request).abstained
    service.append(command("REVIEW_APPROVE", candidate, command_name="journey-review", workspace=workspace))
    approved_request = request(workspace)
    approved_recall = SecondBrainRecallService(
        LifecycleLedgerAuthority(
            database,
            cas,
            trust_authority=trust_for_request(approved_request),
            snapshot_signer=signed_snapshot_signer,
            signer_ref=SIGNER_REF,
            key_id=KEY_ID,
        )
    )
    answer = approved_recall.recall(approved_request)
    assert not answer.abstained
    assert [result.candidate_ref for result in answer.results] == [candidate]
    assert answer.results[0].citations and answer.results[0].content_digest != "synthetic-capture"
    database.close()


def test_wrong_workspace_and_capability_bindings_fail_closed(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "bound")
    create_and_approve(service, cas, candidate, "bound", workspace=workspace)
    wrong_request = request(ref("workspace", "wrong"), authorization_state="DENY")
    recall = SecondBrainRecallService(
        LifecycleLedgerAuthority(
            database,
            cas,
            trust_authority=trust_for_request(wrong_request, authorization_state="DENY"),
            snapshot_signer=signed_snapshot_signer,
            signer_ref=SIGNER_REF,
            key_id=KEY_ID,
        )
    )
    answer = recall.recall(wrong_request)
    assert answer.abstained and not answer.results
    database.close()
