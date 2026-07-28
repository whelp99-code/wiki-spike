from __future__ import annotations

from pathlib import Path

from test_stage3_ledger_persistence import blob, command, create_and_approve, ref, request, store
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority


def test_correction_preserves_provenance_while_supersession_changes_recall(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    recall = SecondBrainRecallService(LifecycleLedgerAuthority(database, cas))
    original, correction = ref("candidate", "original"), ref("candidate", "correction")
    create_and_approve(service, cas, original, "original", workspace=workspace)
    create_and_approve(service, cas, correction, "correction", workspace=workspace)
    service.append(command("SUPERSEDE", original, command_name="journey-supersede", related=correction, workspace=workspace, content_digest=blob(cas, "supersession")))
    answer = recall.recall(request(workspace))
    assert [item.candidate_ref for item in answer.results] == [correction]
    assert database.con.execute("SELECT COUNT(*) FROM ledger_revision WHERE candidate_ref=?", (original,)).fetchone()[0] == 3
    database.close()


def test_forget_is_non_disclosing_after_restart(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "forgotten")
    create_and_approve(service, cas, candidate, "forgotten", workspace=workspace)
    service.append(command("FORGET", candidate, command_name="journey-forget", workspace=workspace))
    database.close()
    from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
    from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority
    from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
    reopened = LifecycleDatabase(tmp_path / "ledger.sqlite"); reopened.initialize()
    recalled = SecondBrainLedgerService(LifecycleLedgerAuthority(reopened, cas), LifecycleLedgerAuthority(reopened, cas)).acquire(request(workspace)).snapshot
    assert candidate not in {item.candidate_ref for item in recalled.candidates}
    assert "forgotten" not in str(recalled).lower()
    reopened.close()
