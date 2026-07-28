from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path

import pytest
from test_stage3_ledger_persistence import LATER, NOW, blob, canonical_ledger_digest, command, create_and_approve, make_recall_continuation_v2, ref, request, store
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_ledger_contracts import RecallSnapshotRequestV2
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority


def test_stale_snapshot_generation_and_checkpoint_are_not_reused_after_delete(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "wal-delete")
    create_and_approve(service, cas, candidate, "wal-delete", workspace=workspace)
    base = request(workspace)
    snapshot = service.acquire(base).snapshot
    body = {"continuation_version": "second-brain-recall-continuation-v2", "continuation_ref": ref("continuation", "stale"), "workspace_ref": workspace, "capability_ref": base.capability_ref, "authority_epoch": base.authority_epoch, "query_digest": base.query_digest, "scope_digest": base.scope_digest, "transaction_cut": snapshot.transaction_cut, "generation_ref": snapshot.generation_ref, "generation_digest": snapshot.generation_digest, "checkpoint_ref": snapshot.checkpoint_ref, "checkpoint_digest": snapshot.checkpoint_digest, "freshness_digest": snapshot.freshness_digest, "authority_checkpoint_digest": snapshot.authority_checkpoint_digest, "authority_commitment_digest": snapshot.authority_commitment_digest, "base_snapshot_digest": snapshot.snapshot_digest, "cursor": "page-2", "expires_at": "2026-01-03T00:00:00Z"}
    continuation = make_recall_continuation_v2(body)
    raw = base.to_mapping(); raw["continuation"] = continuation.to_mapping(); raw.pop("request_digest")
    stale = RecallSnapshotRequestV2.from_mapping(raw | {"request_digest": canonical_ledger_digest("request-v2", raw)})
    service.append(command("FORGET", candidate, command_name="wal-forget", workspace=workspace))
    with pytest.raises(InvalidContractValue, match="continuation.*drift"):
        service.acquire(stale)
    database.close()


def test_concurrent_deletion_is_atomic_and_never_serves_mixed_state(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "concurrent-delete")
    create_and_approve(service, cas, candidate, "concurrent-delete", workspace=workspace)
    start = Barrier(2)

    def delete(kind: str) -> tuple[str, str]:
        local_database = None
        try:
            local_database = type(database)(tmp_path / "ledger.sqlite")
            local_database.initialize()
            authority = LifecycleLedgerAuthority(local_database, cas)
            local_service = type(service)(authority, authority)
            start.wait()
            return "committed", local_service.append(
                command(kind, candidate, command_name=f"concurrent-{kind}", workspace=workspace)
            ).receipt_digest
        except Exception as exc:
            return "rejected", type(exc).__name__
        finally:
            if local_database is not None:
                local_database.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(delete, ("FORGET", "REVOKE")))
    assert sum(outcome[0] == "committed" for outcome in outcomes) == 1
    assert sum(outcome[0] == "rejected" for outcome in outcomes) == 1
    assert SecondBrainRecallService(LifecycleLedgerAuthority(database, cas)).recall(request(workspace)).abstained
    assert database.con.execute("SELECT COUNT(*) FROM ledger_transition WHERE candidate_ref=?", (candidate,)).fetchone()[0] == 3
    database.close()
