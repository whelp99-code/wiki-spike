from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path

import pytest
from test_stage3_ledger_persistence import (
    KEY_ID, NOW, SIGNER_REF, blob, canonical_ledger_bytes, canonical_ledger_digest,
    command, create_and_approve, make_recall_continuation_v2, ref, request, sign,
    signed_snapshot_signer, store, trust_for_request,
)
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_ledger_contracts import RecallSnapshotRequestV2
from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.infrastructure.second_brain_ledger import LedgerAuthorityError, LifecycleLedgerAuthority


def test_stale_snapshot_generation_and_checkpoint_are_not_reused_after_delete(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "wal-delete")
    create_and_approve(service, cas, candidate, "wal-delete", workspace=workspace)
    base = request(workspace)
    snapshot = service.acquire(base).snapshot
    body = {
        "continuation_version": "second-brain-recall-continuation-v2",
        "continuation_ref": ref("continuation", "stale"),
        "workspace_ref": workspace,
        "capability_ref": base.capability_ref,
        "authority_epoch": base.authority_epoch,
        "subject_ref": base.subject_ref,
        "action": base.action,
        "query_digest": base.query_digest,
        "scope_digest": base.scope_digest,
        "valid_at": base.valid_at,
        "recorded_at": base.recorded_at,
        "transaction_cut": snapshot.transaction_cut,
        "authority_provenance_ref": base.authority_provenance_ref,
        "authority_provenance_digest": base.authority_provenance_digest,
        "signer_ref": SIGNER_REF,
        "signer_algorithm": "Ed25519",
        "key_id": KEY_ID,
        "signature": "pending",
        "generation_ref": snapshot.generation_ref,
        "generation_digest": snapshot.generation_digest,
        "checkpoint_ref": snapshot.checkpoint_ref,
        "checkpoint_digest": snapshot.checkpoint_digest,
        "freshness_digest": snapshot.freshness_digest,
        "authority_checkpoint_digest": snapshot.authority_checkpoint_digest,
        "authority_commitment_digest": snapshot.authority_commitment_digest,
        "base_snapshot_digest": snapshot.snapshot_digest,
        "cursor_handle_ref": ref("cursor", "page-2"),
        "cursor_state_digest": canonical_ledger_digest("cursor-state-v2", {"page": "2"}),
        "issued_at": NOW,
        "expires_at": "2026-01-01T00:05:00Z",
    }
    body["signature"] = sign(canonical_ledger_bytes(
        "signed-v2", {key: value for key, value in body.items() if key != "signature"}
    ))
    continuation = make_recall_continuation_v2(body)
    stale = request(workspace, transaction_cut=snapshot.transaction_cut, continuation=continuation)
    authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(stale), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID,
    )
    service = type(service)(authority, authority)
    service.append(command("FORGET", candidate, command_name="wal-forget", workspace=workspace))
    # A fabricated cursor handle is refused by the durable cursor lookup before
    # any generation/checkpoint drift comparison can run.
    with pytest.raises(LedgerAuthorityError, match="continuation cursor is not durably resolvable"):
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
            authority = LifecycleLedgerAuthority(
                local_database, cas, trust_for_request(request(workspace)), signed_snapshot_signer,
                signer_ref=SIGNER_REF, key_id=KEY_ID,
            )
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
    assert SecondBrainRecallService(
        LifecycleLedgerAuthority(
            database, cas, trust_for_request(request(workspace)), signed_snapshot_signer,
            signer_ref=SIGNER_REF, key_id=KEY_ID,
        )
    ).recall(request(workspace)).abstained
    assert database.con.execute("SELECT COUNT(*) FROM ledger_transition WHERE candidate_ref=?", (candidate,)).fetchone()[0] == 3
    database.close()


def test_bounded_batch_serves_a_signed_continuation_that_pages_one_cut(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    left, right = sorted((ref("candidate", "page-a"), ref("candidate", "page-b")))
    create_and_approve(service, cas, ref("candidate", "page-a"), "page-a", workspace=workspace)
    create_and_approve(service, cas, ref("candidate", "page-b"), "page-b", workspace=workspace)

    def paged(value: RecallSnapshotRequestV2) -> LifecycleLedgerAuthority:
        return LifecycleLedgerAuthority(
            database, cas, trust_for_request(value), signed_snapshot_signer,
            signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
        )

    first_request = request(workspace, recorded_at=NOW)
    first_authority = paged(first_request)
    first = SecondBrainLedgerService(first_authority, first_authority).acquire(first_request).snapshot
    assert first.has_more and first.continuation is not None
    assert [item.candidate_ref for item in first.candidates] == [left]
    next_request = request(
        workspace, recorded_at=NOW, transaction_cut=first.transaction_cut, continuation=first.continuation
    )
    next_authority = paged(next_request)
    second = SecondBrainLedgerService(next_authority, next_authority).acquire(next_request).snapshot
    assert [item.candidate_ref for item in second.candidates] == [right]
    assert (second.base_snapshot_digest, second.incoming_continuation_ref) == (
        first.snapshot_digest, first.continuation.continuation_ref
    )
    assert not second.has_more and second.continuation is None
    answer = SecondBrainRecallService(next_authority).recall(next_request)
    assert not answer.abstained and [item.candidate_ref for item in answer.results] == [right]
    database.close()


def test_replayed_or_tampered_resume_cursor_is_refused(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    create_and_approve(service, cas, ref("candidate", "page-a"), "page-a", workspace=workspace)
    create_and_approve(service, cas, ref("candidate", "page-b"), "page-b", workspace=workspace)
    first_request = request(workspace, recorded_at=NOW)
    first_authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(first_request), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    first = SecondBrainLedgerService(first_authority, first_authority).acquire(first_request).snapshot
    service.append(command("REVOKE", ref("candidate", "page-b"), command_name="revoke-after-page", workspace=workspace))
    # A later writer moved the cut, so Core refuses to even build the replayed request.
    with pytest.raises(InvalidContractValue, match="continuation is not request-bound"):
        request(workspace, recorded_at=NOW, continuation=first.continuation)
    assert database.con is not None
    with pytest.raises(Exception, match="append-only"):
        database.con.execute("UPDATE ledger_recall_cursor SET after_candidate_ref='candidate:x'")
    database.con.execute("DROP TRIGGER ledger_recall_cursor_no_update")
    database.con.execute(
        "UPDATE ledger_recall_cursor SET after_candidate_ref=?", (ref("candidate", "tampered"),)
    )
    replay = request(
        workspace, recorded_at=NOW, transaction_cut=first.transaction_cut, continuation=first.continuation
    )
    replay_authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(replay), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    with pytest.raises(LedgerAuthorityError, match="continuation cursor does not bind its durable position"):
        SecondBrainLedgerService(replay_authority, replay_authority).acquire(replay)
    database.close()


def test_component_paging_serves_a_support_linked_pair_whole_with_full_support_refs(tmp_path: Path) -> None:
    """A page-size of 1 must never split a SUPPORT-linked pair: the P0 defect served
    an off-page support ref, which RecallServeSnapshotV2 rejects; component-based
    paging must instead serve both candidates whole on one terminal page."""
    database, cas, service, workspace = store(tmp_path)
    base, corrected = ref("candidate", "comp-base"), ref("candidate", "comp-corrected")
    create_and_approve(service, cas, base, "comp-base", workspace=workspace)
    create_and_approve(service, cas, corrected, "comp-corrected", workspace=workspace)
    service.append(command(
        "CORRECT", corrected, command_name="comp-correct", related=base,
        workspace=workspace, content_digest=blob(cas, "comp-corrected-v2"),
    ))
    authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(request(workspace)), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    snapshot = SecondBrainLedgerService(authority, authority).acquire(request(workspace)).snapshot
    assert not snapshot.has_more
    assert snapshot.continuation is None
    assert {item.candidate_ref for item in snapshot.candidates} == {base, corrected}
    by_ref = {item.candidate_ref: item for item in snapshot.candidates}
    assert by_ref[corrected].support_refs == (base,)
    database.close()


def test_component_paging_serves_a_contradiction_linked_pair_whole_with_conflict(tmp_path: Path) -> None:
    """A page-size of 1 must never split a CONTRADICTION-linked pair: the P1 defect
    silently dropped a straddling conflict; component-based paging must instead
    co-display both candidates whole on one terminal page with the conflict intact."""
    database, cas, service, workspace = store(tmp_path)
    left, right = ref("candidate", "conf-left"), ref("candidate", "conf-right")
    create_and_approve(service, cas, left, "conf-left", workspace=workspace)
    create_and_approve(service, cas, right, "conf-right", workspace=workspace)
    service.append(command(
        "DECLARE_CONTRADICTION", left, command_name="conf-declare", related=right, workspace=workspace,
    ))
    authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(request(workspace)), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    snapshot = SecondBrainLedgerService(authority, authority).acquire(request(workspace)).snapshot
    assert not snapshot.has_more
    assert snapshot.continuation is None
    assert {item.candidate_ref for item in snapshot.candidates} == {left, right}
    assert [(c.left_candidate_ref, c.right_candidate_ref) for c in snapshot.conflicts] == [
        tuple(sorted((left, right)))
    ]
    database.close()


def test_component_paging_serves_a_component_larger_than_page_size_whole(tmp_path: Path) -> None:
    """A three-candidate SUPPORT chain is one component; even at page_size=1 it must
    be served whole on a single terminal page rather than split or rejected."""
    database, cas, service, workspace = store(tmp_path)
    root, middle, leaf = (ref("candidate", value) for value in ("chain-root", "chain-middle", "chain-leaf"))
    for candidate, name in ((root, "chain-root"), (middle, "chain-middle"), (leaf, "chain-leaf")):
        create_and_approve(service, cas, candidate, name, workspace=workspace)
    service.append(command(
        "CORRECT", middle, command_name="chain-support-root-middle", related=root,
        workspace=workspace, content_digest=blob(cas, "chain-middle-v2"),
    ))
    service.append(command(
        "CORRECT", leaf, command_name="chain-support-middle-leaf", related=middle,
        workspace=workspace, content_digest=blob(cas, "chain-leaf-v2"),
    ))
    authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(request(workspace)), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    snapshot = SecondBrainLedgerService(authority, authority).acquire(request(workspace)).snapshot
    assert not snapshot.has_more
    assert snapshot.continuation is None
    assert {item.candidate_ref for item in snapshot.candidates} == {root, middle, leaf}
    database.close()
