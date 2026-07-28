from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path

import pytest

from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, fixture_capture_database
from wiki_spike.infrastructure.second_brain_ledger import (
    LedgerAuthority,
    LedgerAuthorityError,
    LifecycleLedgerAuthority,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    LedgerCommandV2,
    RecallSnapshotRequestV2,
    canonical_ledger_digest,
    make_recall_continuation_v2,
)
from wiki_spike.memory_core.errors import InvalidContractValue


NOW = "2026-01-01T00:00:00Z"
LATER = "2026-01-02T00:00:00Z"


def digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def ref(kind: str, value: str) -> str:
    return f"{kind}:{digest(value)}"


def command(
    kind: str,
    candidate: str,
    *,
    command_name: str,
    related: str | None = None,
    epoch: str = "1",
    workspace: str | None = None,
    content_digest: str | None = None,
    recorded_at: str = NOW,
) -> LedgerCommandV2:
    workspace = workspace or ref("workspace", "stage3")
    prior, result = {
        "CREATE_CANDIDATE": ("ABSENT", "PENDING"),
        "REVIEW_APPROVE": ("PENDING", "APPROVED"),
        "REVIEW_REJECT": ("PENDING", "REJECTED"),
        "CORRECT": ("APPROVED", "APPROVED"),
        "SUPERSEDE": ("APPROVED", "APPROVED"),
        "REVOKE": ("APPROVED", "REVOKED"),
        "FORGET": ("APPROVED", "FORGOTTEN"),
        "DECLARE_CONTRADICTION": ("APPROVED", "APPROVED"),
    }[kind]
    edges: list[dict[str, object]] = []
    contradictions: list[dict[str, object]] = []
    if kind in {"CORRECT", "SUPERSEDE"}:
        assert related is not None
        source, target = (related, candidate) if kind == "CORRECT" else (candidate, related)
        edges.append({"edge_kind": "SUPPORT", "from_candidate_ref": source, "to_candidate_ref": target, "workspace_ref": workspace, "interval": {"valid_from": NOW, "valid_to": None, "recorded_from": recorded_at, "recorded_to": None}})
    if kind == "DECLARE_CONTRADICTION":
        assert related is not None
        contradictions.append({"edge_kind": "CONTRADICTION", "from_candidate_ref": candidate, "to_candidate_ref": related, "workspace_ref": workspace, "interval": {"valid_from": NOW, "valid_to": None, "recorded_from": recorded_at, "recorded_to": None}})
    payload = {
        "candidate_ref": candidate,
        "prior_state": prior,
        "resulting_state": result,
        "content_digest": content_digest if kind in {"CREATE_CANDIDATE", "CORRECT", "SUPERSEDE"} else None,
        "support_edges": edges,
        "contradiction_edges": contradictions,
    }
    body = {
        "command_version": "second-brain-ledger-command-v2",
        "command_ref": ref("command", command_name),
        "workspace_ref": workspace,
        "capability_ref": ref("capability", "stage3"),
        "authority_epoch": epoch,
        "kind": kind,
        "target_candidate_ref": None if kind == "CREATE_CANDIDATE" else candidate,
        "related_candidate_refs": [] if related is None else [related],
        "interval": {"valid_from": NOW, "valid_to": None, "recorded_from": recorded_at, "recorded_to": None},
        "payload": payload,
    }
    return LedgerCommandV2.from_mapping(body | {"command_digest": canonical_ledger_digest("command-v2", body)})


def request(workspace: str, *, epoch: str = "1") -> RecallSnapshotRequestV2:
    body = {"request_version": "second-brain-recall-snapshot-request-v2", "workspace_ref": workspace, "capability_ref": ref("capability", "stage3"), "authority_epoch": epoch, "query_digest": digest("query"), "valid_at": NOW, "recorded_at": LATER, "scope_digest": digest("scope"), "continuation": None}
    return RecallSnapshotRequestV2.from_mapping(body | {"request_digest": canonical_ledger_digest("request-v2", body)})


def store(tmp_path: Path) -> tuple[LifecycleDatabase, EncryptedContentStore, SecondBrainLedgerService, str]:
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    workspace = ref("workspace", "stage3")
    authority = LifecycleLedgerAuthority(database, cas)
    authority.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), NOW)
    return database, cas, SecondBrainLedgerService(authority, authority), workspace


def blob(cas: EncryptedContentStore, name: str) -> str:
    return cas.put(("\x00stage3-encrypted-" + name).encode())


def create_and_approve(service: SecondBrainLedgerService, cas: EncryptedContentStore, candidate: str, name: str, *, workspace: str) -> None:
    service.append(command("CREATE_CANDIDATE", candidate, command_name=f"create-{name}", workspace=workspace, content_digest=blob(cas, name)))
    service.append(command("REVIEW_APPROVE", candidate, command_name=f"approve-{name}", workspace=workspace))


def table_count(database: LifecycleDatabase, table: str) -> int:
    assert database.con is not None
    return database.con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_real_cas_sqlite_concurrent_and_restart_idempotency(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "concurrent")
    create = command("CREATE_CANDIDATE", candidate, command_name="concurrent-create", workspace=workspace, content_digest=blob(cas, "concurrent"))
    assert service.append(create) == service.append(create)
    database.close()

    def retry() -> str:
        reopened = LifecycleDatabase(tmp_path / "ledger.sqlite")
        reopened.initialize()
        ledger = LifecycleLedgerAuthority(reopened, cas)
        receipt = ledger.append_ledger_command(create)
        reopened.close()
        return receipt.receipt_digest

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(lambda _: retry(), range(2)))
    assert len(set(receipts)) == 1
    reopened = LifecycleDatabase(tmp_path / "ledger.sqlite")
    reopened.initialize()
    assert table_count(reopened, "ledger_command") == 1
    assert table_count(reopened, "ledger_candidate") == 1
    assert table_count(reopened, "outbox") == 1
    reopened.close()


def test_stale_epoch_and_stale_state_revision_are_rejected_without_side_effects(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "stale")
    create_and_approve(service, cas, candidate, "stale", workspace=workspace)
    with pytest.raises(LedgerAuthorityError, match="stale"):
        service.append(command("REVOKE", candidate, command_name="stale-epoch", workspace=workspace, epoch="2"))
    service.append(command("REVOKE", candidate, command_name="revoke", workspace=workspace))
    with pytest.raises(LedgerAuthorityError, match="stale"):
        service.append(command("REVOKE", candidate, command_name="stale-state", workspace=workspace))
    assert table_count(database, "ledger_transition") == 3
    assert table_count(database, "outbox") == 3
    database.close()


@pytest.mark.parametrize("failure_phase", range(1, 6))
def test_each_ledger_uow_phase_rolls_back_rows_events_and_outbox(tmp_path: Path, failure_phase: int) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", f"rollback-{failure_phase}")
    create = command("CREATE_CANDIDATE", candidate, command_name=f"rollback-{failure_phase}", workspace=workspace, content_digest=blob(cas, f"rollback-{failure_phase}"))
    # SQLite executes the ledger write as one BEGIN IMMEDIATE UoW. Interrupt it
    # at progressively later SQLite execution points: no command-visible row,
    # event, or outbox entry may survive any interrupted phase.
    remaining = [failure_phase]
    def interrupt() -> int:
        remaining[0] -= 1
        if remaining[0] <= 0:
            raise RuntimeError("injected UoW phase failure")
        return 0

    assert database.con is not None
    database.con.set_progress_handler(interrupt, 1)
    try:
        with pytest.raises(Exception):
            service.append(create)
    finally:
        database.con.set_progress_handler(None, 0)
    assert table_count(database, "ledger_command") == 0
    assert table_count(database, "ledger_transition") == 0
    assert table_count(database, "ledger_revision") == 0
    assert table_count(database, "ledger_edge") == 0
    assert table_count(database, "outbox") == 0
    database.close()


def test_all_transitions_require_explicit_review_and_preserve_correction_history(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    first, second, superseded, successor, rejected = (
        ref("candidate", value)
        for value in ("first", "second", "superseded", "successor", "rejected")
    )
    service.append(command("CREATE_CANDIDATE", first, command_name="create-first", workspace=workspace, content_digest=blob(cas, "first")))
    assert service.acquire(request(workspace)).snapshot.candidates == ()
    service.append(command("REVIEW_APPROVE", first, command_name="approve-first", workspace=workspace))
    create_and_approve(service, cas, second, "second", workspace=workspace)
    service.append(command("CORRECT", first, command_name="correct", related=second, workspace=workspace, content_digest=blob(cas, "correct")))
    create_and_approve(service, cas, superseded, "superseded", workspace=workspace)
    create_and_approve(service, cas, successor, "successor", workspace=workspace)
    service.append(command("SUPERSEDE", superseded, command_name="supersede", related=successor, workspace=workspace, content_digest=blob(cas, "supersede")))
    service.append(command("CREATE_CANDIDATE", rejected, command_name="create-rejected", workspace=workspace, content_digest=blob(cas, "rejected")))
    service.append(command("REVIEW_REJECT", rejected, command_name="reject", workspace=workspace))
    assert table_count(database, "ledger_revision") == 12
    assert database.con.execute("SELECT candidate_state FROM ledger_candidate WHERE candidate_ref=?", (rejected,)).fetchone()[0] == "REJECTED"
    assert {item.candidate_ref for item in service.acquire(request(workspace)).snapshot.candidates} == {first, second, superseded, successor}
    database.close()


def test_revoke_forget_and_deletion_veto_make_candidate_nonservable(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    revoked, forgotten = ref("candidate", "revoked"), ref("candidate", "forgotten")
    create_and_approve(service, cas, revoked, "revoked", workspace=workspace)
    create_and_approve(service, cas, forgotten, "forgotten", workspace=workspace)
    service.append(command("REVOKE", revoked, command_name="revoke", workspace=workspace))
    service.append(command("FORGET", forgotten, command_name="forget", workspace=workspace))
    snapshot = service.acquire(request(workspace)).snapshot
    assert not snapshot.candidates
    assert {row[0] for row in database.con.execute("SELECT candidate_state FROM ledger_candidate")} == {"REVOKED", "FORGOTTEN"}
    database.close()


def test_contradictions_are_co_displayed_only_for_two_approved_candidates(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    left, right = ref("candidate", "left"), ref("candidate", "right")
    create_and_approve(service, cas, left, "left", workspace=workspace)
    create_and_approve(service, cas, right, "right", workspace=workspace)
    service.append(command("DECLARE_CONTRADICTION", left, command_name="contradiction", related=right, workspace=workspace))
    snapshot = service.acquire(request(workspace)).snapshot
    assert {candidate.candidate_ref for candidate in snapshot.candidates} == {left, right}
    assert [(conflict.left_candidate_ref, conflict.right_candidate_ref) for conflict in snapshot.conflicts] == [(left, right)]
    database.close()


def test_support_reverse_bfs_is_atomic_and_rejects_cycles_self_duplicates_and_cross_workspace(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    root, middle, leaf = (ref("candidate", value) for value in ("root", "middle", "leaf"))
    for candidate, name in ((root, "root"), (middle, "middle"), (leaf, "leaf")):
        create_and_approve(service, cas, candidate, name, workspace=workspace)
    service.append(command("CORRECT", middle, command_name="support-root-middle", related=root, workspace=workspace, content_digest=blob(cas, "middle-correction")))
    service.append(command("CORRECT", leaf, command_name="support-middle-leaf", related=middle, workspace=workspace, content_digest=blob(cas, "leaf-correction")))
    with pytest.raises(Exception):
        command("CORRECT", root, command_name="self", related=root, workspace=workspace, content_digest=blob(cas, "self"))
    with pytest.raises(LedgerAuthorityError, match="cycle"):
        service.append(command("SUPERSEDE", leaf, command_name="cycle", related=root, workspace=workspace, content_digest=blob(cas, "cycle")))
    duplicate = command("CORRECT", middle, command_name="duplicate", related=root, workspace=workspace, content_digest=blob(cas, "duplicate"))
    with pytest.raises(LedgerAuthorityError, match="duplicate"):
        service.append(duplicate)
    foreign = ref("candidate", "foreign")
    with pytest.raises(LedgerAuthorityError, match="workspace|absent"):
        service.append(command("CORRECT", leaf, command_name="cross-workspace", related=foreign, workspace=workspace, content_digest=blob(cas, "foreign")))
    service.append(command("REVOKE", root, command_name="revoke-root", workspace=workspace))
    assert {row[0] for row in database.con.execute("SELECT candidate_state FROM ledger_candidate")} == {"REVOKED"}
    database.close()


def test_wal_snapshot_is_one_cut_and_stage2_capture_rows_are_never_served_or_mutated(tmp_path: Path) -> None:
    database = fixture_capture_database(tmp_path / "capture-and-ledger.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    workspace = ref("workspace", "stage3")
    database.con.execute("INSERT INTO capture_scope VALUES(?,?,?,?,?,?)", (ref("scope", "stage2"), workspace, ref("source", "stage2"), "NON_SERVING", digest("stage2"), "capture-handle"))
    database.con.execute("INSERT INTO capture_receipt VALUES(?,?,?,?,?,?,?,?)", (ref("capture", "stage2"), ref("scope", "stage2"), "1", "ACCEPTED", digest("receipt"), ref("encrypted", "one"), ref("encrypted", "two"), "capture-handle"))
    ledger = LifecycleLedgerAuthority(database, cas)
    ledger.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), NOW)
    service = SecondBrainLedgerService(ledger, ledger)
    before = tuple(database.con.execute("SELECT * FROM capture_receipt").fetchone())
    snapshot = service.acquire(request(workspace)).snapshot
    assert snapshot.candidates == () and snapshot.transaction_cut == "1"
    assert tuple(database.con.execute("SELECT * FROM capture_receipt").fetchone()) == before
    database.close()


def test_wal_snapshot_continuation_is_bound_to_one_cut_despite_later_writer(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "continuation")
    create_and_approve(service, cas, candidate, "continuation", workspace=workspace)
    first = service.acquire(request(workspace)).snapshot
    continuation_body = {
        "continuation_version": "second-brain-recall-continuation-v2",
        "continuation_ref": ref("continuation", "one"),
        "workspace_ref": workspace,
        "capability_ref": ref("capability", "stage3"),
        "authority_epoch": "1",
        "query_digest": digest("query"),
        "scope_digest": digest("scope"),
        "transaction_cut": first.transaction_cut,
        "generation_ref": first.generation_ref,
        "generation_digest": first.generation_digest,
        "checkpoint_ref": first.checkpoint_ref,
        "checkpoint_digest": first.checkpoint_digest,
        "freshness_digest": first.freshness_digest,
        "authority_checkpoint_digest": first.authority_checkpoint_digest,
        "authority_commitment_digest": first.authority_commitment_digest,
        "base_snapshot_digest": first.snapshot_digest,
        "cursor": "next-page",
        "expires_at": "2026-01-03T00:00:00Z",
    }
    continuation = make_recall_continuation_v2(continuation_body)
    body = request(workspace).to_mapping() | {"continuation": continuation.to_mapping()}
    body.pop("request_digest")
    continued_request = RecallSnapshotRequestV2.from_mapping(
        body | {"request_digest": canonical_ledger_digest("request-v2", body)}
    )
    service.append(command("REVOKE", candidate, command_name="revoke-after-cut", workspace=workspace))
    with pytest.raises(InvalidContractValue, match="continuation chain drift|continuation authority drift"):
        service.acquire(continued_request)
    assert first.transaction_cut == "2"
    database.close()
