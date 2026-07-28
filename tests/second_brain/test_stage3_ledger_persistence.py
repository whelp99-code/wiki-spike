from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from test_stage1_capabilities import authority as security_authority

from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, fixture_capture_database
from wiki_spike.infrastructure.second_brain_ledger import (
    LedgerAuthority,
    LedgerAuthorityError,
    LifecycleLedgerAuthority,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    AuthorityProvenanceV2,
    GateStateV2,
    LedgerCommandV2,
    RecallSnapshotRequestV2,
    RecallTrustVerifierV2,
    canonical_ledger_bytes,
    canonical_ledger_digest,
    make_recall_continuation_v2,
    mint_recall_trust_authority_v2,
)


NOW = "2026-01-01T00:00:00Z"
LATER = "2026-01-02T00:00:00Z"


def digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def ref(kind: str, value: str) -> str:
    return f"{kind}:{digest(value)}"


_ACTIVE_REVISIONS: dict[str, str] = {}
_CURRENT_CUT = "1"
_COMMAND_PROVENANCE: dict[str, AuthorityProvenanceV2] = {}


class TrackingLedgerService(SecondBrainLedgerService):
    def append(self, ledger_command: LedgerCommandV2):
        item = _COMMAND_PROVENANCE[ledger_command.authority_provenance_ref]
        self._ledger._trust_authority.register_verified_provenance(item)
        receipt = super().append(ledger_command)
        global _CURRENT_CUT
        _ACTIVE_REVISIONS[ledger_command.payload.candidate_ref] = (
            "revision:"
            + sha256(
                (ledger_command.command_ref + ledger_command.command_digest).encode()
            ).hexdigest()
        )
        _CURRENT_CUT = receipt.transaction_cut
        return receipt

_SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
SIGNER_REF = ref("signer", "stage3-fixture")
KEY_ID = ref("key", "stage3-fixture")


class DeterministicEd25519Verifier(RecallTrustVerifierV2):
    def verify_signed_bytes(self, *, signer_ref: str, algorithm: str, key_id: str, signature: str, payload: bytes) -> bool:
        if (signer_ref, algorithm, key_id) != (SIGNER_REF, "Ed25519", KEY_ID):
            return False
        try:
            _SIGNING_KEY.public_key().verify(urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), payload)
        except (InvalidSignature, ValueError):
            return False
        return True


def sign(payload: bytes) -> str:
    return urlsafe_b64encode(_SIGNING_KEY.sign(payload)).rstrip(b"=").decode()


def provenance(*, provenance_ref: str, workspace: str, action: str, transaction_cut: str, query_digest: str | None, scope_digest: str | None, request_digest: str | None, command_payload_digest: str | None, authority_epoch: str = "1", authorization_state: str = "PASS") -> AuthorityProvenanceV2:
    states = (GateStateV2(authorization_state, "1", digest("gate-1")),) + tuple(
        GateStateV2("PASS", "1", digest(f"gate-{index}")) for index in range(2, 9)
    )
    unsigned = {
        "provenance_version": "second-brain-authority-provenance-v2",
        "provenance_ref": provenance_ref,
        "signer_ref": SIGNER_REF,
        "signer_algorithm": "Ed25519",
        "key_id": KEY_ID,
        "component_labels": ["authorization", "global_floor", "binding", "recovery", "route", "cohort", "deletion", "consent"],
        "component_states": [state.to_mapping() for state in states],
        "transaction_cut": transaction_cut,
        "issued_at": "2025-12-31T00:00:00Z",
        "expires_at": "2026-01-04T00:00:00Z",
        "workspace_ref": workspace,
        "capability_ref": ref("capability", "stage3"),
        "authority_epoch": authority_epoch,
        "subject_ref": ref("subject", "stage3"),
        "action": action,
        "query_digest": query_digest,
        "scope_digest": scope_digest,
        "request_digest": request_digest,
        "command_payload_digest": command_payload_digest,
    }
    bound = canonical_ledger_digest("authority-provenance-v2", unsigned)
    return AuthorityProvenanceV2.from_mapping(unsigned | {
        "provenance_digest": bound,
        "signature": sign(canonical_ledger_bytes("signed-v2", unsigned)),
    })


def trust_for_request(value: RecallSnapshotRequestV2, *, authorization_state: str = "PASS"):
    registry: dict[str, AuthorityProvenanceV2] = {}
    candidates = [
        request(
            value.workspace_ref,
            transaction_cut=str(cut),
            authorization_state=authorization_state,
        )
        for cut in range(1, 129)
    ]
    candidates.append(value)
    for candidate in candidates:
        binding_body = {
            key: (
                candidate.continuation.to_mapping()
                if key == "continuation" and candidate.continuation
                else getattr(candidate, key)
            )
            for key in RecallSnapshotRequestV2.FIELDS
            - {"authority_provenance_ref", "authority_provenance_digest", "request_digest"}
        }
        item = provenance(
            provenance_ref=candidate.authority_provenance_ref,
            workspace=candidate.workspace_ref,
            action=candidate.action,
            transaction_cut=candidate.transaction_cut,
            query_digest=candidate.query_digest,
            scope_digest=candidate.scope_digest,
            request_digest=canonical_ledger_digest(
                "request-provenance-binding-v2", binding_body
            ),
            command_payload_digest=None,
            authorization_state=authorization_state,
        )
        if item.provenance_digest != candidate.authority_provenance_digest:
            raise AssertionError("request provenance fixture drift")
        registry[item.provenance_ref] = item
    return mint_recall_trust_authority_v2(
        security_authority(),
        DeterministicEd25519Verifier(),
        lambda: NOW,
        registry,
    )


def signed_snapshot_signer(payload: bytes) -> str:
    return sign(payload)

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
    transaction_cut: str | None = None,
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
    payload_digest = canonical_ledger_digest("command-payload-v2", payload)
    provenance_ref = ref("provenance", f"command-{command_name}")
    body = {
        "command_version": "second-brain-ledger-command-v2",
        "command_ref": ref("command", command_name),
        "workspace_ref": workspace,
        "capability_ref": ref("capability", "stage3"),
        "authority_epoch": epoch,
        "subject_ref": ref("subject", "stage3"),
        "action": "WRITE",
        "scope_digest": digest("scope"),
        "kind": kind,
        "target_candidate_ref": None if kind == "CREATE_CANDIDATE" else candidate,
        "expected_active_revision_ref": None if kind == "CREATE_CANDIDATE" else _ACTIVE_REVISIONS[candidate],
        "related_candidate_refs": [] if related is None else [related],
        "interval": {"valid_from": NOW, "valid_to": None, "recorded_from": recorded_at, "recorded_to": None},
        "payload": payload,
        "command_payload_digest": payload_digest,
    }
    provenance_ref = ref("provenance", f"command-{command_name}")
    binding = canonical_ledger_digest("command-provenance-binding-v2", body)
    item = provenance(
        provenance_ref=provenance_ref,
        workspace=workspace,
        action="WRITE",
        transaction_cut=transaction_cut or _CURRENT_CUT,
        query_digest=None,
        scope_digest=digest("scope"),
        request_digest=None,
        command_payload_digest=binding,
        authority_epoch=epoch,
    )
    _COMMAND_PROVENANCE[provenance_ref] = item
    body["authority_provenance_ref"] = provenance_ref
    body["authority_provenance_digest"] = item.provenance_digest
    return LedgerCommandV2.from_mapping(body | {"command_digest": canonical_ledger_digest("command-v2", body)})


def request(workspace: str, *, epoch: str = "1", transaction_cut: str | None = None, continuation=None, authorization_state: str = "PASS", recorded_at: str = LATER) -> RecallSnapshotRequestV2:
    transaction_cut = transaction_cut or _CURRENT_CUT
    body = {
        "request_version": "second-brain-recall-snapshot-request-v2",
        "workspace_ref": workspace,
        "capability_ref": ref("capability", "stage3"),
        "authority_epoch": epoch,
        "subject_ref": ref("subject", "stage3"),
        "action": "RECALL",
        "query_digest": digest("query"),
        "valid_at": NOW,
        "recorded_at": recorded_at,
        "scope_digest": digest("scope"),
        "transaction_cut": transaction_cut,
        "authority_provenance_ref": ref("provenance", f"request-stage3-{transaction_cut}" if continuation is None else f"request-stage3-{continuation.continuation_ref}"),
        "authority_provenance_digest": digest("placeholder"),
        "continuation": None if continuation is None else continuation.to_mapping(),
    }
    unsigned = RecallSnapshotRequestV2.from_mapping(body | {"request_digest": canonical_ledger_digest("request-v2", body)})
    binding_body = {
        key: (
            unsigned.continuation.to_mapping()
            if key == "continuation" and unsigned.continuation is not None
            else getattr(unsigned, key)
        )
        for key in RecallSnapshotRequestV2.FIELDS - {"authority_provenance_ref", "authority_provenance_digest", "request_digest"}
    }
    item = provenance(
        provenance_ref=unsigned.authority_provenance_ref,
        workspace=workspace,
        action=unsigned.action,
        transaction_cut=transaction_cut,
        query_digest=unsigned.query_digest,
        scope_digest=unsigned.scope_digest,
        request_digest=canonical_ledger_digest("request-provenance-binding-v2", binding_body),
        command_payload_digest=None,
        authorization_state=authorization_state,
    )
    body["authority_provenance_digest"] = item.provenance_digest
    return RecallSnapshotRequestV2.from_mapping(body | {"request_digest": canonical_ledger_digest("request-v2", body)})


def store(tmp_path: Path) -> tuple[LifecycleDatabase, EncryptedContentStore, SecondBrainLedgerService, str]:
    _ACTIVE_REVISIONS.clear()
    _COMMAND_PROVENANCE.clear()
    global _CURRENT_CUT
    _CURRENT_CUT = "1"
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    workspace = ref("workspace", "stage3")
    trusted_request = request(workspace)
    authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(trusted_request), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID,
    )
    authority.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), NOW)
    return database, cas, TrackingLedgerService(authority, authority), workspace


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
        ledger = LifecycleLedgerAuthority(
            reopened, cas, trust_for_request(request(workspace)), signed_snapshot_signer,
            signer_ref=SIGNER_REF, key_id=KEY_ID,
        )
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
    assert {item.candidate_ref for item in service.acquire(request(workspace)).snapshot.candidates} == {first, second, successor}
    assert database.con.execute(
        "SELECT candidate_state FROM ledger_candidate WHERE candidate_ref=?", (superseded,)
    ).fetchone()[0] == "APPROVED"
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
    assert [(conflict.left_candidate_ref, conflict.right_candidate_ref) for conflict in snapshot.conflicts] == [tuple(sorted((left, right)))]
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
    ledger = LifecycleLedgerAuthority(
        database, cas, trust_for_request(request(workspace)), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID,
    )
    ledger.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), NOW)
    service = SecondBrainLedgerService(ledger, ledger)
    before = tuple(database.con.execute("SELECT * FROM capture_receipt").fetchone())
    snapshot = service.acquire(request(workspace, transaction_cut="1")).snapshot
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
        "capability_ref": first.capability_ref,
        "authority_epoch": first.authority_epoch,
        "subject_ref": first.subject_ref,
        "action": first.action,
        "query_digest": first.query_digest,
        "scope_digest": first.scope_digest,
        "valid_at": first.valid_at,
        "recorded_at": first.recorded_at,
        "transaction_cut": first.transaction_cut,
        "authority_provenance_ref": first.authority_provenance_ref,
        "authority_provenance_digest": first.authority_provenance_digest,
        "signer_ref": SIGNER_REF,
        "signer_algorithm": "Ed25519",
        "key_id": KEY_ID,
        "signature": "pending",
        "generation_ref": first.generation_ref,
        "generation_digest": first.generation_digest,
        "checkpoint_ref": first.checkpoint_ref,
        "checkpoint_digest": first.checkpoint_digest,
        "freshness_digest": first.freshness_digest,
        "authority_checkpoint_digest": first.authority_checkpoint_digest,
        "authority_commitment_digest": first.authority_commitment_digest,
        "base_snapshot_digest": first.snapshot_digest,
        "cursor_handle_ref": ref("cursor", "next-page"),
        "cursor_state_digest": digest("next-page"),
        "issued_at": NOW,
        "expires_at": "2026-01-01T00:05:00Z",
    }
    continuation_body["signature"] = sign(canonical_ledger_bytes(
        "signed-v2", {key: value for key, value in continuation_body.items() if key != "signature"}
    ))
    continuation = make_recall_continuation_v2(continuation_body)
    continued_request = request(
        workspace, transaction_cut=first.transaction_cut, continuation=continuation
    )
    authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(continued_request), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID,
    )
    service = TrackingLedgerService(authority, authority)
    service.append(command("REVOKE", candidate, command_name="revoke-after-cut", workspace=workspace))
    # The fabricated cursor handle was never issued, so the durable cursor lookup
    # refuses the replay before any drift comparison can run.
    with pytest.raises(LedgerAuthorityError, match="continuation cursor is not durably resolvable"):
        service.acquire(continued_request)
    assert first.transaction_cut == "3"
    database.close()
def test_history_and_closure_rows_reject_direct_mutation(tmp_path: Path) -> None:
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    assert database.con is not None
    con = database.con
    con.execute(
        "INSERT INTO ledger_candidate_version VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("candidate:test", "revision:test", "workspace:test", "APPROVED", digest("body"),
         "1", NOW, None, NOW, None, "9", None, "command:test"),
    )
    con.execute(
        "INSERT INTO ledger_candidate_version_closure VALUES(?,?,?,?)",
        ("candidate:test", "revision:test", "10", LATER),
    )
    con.execute(
        "INSERT INTO ledger_edge VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("edge:test", "workspace:test", "SUPPORT", "candidate:test", "candidate:other",
         "ACTIVE", NOW, None, NOW, None, "9", None),
    )
    con.execute("INSERT INTO ledger_edge_closure VALUES(?,?,?)", ("edge:test", "10", LATER))
    for statement in (
        "UPDATE ledger_candidate_version SET candidate_state='REVOKED'",
        "DELETE FROM ledger_candidate_version",
        "UPDATE ledger_edge SET edge_state='SUPERSEDED'",
        "DELETE FROM ledger_edge",
        "UPDATE ledger_candidate_version_closure SET end_cut='11'",
        "DELETE FROM ledger_candidate_version_closure",
        "UPDATE ledger_edge_closure SET end_cut='11'",
        "DELETE FROM ledger_edge_closure",
    ):
        with pytest.raises(Exception, match="append-only"):
            con.execute(statement)
    database.close()


def test_every_served_revision_carries_a_committed_citation_bound_to_command_provenance(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "cited")
    create_and_approve(service, cas, candidate, "cited", workspace=workspace)
    assert database.con is not None
    commitments = database.con.execute(
        "SELECT candidate_ref,revision_ref,workspace_ref,content_digest,commitment_state,"
        "provenance_digest,immutable_source_ref FROM ledger_citation_commitment"
    ).fetchall()
    versions = dict(
        database.con.execute("SELECT revision_ref,content_digest FROM ledger_candidate_version")
    )
    command_provenance = {
        row[0]
        for row in database.con.execute(
            "SELECT provenance_digest FROM ledger_provenance WHERE command_ref IS NOT NULL"
        )
    }
    assert len(commitments) == len(versions) == 2
    for row in commitments:
        assert (row[0], row[2], row[4]) == (candidate, workspace, "COMMITTED")
        assert row[3] == versions[row[1]] and row[6] == "source:" + row[3]
        assert row[5] in command_provenance
    snapshot = service.acquire(request(workspace)).snapshot
    served, citation = snapshot.candidates[0], snapshot.citations[0]
    assert citation.candidate_ref == served.candidate_ref
    assert citation.evidence.revision_ref == served.revision_ref
    assert citation.evidence.immutable_source_ref == "source:" + served.content_digest
    database.close()


def test_forged_citation_commitment_is_never_served_even_when_append_only_guard_is_bypassed(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "forged-citation")
    create_and_approve(service, cas, candidate, "forged-citation", workspace=workspace)
    assert service.acquire(request(workspace)).snapshot.citations
    assert database.con is not None
    for statement in (
        "UPDATE ledger_citation_commitment SET commitment_state='REVOKED'",
        "DELETE FROM ledger_citation_commitment",
    ):
        with pytest.raises(Exception, match="append-only"):
            database.con.execute(statement)
    database.con.execute("DROP TRIGGER ledger_citation_commitment_no_update")
    database.con.execute(
        "UPDATE ledger_citation_commitment SET locator_ref=?", ("locator:" + digest("forged"),)
    )
    with pytest.raises(LedgerAuthorityError, match="durable citation commitment failed revalidation"):
        service.acquire(request(workspace))
    database.close()
