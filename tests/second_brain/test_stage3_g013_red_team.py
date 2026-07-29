"""Adversarial / red-team suite for G013: bounded batch recall + satisfiable V2
continuation chain (frozen commit 091951c).

This module tries to BREAK contract obligations C1-C4, not confirm the happy
path. Every test reuses the durable fixtures exported by
``test_stage3_ledger_persistence`` so it exercises the real in-process
black-box surface: ``LifecycleLedgerAuthority`` + ``SecondBrainLedgerService``.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from test_stage3_ledger_persistence import (
    KEY_ID,
    LATER,
    NOW,
    SIGNER_REF,
    blob,
    canonical_ledger_bytes,
    canonical_ledger_digest,
    command,
    create_and_approve,
    digest,
    make_recall_continuation_v2,
    ref,
    request,
    sign,
    signed_snapshot_signer,
    store,
    trust_for_request,
)

from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.infrastructure.second_brain_ledger import (
    LedgerAuthority,
    LedgerAuthorityError,
    LifecycleLedgerAuthority,
)
from wiki_spike.memory_core.errors import InvalidContractValue


def _authority(database, cas, req, *, page_size: int = 50) -> LifecycleLedgerAuthority:
    return LifecycleLedgerAuthority(
        database, cas, trust_for_request(req), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=page_size,
    )


def _acquire(database, cas, req, *, page_size: int = 50):
    authority = _authority(database, cas, req, page_size=page_size)
    return SecondBrainLedgerService(authority, authority).acquire(req).snapshot


# ---------------------------------------------------------------------------
# C1 / C2 -- paging completeness property
# ---------------------------------------------------------------------------

def test_g013_c1_c2_full_page_walk_is_exact_partition_of_candidate_set(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    expected = set()
    for index in range(7):
        candidate = ref("candidate", f"walk-{index}")
        create_and_approve(service, cas, candidate, f"walk-{index}", workspace=workspace)
        expected.add(candidate)
    assert len(expected) == 7

    current_request = request(workspace, recorded_at=NOW)
    cut: str | None = None
    collected: list[str] = []
    pages = 0
    while True:
        snapshot = _acquire(database, cas, current_request, page_size=2)
        pages += 1
        if cut is None:
            cut = snapshot.transaction_cut
        else:
            assert snapshot.transaction_cut == cut, "continuation chain must stay bound to one cut"
        page_refs = [item.candidate_ref for item in snapshot.candidates]
        assert len(page_refs) <= 2, "no page may exceed the configured page size"
        collected.extend(page_refs)
        if not snapshot.has_more:
            assert snapshot.continuation is None, "terminal page must not carry a continuation"
            break
        assert snapshot.continuation is not None, "has_more page must carry a continuation"
        current_request = request(
            workspace, recorded_at=NOW, transaction_cut=cut, continuation=snapshot.continuation
        )
    assert pages == 4  # 7 candidates / page_size=2 -> 2,2,2,1
    assert len(collected) == len(expected) == 7
    assert collected == sorted(expected), "no duplicated and no skipped candidate across pages"
    database.close()


# ---------------------------------------------------------------------------
# C3 -- cross-workspace / cross-scope cursor theft
# ---------------------------------------------------------------------------

def test_g013_c3_stolen_cursor_handle_across_workspace_fails_closed(tmp_path: Path) -> None:
    database, cas, service, workspace_a = store(tmp_path)
    create_and_approve(service, cas, ref("candidate", "cross-a1"), "cross-a1", workspace=workspace_a)
    create_and_approve(service, cas, ref("candidate", "cross-a2"), "cross-a2", workspace=workspace_a)
    first_a = request(workspace_a, recorded_at=NOW)
    page_a = _acquire(database, cas, first_a, page_size=1)
    assert page_a.has_more and page_a.continuation is not None
    stolen = page_a.continuation  # real, durably-issued cursor for workspace A

    workspace_b = ref("workspace", "stage3-cross-b")
    _authority(database, cas, request(workspace_b, transaction_cut="1")).set_authority(
        workspace_b, LedgerAuthority(ref("capability", "stage3"), "1"), NOW
    )
    service.append(command(
        "CREATE_CANDIDATE", ref("candidate", "cross-b1"), command_name="create-cross-b1",
        workspace=workspace_b, content_digest=blob(cas, "cross-b1"), transaction_cut="1",
    ))
    service.append(command(
        "REVIEW_APPROVE", ref("candidate", "cross-b1"), command_name="approve-cross-b1",
        workspace=workspace_b, transaction_cut="2",
    ))

    b_request = request(workspace_b, recorded_at=NOW)
    body = {
        "continuation_version": "second-brain-recall-continuation-v2",
        "continuation_ref": ref("continuation", "stolen-for-b"),
        "workspace_ref": workspace_b,
        "capability_ref": b_request.capability_ref,
        "authority_epoch": b_request.authority_epoch,
        "subject_ref": b_request.subject_ref,
        "action": b_request.action,
        "query_digest": b_request.query_digest,
        "scope_digest": b_request.scope_digest,
        "valid_at": b_request.valid_at,
        "recorded_at": b_request.recorded_at,
        "transaction_cut": b_request.transaction_cut,
        "authority_provenance_ref": stolen.authority_provenance_ref,
        "authority_provenance_digest": stolen.authority_provenance_digest,
        "signer_ref": SIGNER_REF,
        "signer_algorithm": "Ed25519",
        "key_id": KEY_ID,
        "signature": "pending",
        "generation_ref": stolen.generation_ref,
        "generation_digest": stolen.generation_digest,
        "checkpoint_ref": stolen.checkpoint_ref,
        "checkpoint_digest": stolen.checkpoint_digest,
        "freshness_digest": stolen.freshness_digest,
        "authority_checkpoint_digest": stolen.authority_checkpoint_digest,
        "authority_commitment_digest": stolen.authority_commitment_digest,
        "base_snapshot_digest": page_a.snapshot_digest,
        # The actual theft: reuse A's durably-issued cursor handle + state digest verbatim.
        "cursor_handle_ref": stolen.cursor_handle_ref,
        "cursor_state_digest": stolen.cursor_state_digest,
        "issued_at": NOW,
        "expires_at": "2026-01-01T00:05:00Z",
    }
    body["signature"] = sign(canonical_ledger_bytes(
        "signed-v2", {key: value for key, value in body.items() if key != "signature"}
    ))
    forged = make_recall_continuation_v2(body)
    forged_request = request(
        workspace_b, recorded_at=NOW, transaction_cut=b_request.transaction_cut, continuation=forged
    )
    with pytest.raises(LedgerAuthorityError, match="continuation cursor is not durably resolvable"):
        _acquire(database, cas, forged_request, page_size=1)
    database.close()


def test_g013_c3_stolen_cursor_handle_with_different_scope_and_query_digest_fails_closed(tmp_path: Path) -> None:
    """Same workspace, but the caller mints a *new* request with a different declared
    query/scope digest while replaying someone else's durably-issued cursor handle."""
    database, cas, service, workspace = store(tmp_path)
    create_and_approve(service, cas, ref("candidate", "scope-a1"), "scope-a1", workspace=workspace)
    create_and_approve(service, cas, ref("candidate", "scope-a2"), "scope-a2", workspace=workspace)
    first = request(workspace, recorded_at=NOW)
    page1 = _acquire(database, cas, first, page_size=1)
    assert page1.has_more and page1.continuation is not None
    stolen = page1.continuation

    other_query_digest = digest("attacker-query")
    other_scope_digest = digest("attacker-scope")
    replay_request = request(workspace, recorded_at=NOW)
    body = {
        "continuation_version": "second-brain-recall-continuation-v2",
        "continuation_ref": ref("continuation", "scope-swap"),
        "workspace_ref": workspace,
        "capability_ref": replay_request.capability_ref,
        "authority_epoch": replay_request.authority_epoch,
        "subject_ref": replay_request.subject_ref,
        "action": replay_request.action,
        "query_digest": other_query_digest,
        "scope_digest": other_scope_digest,
        "valid_at": replay_request.valid_at,
        "recorded_at": replay_request.recorded_at,
        "transaction_cut": replay_request.transaction_cut,
        "authority_provenance_ref": stolen.authority_provenance_ref,
        "authority_provenance_digest": stolen.authority_provenance_digest,
        "signer_ref": SIGNER_REF,
        "signer_algorithm": "Ed25519",
        "key_id": KEY_ID,
        "signature": "pending",
        "generation_ref": stolen.generation_ref,
        "generation_digest": stolen.generation_digest,
        "checkpoint_ref": stolen.checkpoint_ref,
        "checkpoint_digest": stolen.checkpoint_digest,
        "freshness_digest": stolen.freshness_digest,
        "authority_checkpoint_digest": stolen.authority_checkpoint_digest,
        "authority_commitment_digest": stolen.authority_commitment_digest,
        "base_snapshot_digest": page1.snapshot_digest,
        "cursor_handle_ref": stolen.cursor_handle_ref,
        "cursor_state_digest": stolen.cursor_state_digest,
        "issued_at": NOW,
        "expires_at": "2026-01-01T00:05:00Z",
    }
    body["signature"] = sign(canonical_ledger_bytes(
        "signed-v2", {key: value for key, value in body.items() if key != "signature"}
    ))
    swapped = make_recall_continuation_v2(body)
    # Structural note: `RecallSnapshotRequestV2.__post_init__` requires the
    # continuation's own query_digest/scope_digest to *equal* the wrapping
    # request's query_digest/scope_digest bit-for-bit ("continuation is not
    # request-bound"). A different declared scope/query digest can therefore
    # never even be paired with a stolen continuation at the wire-contract
    # construction layer -- this is refused before any durable cursor lookup
    # or trust verification ever runs, which is a *stronger* fail-closed
    # guarantee than a runtime check would be.
    with pytest.raises(InvalidContractValue, match="continuation is not request-bound"):
        request(
            workspace, recorded_at=NOW, transaction_cut=replay_request.transaction_cut,
            continuation=swapped,
        )
    database.close()


# ---------------------------------------------------------------------------
# C3 -- expired continuation
# ---------------------------------------------------------------------------

def test_g013_c3_expired_continuation_is_refused(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    create_and_approve(service, cas, ref("candidate", "expire-a"), "expire-a", workspace=workspace)
    create_and_approve(service, cas, ref("candidate", "expire-b"), "expire-b", workspace=workspace)
    first = request(workspace, recorded_at=NOW)
    page1 = _acquire(database, cas, first, page_size=1)
    assert page1.has_more and page1.continuation is not None
    live = page1.continuation

    body = live.to_mapping()
    del body["continuation_digest"]
    # A window fully before the trusted clock's NOW: expires_at <= NOW.
    body["issued_at"] = "2025-12-31T23:56:00Z"
    body["expires_at"] = NOW
    body["signature"] = "pending"
    body["signature"] = sign(canonical_ledger_bytes(
        "signed-v2", {key: value for key, value in body.items() if key != "signature"}
    ))
    expired = make_recall_continuation_v2(body)
    expired_request = request(
        workspace, recorded_at=NOW, transaction_cut=live.transaction_cut, continuation=expired
    )
    with pytest.raises(InvalidContractValue, match="expired continuation cannot acquire a snapshot"):
        _acquire(database, cas, expired_request, page_size=1)
    database.close()


# ---------------------------------------------------------------------------
# C3 -- signature forgery / field tampering without a valid re-signature
# ---------------------------------------------------------------------------

def test_g013_c3_tampered_cursor_state_digest_without_resign_fails_durable_binding(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    create_and_approve(service, cas, ref("candidate", "tamper-cursor-a"), "tamper-cursor-a", workspace=workspace)
    create_and_approve(service, cas, ref("candidate", "tamper-cursor-b"), "tamper-cursor-b", workspace=workspace)
    first = request(workspace, recorded_at=NOW)
    page1 = _acquire(database, cas, first, page_size=1)
    assert page1.has_more and page1.continuation is not None
    live = page1.continuation

    body = live.to_mapping()
    del body["continuation_digest"]
    body["cursor_state_digest"] = digest("forged-cursor-state")
    # Signature intentionally NOT re-derived over the tampered body: it is
    # still the original signature bytes.
    tampered = make_recall_continuation_v2(body)
    assert tampered.signature == live.signature
    tampered_request = request(
        workspace, recorded_at=NOW, transaction_cut=live.transaction_cut, continuation=tampered
    )
    with pytest.raises(LedgerAuthorityError, match="continuation cursor is not durably resolvable"):
        _acquire(database, cas, tampered_request, page_size=1)
    database.close()


def test_g013_c3_tampered_transaction_cut_without_resign_fails_closed(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    create_and_approve(service, cas, ref("candidate", "tamper-cut-a"), "tamper-cut-a", workspace=workspace)
    create_and_approve(service, cas, ref("candidate", "tamper-cut-b"), "tamper-cut-b", workspace=workspace)
    first = request(workspace, recorded_at=NOW)
    page1 = _acquire(database, cas, first, page_size=1)
    assert page1.has_more and page1.continuation is not None
    live = page1.continuation

    body = live.to_mapping()
    del body["continuation_digest"]
    forged_cut = str(int(live.transaction_cut) + 1)
    body["transaction_cut"] = forged_cut
    # Signature intentionally stale relative to the mutated body.
    tampered = make_recall_continuation_v2(body)
    tampered_request = request(
        workspace, recorded_at=NOW, transaction_cut=forged_cut, continuation=tampered
    )
    with pytest.raises(LedgerAuthorityError):
        _acquire(database, cas, tampered_request, page_size=1)
    database.close()


def test_g013_c3_tampered_untethered_field_without_resign_fails_signature_verification(tmp_path: Path) -> None:
    """Mutate a field that neither the durable cursor lookup nor the request-binding
    check inspects, so the only remaining guard is cryptographic signature
    verification -- and it must still refuse the forged continuation."""
    database, cas, service, workspace = store(tmp_path)
    create_and_approve(service, cas, ref("candidate", "tamper-sig-a"), "tamper-sig-a", workspace=workspace)
    create_and_approve(service, cas, ref("candidate", "tamper-sig-b"), "tamper-sig-b", workspace=workspace)
    first = request(workspace, recorded_at=NOW)
    page1 = _acquire(database, cas, first, page_size=1)
    assert page1.has_more and page1.continuation is not None
    live = page1.continuation

    body = live.to_mapping()
    del body["continuation_digest"]
    body["authority_checkpoint_digest"] = digest("forged-authority-checkpoint")
    # Signature intentionally NOT re-derived: still the original bytes.
    tampered = make_recall_continuation_v2(body)
    assert tampered.signature == live.signature
    tampered_request = request(
        workspace, recorded_at=NOW, transaction_cut=live.transaction_cut, continuation=tampered
    )
    with pytest.raises(InvalidContractValue, match="continuation signature verification failed"):
        _acquire(database, cas, tampered_request, page_size=1)
    database.close()


# ---------------------------------------------------------------------------
# C1 -- page-size boundary
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_page_size", [0, 501, True, "2"])
def test_g013_c1_page_size_construction_boundaries_are_rejected(tmp_path: Path, bad_page_size) -> None:
    database, cas, service, workspace = store(tmp_path)
    with pytest.raises(LedgerAuthorityError, match="recall page size must be a bounded positive batch"):
        _authority(database, cas, request(workspace), page_size=bad_page_size)
    database.close()


def test_g013_c1_page_size_exactly_equal_to_candidate_count_is_terminal(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    refs = set()
    for index in range(3):
        candidate = ref("candidate", f"exact-{index}")
        create_and_approve(service, cas, candidate, f"exact-{index}", workspace=workspace)
        refs.add(candidate)
    snapshot = _acquire(database, cas, request(workspace, recorded_at=NOW), page_size=3)
    assert not snapshot.has_more
    assert snapshot.continuation is None
    assert {item.candidate_ref for item in snapshot.candidates} == refs
    database.close()


# ---------------------------------------------------------------------------
# C4 -- durable citations
# ---------------------------------------------------------------------------

def test_g013_c4_every_served_candidate_carries_exactly_one_bound_citation(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    refs = []
    for index in range(3):
        candidate = ref("candidate", f"cited-{index}")
        create_and_approve(service, cas, candidate, f"cited-{index}", workspace=workspace)
        refs.append(candidate)
    snapshot = _acquire(database, cas, request(workspace, recorded_at=NOW), page_size=10)
    assert len(snapshot.candidates) == len(snapshot.citations) == 3
    candidate_by_ref = {item.candidate_ref: item for item in snapshot.candidates}
    citation_by_ref = {item.candidate_ref: item for item in snapshot.citations}
    assert candidate_by_ref.keys() == citation_by_ref.keys() == set(refs)
    for candidate_ref, candidate in candidate_by_ref.items():
        citation = citation_by_ref[candidate_ref]
        assert citation.evidence.revision_ref == candidate.revision_ref
        assert citation.evidence.immutable_source_ref == "source:" + candidate.content_digest
    database.close()


def test_g013_c4_tampered_citation_commitment_is_never_served(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "citation-tamper")
    create_and_approve(service, cas, candidate, "citation-tamper", workspace=workspace)
    assert _acquire(database, cas, request(workspace), page_size=10).citations
    assert database.con is not None
    database.con.execute("DROP TRIGGER ledger_citation_commitment_no_update")
    database.con.execute(
        "UPDATE ledger_citation_commitment SET locator_ref=?", ("locator:" + digest("g013-forged"),)
    )
    with pytest.raises(LedgerAuthorityError, match="durable citation commitment failed revalidation"):
        _acquire(database, cas, request(workspace), page_size=10)
    database.close()


# ---------------------------------------------------------------------------
# C2 / C3 -- deletion during an in-flight paging chain
# ---------------------------------------------------------------------------

def test_g013_c2_c3_deletion_between_pages_is_observed_and_reported(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    refs = []
    for index in range(4):
        candidate = ref("candidate", f"pagedel-{index}")
        create_and_approve(service, cas, candidate, f"pagedel-{index}", workspace=workspace)
        refs.append(candidate)
    refs.sort()

    first = request(workspace, recorded_at=NOW)
    page1 = _acquire(database, cas, first, page_size=2)
    assert page1.has_more and page1.continuation is not None
    assert [item.candidate_ref for item in page1.candidates] == refs[:2]

    victim = refs[2]  # first candidate that would appear on page 2
    service.append(command("REVOKE", victim, command_name="revoke-mid-page", workspace=workspace))

    next_request = request(
        workspace, recorded_at=NOW, transaction_cut=page1.transaction_cut, continuation=page1.continuation
    )
    try:
        page2 = _acquire(database, cas, next_request, page_size=2)
    except LedgerAuthorityError:
        # Fail-closed outcome: the in-flight continuation was invalidated by
        # the later mutation rather than serving a stale/mixed view.
        outcome = "fail_closed"
    else:
        served_refs = {item.candidate_ref for item in page2.candidates}
        outcome = "served" if victim in served_refs else "served_without_victim"
        # Whichever it is, the revoked candidate must never leak with an
        # APPROVED/undeleted state if it is served at all -- it may only
        # legitimately reappear because the continuation is durably pinned to
        # the pre-revoke transaction cut (a point-in-time read), which is a
        # documented Stage-3 invariant (see
        # test_wal_snapshot_continuation_is_bound_to_one_cut_despite_later_writer).
        if victim in served_refs:
            pinned = {item.candidate_ref: item.state for item in page2.candidates}
            assert pinned[victim] == "APPROVED"
            assert page2.transaction_cut == page1.transaction_cut, (
                "victim was only served because the page is pinned to the pre-revoke cut"
            )
    assert outcome in {"fail_closed", "served", "served_without_victim"}
    database.close()
