"""Adversarial / red-team suite for G013: bounded batch recall + satisfiable V2
continuation chain (frozen commit 091951c).

This module tries to BREAK contract obligations C1-C4, not confirm the happy
path. Every test reuses the durable fixtures exported by
``test_stage3_ledger_persistence`` so it exercises the real in-process
black-box surface: ``LifecycleLedgerAuthority`` + ``SecondBrainLedgerService``.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import test_stage3_ledger_persistence as ledger_fixtures
from test_stage1_capabilities import authority as security_authority
from test_stage3_ledger_persistence import (
    KEY_ID,
    LATER,
    NOW,
    SIGNER_REF,
    DeterministicEd25519Verifier,
    TrackingLedgerService,
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
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.composition.api_v2 import CapabilityUseV2, SecondBrainApiV2
from wiki_spike.composition.second_brain_product import SecondBrainProductV2
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.second_brain_ledger import (
    LedgerAuthority,
    LedgerAuthorityError,
    LifecycleLedgerAuthority,
)
from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.second_brain_ledger_contracts import RecallContinuationV2, mint_recall_trust_authority_v2


def _authority(database, cas, req, *, page_size: int = 50) -> LifecycleLedgerAuthority:
    return LifecycleLedgerAuthority(
        database, cas, trust_for_request(req), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=page_size,
    )


def _acquire(database, cas, req, *, page_size: int = 50):
    authority = _authority(database, cas, req, page_size=page_size)
    return SecondBrainLedgerService(authority, authority).acquire(req).snapshot


def _shift(instant: str, seconds: int) -> str:
    parsed = datetime.fromisoformat(instant[:-1] + "+00:00").astimezone(timezone.utc)
    shifted = parsed + timedelta(seconds=seconds)
    return shifted.strftime("%Y-%m-%dT%H:%M:%SZ")


def _use(workspace: str, action: str, nonce: str) -> CapabilityUseV2:
    return CapabilityUseV2(
        ref("capability", "stage3"), "1", workspace, digest("scope"), action, nonce, ("citation", "recall"),
    )


def _v2_stack(database, cas, req, *, page_size: int):
    """Build one authenticated V2 product + API instance bound to req's trust set."""
    authority = _authority(database, cas, req, page_size=page_size)
    product = SecondBrainProductV2(
        authority=security_authority(),
        ledger=SecondBrainLedgerService(authority, authority),
        recall=SecondBrainRecallService(authority),
    )
    return authority, SecondBrainApiV2(product)


_FORBIDDEN_SURFACE = (
    "list", "dump", "Workspace", "McpServer", "raw_key", "derived_key", "artifact", "blob", "Gate8", "workspace_dump",
)


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


def test_g013_c1_c2_component_paged_walk_partitions_linked_and_isolated_candidates(tmp_path: Path) -> None:
    """Extends the exact-partition adversarial walk to a mixed workspace: a
    SUPPORT-linked pair, a CONTRADICTION-linked pair, and two isolated candidates.
    Component-based paging must never split a linked pair across a page boundary --
    no support ref or conflict endpoint may ever be off-page -- while the walk as a
    whole must still be an exact, non-overlapping partition of the workspace, and
    the one declared contradiction must surface in exactly one page."""
    database, cas, service, workspace = store(tmp_path)
    support_base, support_corrected = ref("candidate", "mix-support-base"), ref("candidate", "mix-support-corrected")
    conflict_left, conflict_right = ref("candidate", "mix-conflict-left"), ref("candidate", "mix-conflict-right")
    isolated_a, isolated_b = ref("candidate", "mix-isolated-a"), ref("candidate", "mix-isolated-b")
    for candidate, name in (
        (support_base, "mix-support-base"), (support_corrected, "mix-support-corrected"),
        (conflict_left, "mix-conflict-left"), (conflict_right, "mix-conflict-right"),
        (isolated_a, "mix-isolated-a"), (isolated_b, "mix-isolated-b"),
    ):
        create_and_approve(service, cas, candidate, name, workspace=workspace)
    service.append(command(
        "CORRECT", support_corrected, command_name="mix-correct", related=support_base,
        workspace=workspace, content_digest=blob(cas, "mix-support-corrected-v2"),
    ))
    service.append(command(
        "DECLARE_CONTRADICTION", conflict_left, command_name="mix-declare",
        related=conflict_right, workspace=workspace,
    ))
    expected = {support_base, support_corrected, conflict_left, conflict_right, isolated_a, isolated_b}
    assert len(expected) == 6

    current_request = request(workspace, recorded_at=NOW)
    cut: str | None = None
    collected: list[str] = []
    support_refs_by_ref: dict[str, tuple[str, ...]] = {}
    seen_conflicts: list[tuple[str, str]] = []
    pages = 0
    while True:
        snapshot = _acquire(database, cas, current_request, page_size=2)
        pages += 1
        if cut is None:
            cut = snapshot.transaction_cut
        else:
            assert snapshot.transaction_cut == cut, "continuation chain must stay bound to one cut"
        page_refs = [item.candidate_ref for item in snapshot.candidates]
        page_displayed = set(page_refs)
        assert 1 <= len(page_refs) <= 2, "no component in this workspace exceeds page_size"
        for item in snapshot.candidates:
            assert set(item.support_refs) <= page_displayed, "support ref must never be off-page"
            support_refs_by_ref[item.candidate_ref] = item.support_refs
        for conflict in snapshot.conflicts:
            assert conflict.left_candidate_ref in page_displayed
            assert conflict.right_candidate_ref in page_displayed
            seen_conflicts.append((conflict.left_candidate_ref, conflict.right_candidate_ref))
        collected.extend(page_refs)
        if not snapshot.has_more:
            assert snapshot.continuation is None, "terminal page must not carry a continuation"
            break
        assert snapshot.continuation is not None, "has_more page must carry a continuation"
        current_request = request(
            workspace, recorded_at=NOW, transaction_cut=cut, continuation=snapshot.continuation
        )
    assert len(collected) == len(set(collected)) == len(expected) == 6, "exact partition: no duplicate, no omission"
    assert set(collected) == expected
    assert support_refs_by_ref[support_corrected] == (support_base,)
    assert seen_conflicts == [tuple(sorted((conflict_left, conflict_right)))], (
        "the declared contradiction must appear in exactly one page"
    )
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


# ---------------------------------------------------------------------------
# C1 / C2 -- component paging (commit 8a682ac) -- adversarial extensions
# ---------------------------------------------------------------------------

def test_g013_c1_c2_dense_component_swallows_most_candidates_at_tight_page_size(tmp_path: Path) -> None:
    """A single SUPPORT chain spanning 7 of 9 candidates must still be served whole
    on one page even though it dwarfs page_size=2 by more than 3x; the two isolated
    candidates must still page normally around it, and the whole walk must remain
    an exact partition."""
    database, cas, service, workspace = store(tmp_path)
    chain = [ref("candidate", f"dense-chain-{index}") for index in range(7)]
    for index, candidate in enumerate(chain):
        create_and_approve(service, cas, candidate, f"dense-chain-{index}", workspace=workspace)
    for index in range(1, 7):
        service.append(command(
            "CORRECT", chain[index], command_name=f"dense-link-{index}", related=chain[index - 1],
            workspace=workspace, content_digest=blob(cas, f"dense-chain-{index}-v2"),
        ))
    isolated = [ref("candidate", f"dense-isolated-{index}") for index in range(2)]
    for index, candidate in enumerate(isolated):
        create_and_approve(service, cas, candidate, f"dense-isolated-{index}", workspace=workspace)
    expected = set(chain) | set(isolated)
    assert len(expected) == 9

    current_request = request(workspace, recorded_at=NOW)
    cut: str | None = None
    collected: list[str] = []
    pages: list[set[str]] = []
    while True:
        snapshot = _acquire(database, cas, current_request, page_size=2)
        if cut is None:
            cut = snapshot.transaction_cut
        else:
            assert snapshot.transaction_cut == cut
        page_refs = {item.candidate_ref for item in snapshot.candidates}
        pages.append(page_refs)
        collected.extend(item.candidate_ref for item in snapshot.candidates)
        if not snapshot.has_more:
            assert snapshot.continuation is None
            break
        assert snapshot.continuation is not None
        current_request = request(
            workspace, recorded_at=NOW, transaction_cut=cut, continuation=snapshot.continuation
        )
    assert len(collected) == len(set(collected)) == len(expected) == 9, "exact partition: no duplicate, no omission"
    assert set(collected) == expected
    chain_pages = [page for page in pages if page & set(chain)]
    assert len(chain_pages) == 1, "the 7-member chain component must never be split across pages"
    assert chain_pages[0] == set(chain), "the whole chain component must be served together"
    assert len(chain_pages[0]) > 2, "the oversized component legitimately exceeds page_size on its own page"
    for page in pages:
        if page != chain_pages[0]:
            assert len(page) <= 2, "non-oversized pages must still respect page_size"
    database.close()


@pytest.mark.parametrize("page_size", [1, 2, 3, 4, 7])
def test_g013_c1_c2_interleaved_links_and_isolated_candidates_across_several_page_sizes(
    tmp_path: Path, page_size: int
) -> None:
    database, cas, service, workspace = store(tmp_path)
    pair_a = (ref("candidate", "inter-pair-a-left"), ref("candidate", "inter-pair-a-right"))
    pair_b = (ref("candidate", "inter-pair-b-left"), ref("candidate", "inter-pair-b-right"))
    isolated = [ref("candidate", f"inter-isolated-{index}") for index in range(3)]
    for candidate, name in (
        (pair_a[0], "inter-pair-a-left"), (pair_a[1], "inter-pair-a-right"),
        (pair_b[0], "inter-pair-b-left"), (pair_b[1], "inter-pair-b-right"),
        *((candidate, f"inter-isolated-{index}") for index, candidate in enumerate(isolated)),
    ):
        create_and_approve(service, cas, candidate, name, workspace=workspace)
    service.append(command(
        "CORRECT", pair_a[1], command_name="inter-support-a", related=pair_a[0],
        workspace=workspace, content_digest=blob(cas, "inter-pair-a-right-v2"),
    ))
    service.append(command(
        "DECLARE_CONTRADICTION", pair_b[0], command_name="inter-conflict-b", related=pair_b[1], workspace=workspace,
    ))
    expected = set(pair_a) | set(pair_b) | set(isolated)
    assert len(expected) == 7

    current_request = request(workspace, recorded_at=NOW)
    cut: str | None = None
    collected: list[str] = []
    seen_conflicts: list[tuple[str, str]] = []
    while True:
        snapshot = _acquire(database, cas, current_request, page_size=page_size)
        if cut is None:
            cut = snapshot.transaction_cut
        else:
            assert snapshot.transaction_cut == cut
        page_displayed = {item.candidate_ref for item in snapshot.candidates}
        for item in snapshot.candidates:
            assert set(item.support_refs) <= page_displayed, "support ref must never be off-page"
        for conflict in snapshot.conflicts:
            assert conflict.left_candidate_ref in page_displayed and conflict.right_candidate_ref in page_displayed
            seen_conflicts.append((conflict.left_candidate_ref, conflict.right_candidate_ref))
        collected.extend(item.candidate_ref for item in snapshot.candidates)
        if not snapshot.has_more:
            assert snapshot.continuation is None
            break
        assert snapshot.continuation is not None
        current_request = request(
            workspace, recorded_at=NOW, transaction_cut=cut, continuation=snapshot.continuation
        )
    assert len(collected) == len(set(collected)) == len(expected) == 7, "exact partition: no duplicate, no omission"
    assert set(collected) == expected
    assert seen_conflicts == [tuple(sorted(pair_b))], "the one declared contradiction must surface exactly once"
    database.close()


def test_g013_c1_c2_component_members_straddle_lexicographic_gap_between_isolated_candidates(
    tmp_path: Path,
) -> None:
    """The three literal names below are chosen (offline, by brute force over the
    same sha256 ref digest the fixtures use) so that the isolated candidate's ref
    falls STRICTLY BETWEEN the two support-linked component members in plain
    candidate_ref sort order. A pre-8a682ac lexicographic page walk at page_size=1
    would have served base, then the isolated candidate, then corrected -- three
    pages, splitting the component and leaving the correction's support ref
    off-page. Component-based paging must instead serve the linked pair together
    on one page (page_size=1 legitimately exceeded) and the isolated candidate
    alone on its own page, in min-ref order."""
    database, cas, service, workspace = store(tmp_path)
    support_base = ref("candidate", "straddle-support-base")
    support_corrected = ref("candidate", "straddle-support-corrected")
    isolated = ref("candidate", "straddle-isolated-8")
    assert sorted((support_base, isolated, support_corrected)) == [support_base, isolated, support_corrected], (
        "fixture precondition: the isolated ref must sort strictly between the pair"
    )
    create_and_approve(service, cas, support_base, "straddle-support-base", workspace=workspace)
    create_and_approve(service, cas, support_corrected, "straddle-support-corrected", workspace=workspace)
    create_and_approve(service, cas, isolated, "straddle-isolated-8", workspace=workspace)
    service.append(command(
        "CORRECT", support_corrected, command_name="straddle-correct", related=support_base,
        workspace=workspace, content_digest=blob(cas, "straddle-support-corrected-v2"),
    ))
    expected = {support_base, support_corrected, isolated}

    current_request = request(workspace, recorded_at=NOW)
    cut: str | None = None
    pages: list[set[str]] = []
    while True:
        snapshot = _acquire(database, cas, current_request, page_size=1)
        if cut is None:
            cut = snapshot.transaction_cut
        pages.append({item.candidate_ref for item in snapshot.candidates})
        if not snapshot.has_more:
            assert snapshot.continuation is None
            break
        current_request = request(
            workspace, recorded_at=NOW, transaction_cut=cut, continuation=snapshot.continuation
        )
    assert len(pages) == 2, "the linked pair must be co-served, so 3 candidates take 2 pages, not 3"
    assert pages[0] == {support_base, support_corrected}, "the component must be the first page, whole"
    assert pages[1] == {isolated}
    assert {ref for page in pages for ref in page} == expected
    database.close()


def test_g013_c1_c2_multiple_contradictions_each_surface_exactly_once_across_full_walk(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    pairs = [
        (ref("candidate", f"multi-conflict-{index}-left"), ref("candidate", f"multi-conflict-{index}-right"))
        for index in range(3)
    ]
    for index, (left, right) in enumerate(pairs):
        create_and_approve(service, cas, left, f"multi-conflict-{index}-left", workspace=workspace)
        create_and_approve(service, cas, right, f"multi-conflict-{index}-right", workspace=workspace)
        service.append(command(
            "DECLARE_CONTRADICTION", left, command_name=f"multi-declare-{index}", related=right, workspace=workspace,
        ))
    expected = {candidate for pair in pairs for candidate in pair}
    assert len(expected) == 6
    expected_conflicts = sorted(tuple(sorted(pair)) for pair in pairs)

    current_request = request(workspace, recorded_at=NOW)
    cut: str | None = None
    collected: list[str] = []
    seen_conflicts: list[tuple[str, str]] = []
    while True:
        snapshot = _acquire(database, cas, current_request, page_size=2)
        if cut is None:
            cut = snapshot.transaction_cut
        else:
            assert snapshot.transaction_cut == cut
        page_displayed = {item.candidate_ref for item in snapshot.candidates}
        for conflict in snapshot.conflicts:
            assert conflict.left_candidate_ref in page_displayed and conflict.right_candidate_ref in page_displayed
            seen_conflicts.append((conflict.left_candidate_ref, conflict.right_candidate_ref))
        collected.extend(item.candidate_ref for item in snapshot.candidates)
        if not snapshot.has_more:
            assert snapshot.continuation is None
            break
        current_request = request(
            workspace, recorded_at=NOW, transaction_cut=cut, continuation=snapshot.continuation
        )
    assert set(collected) == expected and len(collected) == len(set(collected)) == 6
    assert sorted(seen_conflicts) == expected_conflicts, (
        "every declared contradiction must surface exactly once across the whole walk"
    )
    database.close()


# ---------------------------------------------------------------------------
# V2 transport paging (commit 6f0dcca)
# ---------------------------------------------------------------------------

def test_g013_v2_recall_pages_to_exhaustion_and_citation_flags_off_page_candidates(tmp_path: Path) -> None:
    """Drive SecondBrainApiV2 end to end: walk recall() to has_more=False purely
    through the encoded continuation handle, and prove citation() tells apart
    'served on an earlier/current page' (OK) from 'not yet resolvable because more
    pages remain' (NOT_SERVED) for every candidate at every step."""
    ledger_fixtures._ACTIVE_REVISIONS.clear()
    ledger_fixtures._COMMAND_PROVENANCE.clear()
    ledger_fixtures._CURRENT_CUT = "1"
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    workspace = ref("workspace", "v2-exhaust")
    first_request = request(workspace, transaction_cut="1", recorded_at=NOW)
    write_authority = _authority(database, cas, first_request, page_size=1)
    write_authority.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), "2026-01-01T00:00:00Z")
    writer = TrackingLedgerService(write_authority, write_authority)
    refs = [ref("candidate", f"v2-exhaust-{index}") for index in range(3)]
    for index, candidate in enumerate(refs):
        create_and_approve(writer, cas, candidate, f"v2-exhaust-{index}", workspace=workspace)
    expected = set(refs)

    current_request = request(workspace, recorded_at=NOW)
    collected: set[str] = set()
    nonce = 0
    pages = 0
    while True:
        _, api = _v2_stack(database, cas, current_request, page_size=1)
        recall_result = api.recall(_use(workspace, "recall", f"n-recall-{nonce}"), current_request)
        assert recall_result.code == "OK"
        pages += 1
        page_served: set[str] = set()
        for candidate in refs:
            if candidate in collected:
                continue
            citation = api.citation(_use(workspace, "citation", f"n-cite-{nonce}-{candidate}"), current_request, candidate)
            if citation.code == "OK":
                assert int(citation.receipt["citation_count"]) > 0
                page_served.add(candidate)
            elif recall_result.receipt["has_more"] == "true":
                assert citation.code == "NOT_SERVED", "an off-page candidate must never report OK"
                assert citation.receipt["citation_count"] == "0"
        assert len(page_served) == int(recall_result.receipt["result_count"])
        collected |= page_served
        nonce += 1
        if recall_result.receipt["has_more"] == "false":
            assert recall_result.receipt["continuation"] == ""
            break
        assert recall_result.receipt["continuation"]
        decoded = dict(pair.split("=", 1) for pair in recall_result.receipt["continuation"].split(";"))
        continuation = RecallContinuationV2.from_mapping(decoded)
        current_request = request(
            workspace, recorded_at=NOW, transaction_cut=continuation.transaction_cut, continuation=continuation
        )
    assert pages == 3, "page_size=1 over 3 candidates must take exactly 3 pages"
    assert collected == expected, "the full walk must be an exact partition of the servable candidate set"
    database.close()


def test_g013_v2_citation_reports_not_served_for_an_earlier_page_candidate_on_the_terminal_page(
    tmp_path: Path,
) -> None:
    """B3 regression: citation() must tell apart 'served on an earlier page' from
    'genuinely uncited' even on the LAST page of a walk. Gating solely on
    `answer.has_more` misreports a candidate served on an earlier page as OK with
    citation_count 0 once the walk reaches its terminal (has_more=False) page,
    because that page's own results no longer include the earlier candidate.
    Gating on `answer.has_more or request.continuation is not None` catches this:
    a terminal page reached via a continuation is still only a partial view of
    the walk from the caller's perspective for candidates outside it."""
    database, cas, service, workspace = store(tmp_path)
    a, b = ref("candidate", "term-a"), ref("candidate", "term-b")
    create_and_approve(service, cas, a, "term-a", workspace=workspace)
    create_and_approve(service, cas, b, "term-b", workspace=workspace)

    first_request = request(workspace, recorded_at=NOW)
    _, api = _v2_stack(database, cas, first_request, page_size=1)
    page1 = api.recall(_use(workspace, "recall", "n-term-recall-1"), first_request)
    assert page1.code == "OK" and page1.receipt["has_more"] == "true"
    page1_citation_a = api.citation(_use(workspace, "citation", "n-term-cite-page1-a"), first_request, a)
    served_first = a if page1_citation_a.code == "OK" else b
    served_second = b if served_first == a else a
    decoded = dict(pair.split("=", 1) for pair in page1.receipt["continuation"].split(";"))
    continuation = RecallContinuationV2.from_mapping(decoded)
    second_request = request(
        workspace, recorded_at=NOW, transaction_cut=continuation.transaction_cut, continuation=continuation
    )
    _, api2 = _v2_stack(database, cas, second_request, page_size=1)
    page2 = api2.citation(_use(workspace, "citation", "n-term-cite-page2"), second_request, served_first)
    page2_recall = api2.recall(_use(workspace, "recall", "n-term-recall-2"), second_request)
    assert page2_recall.receipt["has_more"] == "false", "the second page must be the terminal page"
    assert page2.code == "NOT_SERVED", "served_first lies outside this terminal page's own results"
    assert page2.receipt["citation_count"] == "0"
    on_page = api2.citation(_use(workspace, "citation", "n-term-cite-b"), second_request, served_second)
    assert on_page.code == "OK" and int(on_page.receipt["citation_count"]) > 0
    database.close()


def test_g013_v2_mangled_continuation_receipt_fails_closed(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    a, b = ref("candidate", "mangle-a"), ref("candidate", "mangle-b")
    create_and_approve(service, cas, a, "mangle-a", workspace=workspace)
    create_and_approve(service, cas, b, "mangle-b", workspace=workspace)
    first_request = request(workspace, recorded_at=NOW)
    _, api = _v2_stack(database, cas, first_request, page_size=1)
    result = api.recall(_use(workspace, "recall", "n-mangle-1"), first_request)
    assert result.receipt["has_more"] == "true"
    encoded = result.receipt["continuation"]
    # Flip one hex character deep inside the encoded receipt -- not a separator,
    # not a structural character, purely a value byte -- so the string still
    # parses field-by-field but the recomputed continuation_digest can no longer
    # match.
    index = encoded.index("cursor_state_digest=") + len("cursor_state_digest=")
    flipped_char = "1" if encoded[index] != "1" else "2"
    mangled = encoded[:index] + flipped_char + encoded[index + 1:]
    decoded = dict(pair.split("=", 1) for pair in mangled.split(";"))
    with pytest.raises(InvalidContractValue):
        RecallContinuationV2.from_mapping(decoded)
    database.close()


def test_g013_v2_truncated_continuation_receipt_fails_closed(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    a, b = ref("candidate", "trunc-a"), ref("candidate", "trunc-b")
    create_and_approve(service, cas, a, "trunc-a", workspace=workspace)
    create_and_approve(service, cas, b, "trunc-b", workspace=workspace)
    first_request = request(workspace, recorded_at=NOW)
    _, api = _v2_stack(database, cas, first_request, page_size=1)
    result = api.recall(_use(workspace, "recall", "n-trunc-1"), first_request)
    encoded = result.receipt["continuation"]
    assert encoded
    truncated = encoded[: len(encoded) // 2]
    with pytest.raises((ValueError, InvalidContractValue)):
        decoded = dict(pair.split("=", 1) for pair in truncated.split(";"))
        RecallContinuationV2.from_mapping(decoded)
    database.close()


def test_g013_v2_separator_injected_continuation_receipt_fails_closed(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    a, b = ref("candidate", "sep-a"), ref("candidate", "sep-b")
    create_and_approve(service, cas, a, "sep-a", workspace=workspace)
    create_and_approve(service, cas, b, "sep-b", workspace=workspace)
    first_request = request(workspace, recorded_at=NOW)
    _, api = _v2_stack(database, cas, first_request, page_size=1)
    result = api.recall(_use(workspace, "recall", "n-sep-1"), first_request)
    encoded = result.receipt["continuation"]
    assert encoded

    # Attack 1: smuggle an extra field by injecting a bonus ';'-delimited pair.
    smuggled = encoded + ";forged_field=evil"
    decoded_smuggled = dict(pair.split("=", 1) for pair in smuggled.split(";"))
    with pytest.raises(UnknownContractField):
        RecallContinuationV2.from_mapping(decoded_smuggled)

    # Attack 2: inject a bonus '=' inside one field's own value to try to widen
    # or corrupt its parsed boundary.
    assert "cursor_handle_ref=" in encoded
    injected = encoded.replace("cursor_handle_ref=", "cursor_handle_ref=X=", 1)
    decoded_injected = dict(pair.split("=", 1) for pair in injected.split(";"))
    with pytest.raises(InvalidContractValue):
        RecallContinuationV2.from_mapping(decoded_injected)
    database.close()


def test_g013_v2_foreign_workspace_continuation_receipt_fails_closed(tmp_path: Path) -> None:
    database, cas, service, workspace_a = store(tmp_path)
    create_and_approve(service, cas, ref("candidate", "v2-cross-a1"), "v2-cross-a1", workspace=workspace_a)
    create_and_approve(service, cas, ref("candidate", "v2-cross-a2"), "v2-cross-a2", workspace=workspace_a)
    first_a = request(workspace_a, recorded_at=NOW)
    _, api_a = _v2_stack(database, cas, first_a, page_size=1)
    result_a = api_a.recall(_use(workspace_a, "recall", "n-cross-a"), first_a)
    assert result_a.receipt["has_more"] == "true"
    encoded = result_a.receipt["continuation"]
    decoded = dict(pair.split("=", 1) for pair in encoded.split(";"))

    workspace_b = ref("workspace", "v2-cross-b")
    _authority(database, cas, request(workspace_b, transaction_cut="1")).set_authority(
        workspace_b, LedgerAuthority(ref("capability", "stage3"), "1"), NOW
    )
    service.append(command(
        "CREATE_CANDIDATE", ref("candidate", "v2-cross-b1"), command_name="v2-create-cross-b1",
        workspace=workspace_b, content_digest=blob(cas, "v2-cross-b1"), transaction_cut="1",
    ))
    service.append(command(
        "REVIEW_APPROVE", ref("candidate", "v2-cross-b1"), command_name="v2-approve-cross-b1",
        workspace=workspace_b, transaction_cut="2",
    ))
    # The wire receipt is workspace-scoped structurally: replaying workspace A's
    # decoded continuation while constructing a workspace-B request must be
    # refused before any durable cursor lookup or trust verification runs.
    with pytest.raises(InvalidContractValue, match="continuation is not request-bound"):
        request(
            workspace_b, recorded_at=NOW, transaction_cut="2",
            continuation=RecallContinuationV2.from_mapping(decoded),
        )
    database.close()


def test_g013_v2_no_receipt_value_leaks_forbidden_surface_name_across_full_walk(tmp_path: Path) -> None:
    ledger_fixtures._ACTIVE_REVISIONS.clear()
    ledger_fixtures._COMMAND_PROVENANCE.clear()
    ledger_fixtures._CURRENT_CUT = "1"
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    workspace = ref("workspace", "v2-leak")
    first_request = request(workspace, transaction_cut="1", recorded_at=NOW)
    write_authority = _authority(database, cas, first_request, page_size=1)
    write_authority.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), "2026-01-01T00:00:00Z")
    writer = TrackingLedgerService(write_authority, write_authority)
    refs = [ref("candidate", f"v2-leak-{index}") for index in range(3)]
    for index, candidate in enumerate(refs):
        create_and_approve(writer, cas, candidate, f"v2-leak-{index}", workspace=workspace)

    current_request = request(workspace, recorded_at=NOW)
    nonce = 0
    while True:
        _, api = _v2_stack(database, cas, current_request, page_size=1)
        recall_result = api.recall(_use(workspace, "recall", f"n-leak-recall-{nonce}"), current_request)
        for candidate in refs:
            citation = api.citation(
                _use(workspace, "citation", f"n-leak-cite-{nonce}-{candidate}"), current_request, candidate
            )
            for value in citation.receipt.values():
                for forbidden in _FORBIDDEN_SURFACE:
                    assert forbidden not in value
        for value in recall_result.receipt.values():
            for forbidden in _FORBIDDEN_SURFACE:
                assert forbidden not in value
        nonce += 1
        if recall_result.receipt["has_more"] == "false":
            break
        decoded = dict(pair.split("=", 1) for pair in recall_result.receipt["continuation"].split(";"))
        continuation = RecallContinuationV2.from_mapping(decoded)
        current_request = request(
            workspace, recorded_at=NOW, transaction_cut=continuation.transaction_cut, continuation=continuation
        )
    database.close()


# ---------------------------------------------------------------------------
# C3 -- cursor expiry and retention (commit 2bbfcc3)
# ---------------------------------------------------------------------------

def test_g013_c3_expired_cursor_row_refuses_resumption_after_ttl_elapses(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    a, b, c = (ref("candidate", value) for value in ("ttl-a", "ttl-b", "ttl-c"))
    for candidate, name in ((a, "ttl-a"), (b, "ttl-b"), (c, "ttl-c")):
        create_and_approve(service, cas, candidate, name, workspace=workspace)
    first_request = request(workspace, recorded_at=NOW)
    first = _acquire(database, cas, first_request, page_size=1)
    assert first.has_more and first.continuation is not None
    continuation = first.continuation

    assert database.con is not None
    database.con.execute("DROP TRIGGER ledger_recall_cursor_no_update")
    database.con.execute(
        "UPDATE ledger_recall_cursor SET expires_at=? WHERE cursor_handle_ref=?",
        ("2020-01-01T00:00:00Z", continuation.cursor_handle_ref),
    )
    replay_request = request(
        workspace, recorded_at=NOW, transaction_cut=first.transaction_cut, continuation=continuation
    )
    with pytest.raises(LedgerAuthorityError, match="continuation cursor has expired"):
        _acquire(database, cas, replay_request, page_size=1)
    database.close()


def test_g013_c3_live_cursor_row_is_undeletable_and_unupdatable_via_direct_sql(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    a, b = ref("candidate", "immutable-a"), ref("candidate", "immutable-b")
    create_and_approve(service, cas, a, "immutable-a", workspace=workspace)
    create_and_approve(service, cas, b, "immutable-b", workspace=workspace)
    first = _acquire(database, cas, request(workspace, recorded_at=NOW), page_size=1)
    assert first.has_more and first.continuation is not None
    handle = first.continuation.cursor_handle_ref
    assert database.con is not None
    con = database.con
    with pytest.raises(Exception, match="cannot be deleted"):
        con.execute("DELETE FROM ledger_recall_cursor WHERE cursor_handle_ref=?", (handle,))
    with pytest.raises(Exception, match="append-only"):
        con.execute(
            "UPDATE ledger_recall_cursor SET after_candidate_ref=? WHERE cursor_handle_ref=?", (b, handle)
        )
    still_there = con.execute(
        "SELECT COUNT(*) FROM ledger_recall_cursor WHERE cursor_handle_ref=?", (handle,)
    ).fetchone()[0]
    assert still_there == 1
    database.close()


def test_g013_c3_retention_bound_table_cannot_be_abused_to_delete_a_live_cursor(tmp_path: Path) -> None:
    """The ledger_recall_cursor_no_delete trigger only ever permits deleting a row
    whose own expires_at is at or before the retention_bound_at stamped in
    ledger_recall_cursor_retention_bound, and LifecycleDatabase.purge_expired_recall_cursors'
    docstring claims that bound "never persists as ambient authority outside the
    retention transaction itself" -- i.e. a live row can supposedly never be
    removed "by this or any other statement". Attack that claim directly:
    without ever touching the no-delete/no-update triggers (no DROP TRIGGER
    anywhere in this test -- every OTHER durable-invariant bypass in this whole
    suite needs one first), stamp a far-future retention bound with a bare
    INSERT into the (unguarded) retention-bound table, then issue a plain DELETE
    against a cursor row that is still well inside its live 300s TTL."""
    database, cas, service, workspace = store(tmp_path)
    a, b = ref("candidate", "abuse-a"), ref("candidate", "abuse-b")
    create_and_approve(service, cas, a, "abuse-a", workspace=workspace)
    create_and_approve(service, cas, b, "abuse-b", workspace=workspace)
    first = _acquire(database, cas, request(workspace, recorded_at=NOW), page_size=1)
    assert first.has_more and first.continuation is not None
    live_handle = first.continuation.cursor_handle_ref
    assert database.con is not None
    con = database.con

    # No trigger is dropped or altered here -- this is a bare data-plane INSERT
    # into a table the schema declares with no append-only/no-delete guard of
    # its own, unlike every other durable ledger table in this schema.
    con.execute(
        "INSERT INTO ledger_recall_cursor_retention_bound VALUES('singleton', ?)",
        ("2999-01-01T00:00:00Z",),
    )
    with pytest.raises(Exception, match="cannot be deleted"):
        con.execute("DELETE FROM ledger_recall_cursor WHERE cursor_handle_ref=?", (live_handle,))
    still_there = con.execute(
        "SELECT COUNT(*) FROM ledger_recall_cursor WHERE cursor_handle_ref=?", (live_handle,)
    ).fetchone()[0]
    assert still_there == 1, (
        "BLOCKER: a bare INSERT into ledger_recall_cursor_retention_bound (no DROP "
        "TRIGGER, no schema tampering -- just ordinary SQL any code path with a "
        "write connection can issue) lets a plain DELETE remove a cursor row still "
        "well inside its 300s TTL. The retention-bound table has no append-only, "
        "single-writer, or same-transaction-only guard of its own, so the 'live "
        "row can never be removed by this or any other statement' guarantee only "
        "holds as long as nothing else in the process ever writes that one table -- "
        "reproduce with: INSERT INTO ledger_recall_cursor_retention_bound "
        "VALUES('singleton','2999-01-01T00:00:00Z'); DELETE FROM ledger_recall_cursor "
        "WHERE cursor_handle_ref=<live handle>;"
    )
    database.close()


# ---------------------------------------------------------------------------
# C4 -- clock skew (commit 2bbfcc3)
# ---------------------------------------------------------------------------

def test_g013_c4_recorded_at_forward_skew_bound_refused_on_first_page_with_exact_boundary_probe(
    tmp_path: Path,
) -> None:
    (tmp_path / "within").mkdir()
    database, cas, service, workspace = store(tmp_path / "within")
    candidate = ref("candidate", "skew-boundary")
    create_and_approve(service, cas, candidate, "skew-boundary", workspace=workspace)
    at_bound = request(workspace, recorded_at=_shift(NOW, 30))
    snapshot = _acquire(database, cas, at_bound, page_size=50)
    assert not snapshot.has_more
    assert [item.candidate_ref for item in snapshot.candidates] == [candidate]
    database.close()

    (tmp_path / "beyond").mkdir()
    database, cas, service, workspace = store(tmp_path / "beyond")
    create_and_approve(service, cas, candidate, "skew-boundary", workspace=workspace)
    beyond_bound = request(workspace, recorded_at=_shift(NOW, 31))
    with pytest.raises(LedgerAuthorityError, match="recall recorded_at exceeds the trusted clock skew bound"):
        _acquire(database, cas, beyond_bound, page_size=50)
    database.close()

    (tmp_path / "gross").mkdir()
    database, cas, service, workspace = store(tmp_path / "gross")
    create_and_approve(service, cas, candidate, "skew-boundary", workspace=workspace)
    # Attack the far end too: a wildly future recorded_at (a full month ahead)
    # must be refused exactly the same way, not silently accepted just because
    # it is far past the near boundary that already tripped once.
    far_future = request(workspace, recorded_at=_shift(NOW, 3600 * 24 * 30))
    with pytest.raises(LedgerAuthorityError, match="recall recorded_at exceeds the trusted clock skew bound"):
        _acquire(database, cas, far_future, page_size=50)
    database.close()


def test_g013_c4_as_of_far_in_the_past_still_succeeds(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    candidate = ref("candidate", "skew-past")
    create_and_approve(service, cas, candidate, "skew-past", workspace=workspace)
    far_past = request(workspace, recorded_at=_shift(NOW, -3600 * 24 * 365 * 5))
    snapshot = _acquire(database, cas, far_past, page_size=50)
    assert snapshot.candidates == ()
    database.close()


def test_g013_c4_clock_skew_is_enforced_on_a_continued_page_not_only_the_first(tmp_path: Path) -> None:
    """The forward skew guard must not be a one-shot check the first page's caller
    alone has to satisfy. A continuation pins its own recorded_at (the request-
    binding check refuses any wrapping request that disagrees), so the recorded_at
    itself can never drift between pages of one chain -- but the TRUSTED CLOCK used
    to evaluate the bound can legitimately differ per authority instance (e.g. a
    replica or a restarted process resuming the chain with a clock that lags the
    one that issued page 1). Simulate exactly that: mint a second trust authority
    over the same durable registry with a clock 40s BEHIND NOW and prove the
    resumed page is refused even though the identical recorded_at was accepted
    when page 1 was issued moments earlier under the un-drifted clock."""
    database, cas, service, workspace = store(tmp_path)
    a, b = ref("candidate", "skew-page-a"), ref("candidate", "skew-page-b")
    create_and_approve(service, cas, a, "skew-page-a", workspace=workspace)
    create_and_approve(service, cas, b, "skew-page-b", workspace=workspace)
    first_request = request(workspace, recorded_at=NOW)
    first_authority = _authority(database, cas, first_request, page_size=1)
    first = SecondBrainLedgerService(first_authority, first_authority).acquire(first_request).snapshot
    assert first.has_more and first.continuation is not None

    resumed_request = request(
        workspace, recorded_at=NOW, transaction_cut=first.transaction_cut, continuation=first.continuation
    )
    lagging_trust = mint_recall_trust_authority_v2(
        security_authority(), DeterministicEd25519Verifier(), lambda: _shift(NOW, -40),
        trust_for_request(resumed_request)._RecallTrustAuthorityV2__provenance,
    )
    lagging_authority = LifecycleLedgerAuthority(
        database, cas, lagging_trust, signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    with pytest.raises(LedgerAuthorityError, match="recall recorded_at exceeds the trusted clock skew bound"):
        SecondBrainLedgerService(lagging_authority, lagging_authority).acquire(resumed_request)
    database.close()
