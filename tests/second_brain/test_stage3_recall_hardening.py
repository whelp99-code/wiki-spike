"""Regression coverage for the three P2 architect findings on Second-Brain
Stage 3 bounded recall:

- F6: ``ledger_recall_cursor`` rows now expire on the shared 300s continuation
  TTL. An expired row refuses resumption, and a narrow retention path can
  delete only already-expired rows -- a live row can never be deleted or
  updated, with no DROP TRIGGER required.
- F7: the recall page query and its support/citation joins now have covering
  indexes so a page's cost stops scaling with total ledger size.
- F8: ``recorded_at`` is bounded against the trusted clock by a small forward
  skew tolerance, checked immediately rather than deferred until ``has_more``.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from test_stage3_ledger_persistence import (
    KEY_ID,
    NOW,
    SIGNER_REF,
    create_and_approve,
    digest,
    ref,
    request,
    signed_snapshot_signer,
    store,
    trust_for_request,
)

from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.second_brain_ledger import LedgerAuthorityError, LifecycleLedgerAuthority


def _paged_authority(database, cas, req, *, page_size: int = 1) -> LifecycleLedgerAuthority:
    return LifecycleLedgerAuthority(
        database, cas, trust_for_request(req), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=page_size,
    )


def _shift(instant: str, seconds: int) -> str:
    parsed = datetime.fromisoformat(instant[:-1] + "+00:00").astimezone(timezone.utc)
    shifted = parsed + timedelta(seconds=seconds)
    return shifted.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# F6 -- cursor row expiry
# --------------------------------------------------------------------------- #

def test_expired_cursor_row_refuses_resumption_while_a_live_row_still_resumes(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    a, b, c = (ref("candidate", value) for value in ("cursor-a", "cursor-b", "cursor-c"))
    for candidate, name in ((a, "cursor-a"), (b, "cursor-b"), (c, "cursor-c")):
        create_and_approve(service, cas, candidate, name, workspace=workspace)

    first_request = request(workspace, recorded_at=NOW)
    first_authority = _paged_authority(database, cas, first_request)
    first = SecondBrainLedgerService(first_authority, first_authority).acquire(first_request).snapshot
    assert first.has_more and first.continuation is not None
    continuation = first.continuation

    # Live: the row was just issued, well inside its 300s TTL -- resumption succeeds.
    resumed_request = request(
        workspace, recorded_at=NOW, transaction_cut=first.transaction_cut, continuation=continuation
    )
    resumed_authority = _paged_authority(database, cas, resumed_request)
    second = SecondBrainLedgerService(resumed_authority, resumed_authority).acquire(resumed_request).snapshot
    assert [item.candidate_ref for item in second.candidates] == [b]

    # Now force the SAME durable cursor row past its expiry (bypassing the
    # unconditional no_update trigger the way the existing tamper-revalidation
    # coverage already does), and prove a second resumption attempt against
    # that now-expired row is refused with a clear, immediate error.
    assert database.con is not None
    database.con.execute("DROP TRIGGER ledger_recall_cursor_no_update")
    database.con.execute(
        "UPDATE ledger_recall_cursor SET expires_at=? WHERE cursor_handle_ref=?",
        ("2020-01-01T00:00:00Z", continuation.cursor_handle_ref),
    )
    replay_request = request(
        workspace, recorded_at=NOW, transaction_cut=first.transaction_cut, continuation=continuation
    )
    replay_authority = _paged_authority(database, cas, replay_request)
    with pytest.raises(LedgerAuthorityError, match="continuation cursor has expired"):
        SecondBrainLedgerService(replay_authority, replay_authority).acquire(replay_request)
    database.close()


# --------------------------------------------------------------------------- #
# F6 -- narrow retention deletion path
# --------------------------------------------------------------------------- #

def test_retention_path_deletes_only_expired_cursor_rows_live_rows_stay_immutable(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    a, b = sorted((ref("candidate", "gc-a"), ref("candidate", "gc-b")))
    create_and_approve(service, cas, a, "gc-a", workspace=workspace)
    create_and_approve(service, cas, b, "gc-b", workspace=workspace)

    first_request = request(workspace, recorded_at=NOW)
    authority = _paged_authority(database, cas, first_request)
    first = SecondBrainLedgerService(authority, authority).acquire(first_request).snapshot
    assert first.has_more and first.continuation is not None
    live_handle = first.continuation.cursor_handle_ref

    assert database.con is not None
    con = database.con
    # A second, independently forged-but-durable row standing in for a stale
    # cursor whose TTL has already elapsed (bypassing no_update the same way
    # the tamper-revalidation coverage does, purely to seed the fixture).
    expired_handle = "cursor:" + digest("expired-fixture-row")
    con.execute(
        "INSERT INTO ledger_recall_cursor VALUES(?,?,?,?,?,?,?)",
        (expired_handle, workspace, first.transaction_cut, digest("expired-state"), a,
         "2019-12-31T23:55:00Z", "2020-01-01T00:00:00Z"),
    )

    before_count = con.execute("SELECT COUNT(*) FROM ledger_recall_cursor").fetchone()[0]
    assert before_count == 2

    # Attempting to delete the still-live row directly must fail closed --
    # the narrow retention path never needs DROP TRIGGER because it can only
    # ever touch already-expired rows in the first place.
    with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
        con.execute("DELETE FROM ledger_recall_cursor WHERE cursor_handle_ref=?", (live_handle,))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        con.execute(
            "UPDATE ledger_recall_cursor SET after_candidate_ref=? WHERE cursor_handle_ref=?",
            (b, live_handle),
        )

    removed = authority.purge_expired_recall_cursors()
    assert removed == 1

    remaining = {row[0] for row in con.execute("SELECT cursor_handle_ref FROM ledger_recall_cursor")}
    assert remaining == {live_handle}

    # The live row is unaffected and the workspace's real continuation still
    # resumes normally after a no-op retention pass.
    resumed_request = request(
        workspace, recorded_at=NOW, transaction_cut=first.transaction_cut, continuation=first.continuation
    )
    resumed_authority = _paged_authority(database, cas, resumed_request)
    second = SecondBrainLedgerService(resumed_authority, resumed_authority).acquire(resumed_request).snapshot
    assert [item.candidate_ref for item in second.candidates] == [b]
    database.close()


# --------------------------------------------------------------------------- #
# F8 -- recorded_at clock skew bound
# --------------------------------------------------------------------------- #

def test_recorded_at_beyond_skew_bound_is_refused_immediately_on_first_page(tmp_path: Path) -> None:
    # Each sub-case gets its own store: the fixture's provenance_ref is keyed
    # by transaction_cut alone, so reusing one workspace across requests that
    # differ only in recorded_at would collide on that ref -- isolating the
    # store keeps this test about the skew bound, not fixture plumbing.
    (tmp_path / "within").mkdir()
    database, cas, service, workspace = store(tmp_path / "within")
    candidate = ref("candidate", "skew-only")
    create_and_approve(service, cas, candidate, "skew-only", workspace=workspace)
    # A single candidate with the default page_size never sets has_more --
    # the failure below can only be an immediate, first-page rejection, never
    # a deferred one triggered by pagination.
    within_bound = request(workspace, recorded_at=_shift(NOW, 30))
    within_authority = _paged_authority(database, cas, within_bound, page_size=50)
    boundary = SecondBrainLedgerService(within_authority, within_authority).acquire(within_bound).snapshot
    assert not boundary.has_more
    assert [item.candidate_ref for item in boundary.candidates] == [candidate]
    database.close()

    (tmp_path / "beyond").mkdir()
    database, cas, service, workspace = store(tmp_path / "beyond")
    create_and_approve(service, cas, candidate, "skew-only", workspace=workspace)
    beyond_bound = request(workspace, recorded_at=_shift(NOW, 31))
    beyond_authority = _paged_authority(database, cas, beyond_bound, page_size=50)
    with pytest.raises(LedgerAuthorityError, match="recall recorded_at exceeds the trusted clock skew bound"):
        SecondBrainLedgerService(beyond_authority, beyond_authority).acquire(beyond_bound)
    database.close()

    # Bitemporal "as-of" queries may still look arbitrarily far into the past:
    # only the forward direction is bounded.
    (tmp_path / "past").mkdir()
    database, cas, service, workspace = store(tmp_path / "past")
    create_and_approve(service, cas, candidate, "skew-only", workspace=workspace)
    far_past = request(workspace, recorded_at=_shift(NOW, -3600 * 24 * 365))
    far_past_authority = _paged_authority(database, cas, far_past, page_size=50)
    past_snapshot = SecondBrainLedgerService(far_past_authority, far_past_authority).acquire(far_past).snapshot
    assert past_snapshot.candidates == ()
    database.close()


# --------------------------------------------------------------------------- #
# F7 -- unique citation-commitment index
# --------------------------------------------------------------------------- #

def test_citation_commitment_unique_index_rejects_a_duplicate_candidate_revision_workspace_row(
    tmp_path: Path,
) -> None:
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    assert database.con is not None
    con = database.con
    candidate_ref, revision_ref, workspace_ref = (
        ref("candidate", "dup"), ref("revision", "dup"), ref("workspace", "dup")
    )
    row = (
        candidate_ref, revision_ref, workspace_ref,
        ref("locator", "one"), digest("locator-one"), ref("source", "one"),
        digest("content-one"), ref("generation", "one"), ref("checkpoint", "one"),
        digest("provenance-one"), digest("citation-one"), "COMMITTED", NOW,
    )
    con.execute("INSERT INTO ledger_citation_commitment VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
    duplicate = (
        candidate_ref, revision_ref, workspace_ref,
        ref("locator", "two"), digest("locator-two"), ref("source", "two"),
        digest("content-two"), ref("generation", "two"), ref("checkpoint", "two"),
        digest("provenance-two"), digest("citation-two"), "COMMITTED", NOW,
    )
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO ledger_citation_commitment VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", duplicate)
    assert con.execute(
        "SELECT COUNT(*) FROM ledger_citation_commitment WHERE candidate_ref=? AND revision_ref=? AND workspace_ref=?",
        (candidate_ref, revision_ref, workspace_ref),
    ).fetchone()[0] == 1
    database.close()
