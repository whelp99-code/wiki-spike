"""Tests for wiki_spike.infrastructure.lifecycle_db.LifecycleDatabase (Gate 2)."""
from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from wiki_spike.infrastructure.lifecycle_db import (
    TABLE_NAMES,
    EventChainError,
    LifecycleDatabase,
    LifecycleDbError,
    assert_no_plaintext_columns,
    is_allowed_column_name,
    table_columns,
)


def make_db(tmp_path, name: str = "lifecycle.sqlite3") -> LifecycleDatabase:
    db = LifecycleDatabase(db_path=tmp_path / name)
    db.initialize()
    return db


# --------------------------------------------------------------------------- #
# PRAGMAs
# --------------------------------------------------------------------------- #


def test_initialize_applies_all_contract_pragmas(tmp_path):
    db = make_db(tmp_path)
    try:
        assert str(db.con.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
        assert int(db.con.execute("PRAGMA synchronous").fetchone()[0]) == 2
        assert int(db.con.execute("PRAGMA foreign_keys").fetchone()[0]) == 1
        assert int(db.con.execute("PRAGMA busy_timeout").fetchone()[0]) == 5000
        # assert_contract_pragmas must not raise on a correctly-initialized db.
        db.assert_contract_pragmas()
    finally:
        db.close()


def test_assert_contract_pragmas_raises_before_initialize(tmp_path):
    db = LifecycleDatabase(db_path=tmp_path / "not-yet.sqlite3")
    with pytest.raises(AssertionError):
        db.assert_contract_pragmas()


# --------------------------------------------------------------------------- #
# initialize() migration concurrency
# --------------------------------------------------------------------------- #


def test_concurrent_initialize_on_existing_db_does_not_race_the_migration(tmp_path):
    """Every opener must survive initialize() on an already-created file.

    initialize() back-fills columns and replaces the recall-cursor no-delete
    trigger. Run without one serialising transaction, each opener observes the
    pre-migration shape and the losers fail with "trigger ... already exists"
    (or "duplicate column name") once the winner commits. busy_timeout cannot
    mask it: the statements never conflict on locks, the losers simply acted on
    a stale read.

    The barrier plus repeated rounds is calibrated against the unguarded code:
    a single barrier round reproduced the failure in 7 of 8 measured trials, so
    24 rounds leave effectively no escape, while the guarded code completed all
    rounds cleanly in about 1.6s.
    """
    rounds, workers = 24, 8
    for round_index in range(rounds):
        path = tmp_path / f"concurrent-initialize-{round_index}.sqlite3"
        seed = LifecycleDatabase(db_path=path)
        seed.initialize()
        seed.close()

        gate = threading.Barrier(workers)

        def reopen(_: int, path: Path = path, gate: threading.Barrier = gate) -> None:
            # Enter initialize() together so the migration window overlaps.
            gate.wait(timeout=30)
            db = LifecycleDatabase(db_path=path)
            db.initialize()
            db.close()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            # list() re-raises the first worker exception.
            list(pool.map(reopen, range(workers)))

        db = LifecycleDatabase(db_path=path)
        db.initialize()
        try:
            rows = db.con.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND name='ledger_recall_cursor_no_delete'"
            ).fetchall()
            # Exactly one trigger survives, in the unconditional post-migration
            # form, and the ambient retention-bound table stays dropped.
            assert len(rows) == 1
            assert " WHEN " not in rows[0][0].upper()
            assert db.con.execute(
                "SELECT name FROM sqlite_master "
                "WHERE name='ledger_recall_cursor_retention_bound'"
            ).fetchall() == []
        finally:
            db.close()


def test_initialize_commits_its_migration_and_leaves_no_open_transaction(tmp_path):
    """The migration must not leave a write transaction holding the file."""
    db = make_db(tmp_path, "migration-committed.sqlite3")
    try:
        assert not db.con.in_transaction
        # An independent connection can immediately take the write lock, which
        # is impossible while the migration transaction is still open.
        other = sqlite3.connect(str(db.db_path), isolation_level=None)
        try:
            other.execute("PRAGMA busy_timeout=0")
            other.execute("BEGIN IMMEDIATE")
            other.execute("ROLLBACK")
        finally:
            other.close()
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# No plaintext columns
# --------------------------------------------------------------------------- #


def test_ddl_has_no_plaintext_columns(tmp_path):
    db = make_db(tmp_path)
    try:
        # Must not raise: every column in every table is allowlisted.
        assert_no_plaintext_columns(db.con)
        # And there is real schema to check (not a vacuous pass).
        total_columns = sum(len(table_columns(db.con, t)) for t in TABLE_NAMES)
        assert total_columns > 20
    finally:
        db.close()


def test_plaintext_column_name_is_rejected():
    assert not is_allowed_column_name("body")
    assert not is_allowed_column_name("plaintext")
    assert not is_allowed_column_name("content")
    assert not is_allowed_column_name("notes")


def test_allowlisted_column_kinds_accepted():
    for name in (
        "command_id",
        "input_digest",
        "checkpoint_sha256",
        "provider_handle",
        "command_state",
        "artifact_kind",
        "artifact_role",
        "wrapped_key_hex",
        "created_at",
        "stable_floor_generation",
        "checkpoint_sequence",
        "ordinal",
    ):
        assert is_allowed_column_name(name), name


def test_assert_no_plaintext_columns_detects_injected_body_column(tmp_path):
    db = make_db(tmp_path)
    try:
        db.con.execute("ALTER TABLE command ADD COLUMN body TEXT")
        with pytest.raises(LifecycleDbError):
            assert_no_plaintext_columns(db.con)
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# canonical_artifact UNIQUE(workspace_id, artifact_kind, revision_id)
# --------------------------------------------------------------------------- #


def test_canonical_artifact_unique_rejects_duplicate_tuple(tmp_path):
    db = make_db(tmp_path)
    try:
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-1", "ws-1", "memory_revision", "rev-1", "PREPARED", "t0")
        with pytest.raises(sqlite3.IntegrityError):
            with db.unit_of_work() as uow:
                uow.insert_canonical_artifact(
                    "art-2", "ws-1", "memory_revision", "rev-1", "PREPARED", "t1"
                )
        # The rejected duplicate must not have partially landed.
        with db.unit_of_work() as uow:
            assert uow.get_canonical_artifact("art-2") is None
            assert uow.get_canonical_artifact("art-1") is not None
    finally:
        db.close()


def test_canonical_artifact_allows_same_tuple_shape_in_different_workspace(tmp_path):
    db = make_db(tmp_path)
    try:
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-1", "ws-1", "memory_revision", "rev-1", "PREPARED", "t0")
            uow.insert_canonical_artifact("art-2", "ws-2", "memory_revision", "rev-1", "PREPARED", "t0")
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# command_artifact junction UNIQUE constraints
# --------------------------------------------------------------------------- #


def _seed_command_and_artifacts(uow) -> None:
    uow.insert_command("cmd-1", "ws-1", "remember", "digest-abc", "PREPARED", "t0")
    uow.insert_canonical_artifact("art-1", "ws-1", "memory_revision", "rev-1", "PREPARED", "t0")
    uow.insert_canonical_artifact("art-2", "ws-1", "memory_revision", "rev-2", "PREPARED", "t0")


def test_command_artifact_unique_command_artifact_pair(tmp_path):
    db = make_db(tmp_path)
    try:
        with db.unit_of_work() as uow:
            _seed_command_and_artifacts(uow)
            uow.insert_command_artifact("cmd-1", "art-1", "primary", "0")
        with pytest.raises(sqlite3.IntegrityError):
            with db.unit_of_work() as uow:
                uow.insert_command_artifact("cmd-1", "art-1", "evidence", "1")
    finally:
        db.close()


def test_command_artifact_unique_role_ordinal(tmp_path):
    db = make_db(tmp_path)
    try:
        with db.unit_of_work() as uow:
            _seed_command_and_artifacts(uow)
            uow.insert_command_artifact("cmd-1", "art-1", "primary", "0")
        with pytest.raises(sqlite3.IntegrityError):
            with db.unit_of_work() as uow:
                # Different artifact_id, but same (command_id, artifact_role, ordinal).
                uow.insert_command_artifact("cmd-1", "art-2", "primary", "0")
        with db.unit_of_work() as uow:
            rows = uow.list_command_artifacts("cmd-1")
            assert len(rows) == 1
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Restart durability
# --------------------------------------------------------------------------- #


def test_restart_durability_reopen_and_read(tmp_path):
    path = tmp_path / "durable.sqlite3"
    db1 = LifecycleDatabase(db_path=path)
    db1.initialize()
    with db1.unit_of_work() as uow:
        uow.insert_canonical_artifact("art-1", "ws-1", "memory_revision", "rev-1", "PREPARED", "t0")
    db1.close()

    db2 = LifecycleDatabase(db_path=path)
    db2.initialize()
    try:
        db2.assert_contract_pragmas()
        with db2.unit_of_work() as uow:
            row = uow.get_canonical_artifact("art-1")
            assert row is not None
            assert row["revision_id"] == "rev-1"
            assert row["artifact_state"] == "PREPARED"
    finally:
        db2.close()


# --------------------------------------------------------------------------- #
# unit_of_work rollback on exception
# --------------------------------------------------------------------------- #


def test_unit_of_work_rollback_on_exception_leaves_no_partial_write(tmp_path):
    db = make_db(tmp_path)
    try:
        class Boom(RuntimeError):
            pass

        with pytest.raises(Boom):
            with db.unit_of_work() as uow:
                uow.insert_canonical_artifact(
                    "art-1", "ws-1", "memory_revision", "rev-1", "PREPARED", "t0"
                )
                uow.insert_command("cmd-1", "ws-1", "remember", "digest-abc", "PREPARED", "t0")
                raise Boom("simulated failure mid-transaction")

        with db.unit_of_work() as uow:
            assert uow.get_canonical_artifact("art-1") is None
            assert uow.get_command("cmd-1") is None
    finally:
        db.close()


def test_unit_of_work_rollback_on_integrity_error_leaves_no_partial_write(tmp_path):
    db = make_db(tmp_path)
    try:
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-1", "ws-1", "memory_revision", "rev-1", "PREPARED", "t0")

        with pytest.raises(sqlite3.IntegrityError):
            with db.unit_of_work() as uow:
                uow.insert_command("cmd-1", "ws-1", "remember", "digest-abc", "PREPARED", "t0")
                # Violates canonical_artifact UNIQUE tuple constraint -> whole tx rolls back.
                uow.insert_canonical_artifact(
                    "art-2", "ws-1", "memory_revision", "rev-1", "PREPARED", "t1"
                )

        with db.unit_of_work() as uow:
            # cmd-1 must not have survived even though it was valid in isolation.
            assert uow.get_command("cmd-1") is None
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# append_event hash chain
# --------------------------------------------------------------------------- #


def test_append_event_forms_verifiable_hash_chain(tmp_path):
    db = make_db(tmp_path)
    try:
        assert db.event_chain_head() is None
        d1 = db.append_event(None, "artifact_prepared", "digest-1")
        assert db.event_chain_head() == d1
        d2 = db.append_event(d1, "artifact_active", "digest-2")
        assert db.event_chain_head() == d2
        d3 = db.append_event(d2, "artifact_superseded", "digest-3")
        assert db.event_chain_head() == d3

        rows = db.event_log_rows()
        assert [r["event_digest"] for r in rows] == [d1, d2, d3]
        assert rows[0]["prev_digest"] is None
        assert rows[1]["prev_digest"] == d1
        assert rows[2]["prev_digest"] == d2
        assert len({d1, d2, d3}) == 3
    finally:
        db.close()


def test_append_event_rejects_stale_prev_digest(tmp_path):
    db = make_db(tmp_path)
    try:
        d1 = db.append_event(None, "artifact_prepared", "digest-1")
        with pytest.raises(EventChainError):
            db.append_event(None, "artifact_active", "digest-2")
        with pytest.raises(EventChainError):
            db.append_event("not-the-real-head", "artifact_active", "digest-2")
        # Chain head unaffected by rejected appends.
        assert db.event_chain_head() == d1
        assert len(db.event_log_rows()) == 1
    finally:
        db.close()


def test_event_log_payload_carries_no_body_field(tmp_path):
    db = make_db(tmp_path)
    try:
        db.append_event(None, "artifact_prepared", "digest-1")
        columns = set(table_columns(db.con, "event_log"))
        assert "body" not in columns
        assert not any("body" in c for c in columns)
        # Every column is allowlisted (id/digest/handle/state/wrapped/ts kinds).
        for c in columns:
            assert is_allowed_column_name(c), c
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# checked_snapshot_read
# --------------------------------------------------------------------------- #


def test_checked_snapshot_read_returns_consistent_as_of_snapshot(tmp_path):
    db = make_db(tmp_path)
    try:
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-1", "ws-1", "memory_revision", "rev-1", "PREPARED", "t0")
            uow.upsert_key_state("art-1", "PREPARED", "t0")
        d1 = db.append_event(None, "artifact_prepared", "art-1")

        snap = db.checked_snapshot_read("art-1")
        assert snap.artifact_id == "art-1"
        assert snap.artifact_state == "PREPARED"
        assert snap.custody_state == "PREPARED"
        assert snap.event_chain_head_digest == d1

        # Advance state after the first snapshot; a fresh snapshot must observe
        # the new state, proving the read is re-acquired (not cached) each call.
        with db.unit_of_work() as uow:
            uow.upsert_key_state("art-1", "ACTIVE", "t1")
        d2 = db.append_event(d1, "artifact_active", "art-1")

        snap2 = db.checked_snapshot_read("art-1")
        assert snap2.custody_state == "ACTIVE"
        assert snap2.event_chain_head_digest == d2

    finally:
        db.close()


def test_checked_snapshot_read_missing_artifact_returns_none_fields(tmp_path):
    db = make_db(tmp_path)
    try:
        snap = db.checked_snapshot_read("does-not-exist")
        assert snap.artifact_state is None
        assert snap.custody_state is None
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Two-connection WAL checked-snapshot isolation barrier (ADR-0027 §9)
# --------------------------------------------------------------------------- #


def test_checked_snapshot_is_isolated_from_concurrent_second_connection_write(tmp_path):
    path = tmp_path / "barrier.sqlite3"
    db = LifecycleDatabase(db_path=path)
    db.initialize()
    try:
        # Seed a baseline committed state on connection A (the database's own
        # connection).
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-1", "ws-1", "memory_revision", "rev-1", "PREPARED", "t0")
            uow.upsert_key_state("art-1", "PREPARED", "t0")
        d1 = db.append_event(None, "artifact_prepared", "art-1")

        baseline = db.checked_snapshot_read("art-1")
        assert baseline.custody_state == "PREPARED"
        assert baseline.event_chain_head_digest == d1

        # Connection A: open the SAME deferred-BEGIN read primitive that
        # checked_snapshot_read uses, and keep the transaction open across a
        # concurrent write committed on an independent connection B.
        con_a = db.con
        con_a.row_factory = sqlite3.Row
        con_a.execute("BEGIN")
        try:
            snap_during_a = con_a.execute(
                "SELECT custody_state FROM key_state WHERE artifact_id=?", ("art-1",)
            ).fetchone()
            head_during_a = con_a.execute(
                "SELECT event_digest FROM event_log ORDER BY event_id DESC LIMIT 1"
            ).fetchone()
            # First read establishes A's WAL snapshot at the pre-write point.
            assert snap_during_a["custody_state"] == "PREPARED"
            assert head_during_a["event_digest"] == d1

            # Connection B: an independent connection to the SAME db file,
            # committing a write under BEGIN IMMEDIATE while A's snapshot
            # transaction is still open (WAL readers never block writers).
            con_b = sqlite3.connect(str(path), isolation_level=None)
            con_b.execute("PRAGMA busy_timeout=5000")
            try:
                con_b.execute("BEGIN IMMEDIATE")
                con_b.execute(
                    "UPDATE key_state SET custody_state=?, updated_at=? WHERE artifact_id=?",
                    ("ACTIVE", "t1", "art-1"),
                )
                con_b.execute(
                    "INSERT INTO event_log "
                    "(prev_digest, event_kind, ref_digest, event_digest, created_at) "
                    "VALUES (?,?,?,?,?)",
                    (d1, "artifact_active", "art-1", "digest-from-b", "t1"),
                )
                con_b.execute("COMMIT")
            finally:
                con_b.close()

            # A's still-open snapshot transaction must NOT observe B's commit:
            # re-reading inside the same transaction returns the pre-write
            # baseline (WAL snapshot isolation for the duration of A's tx).
            snap_after_b_commit = con_a.execute(
                "SELECT custody_state FROM key_state WHERE artifact_id=?", ("art-1",)
            ).fetchone()
            head_after_b_commit = con_a.execute(
                "SELECT event_digest FROM event_log ORDER BY event_id DESC LIMIT 1"
            ).fetchone()
            assert snap_after_b_commit["custody_state"] == "PREPARED"
            assert head_after_b_commit["event_digest"] == d1
        finally:
            con_a.execute("COMMIT")

        # A fresh checked-snapshot read (a new deferred-BEGIN transaction) now
        # DOES observe B's committed write: the barrier only holds for the
        # lifetime of the snapshot that was already acquired.
        fresh = db.checked_snapshot_read("art-1")
        assert fresh.custody_state == "ACTIVE"
        assert fresh.event_chain_head_digest == "digest-from-b"
    finally:
        db.close()


def test_checked_serve_snapshot_read_captures_all_serve_state(tmp_path):
    """F4 (ADR-0027 §9): the serve snapshot captures artifact, custody, deletion
    phase, freshness serve gate, and event head in one atomic acquisition."""
    db = make_db(tmp_path)
    try:
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-1", "ws-1", "MEMORY_REVISION", "rev-1", "ACTIVE", "t0")
            uow.upsert_key_state("art-1", "ACTIVE", "t0")
            uow.insert_deletion_state("del-1", "art-1", "REQUESTED", "t0")
            uow.upsert_freshness_serve_gate(
                workspace_id="ws-1",
                gate_state="SERVE_ALLOWED",
                stable_floor_generation="3",
                stable_checkpoint_id="cp-1",
                source_candidate_digest="ab" * 32,
                reason_state="fresh",
                updated_at="t0",
            )
        d1 = db.append_event(None, "artifact_active", "art-1")

        snap = db.checked_serve_snapshot_read("art-1", "ws-1")
        assert snap.artifact_state == "ACTIVE"
        assert snap.custody_state == "ACTIVE"
        assert snap.deletion_phase_state == "REQUESTED"
        assert snap.serve_gate_state == "SERVE_ALLOWED"
        assert snap.serve_gate_reason == "fresh"
        assert snap.event_chain_head_digest == d1

        # A missing artifact yields None states (no row), never an error.
        missing = db.checked_serve_snapshot_read("nope", "ws-1")
        assert missing.artifact_state is None
        assert missing.custody_state is None
        assert missing.deletion_phase_state is None
        # The workspace serve gate is still captured for a missing artifact.
        assert missing.serve_gate_state == "SERVE_ALLOWED"
    finally:
        db.close()


def test_serve_snapshot_is_isolated_from_concurrent_forget(tmp_path):
    """F4 (ADR-0027 §9): a serve snapshot's veto visibility is linearized at its
    acquisition. A concurrent FORGET committing a deletion veto on an independent
    connection while the serve-snapshot transaction is open is NOT observed by
    that already-acquired snapshot, but IS observed by a fresh one."""
    path = tmp_path / "serve-barrier.sqlite3"
    db = LifecycleDatabase(db_path=path)
    db.initialize()
    try:
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-1", "ws-1", "MEMORY_REVISION", "rev-1", "ACTIVE", "t0")
            uow.upsert_key_state("art-1", "ACTIVE", "t0")

        baseline = db.checked_serve_snapshot_read("art-1", "ws-1")
        assert baseline.artifact_state == "ACTIVE"
        assert baseline.deletion_phase_state is None

        con_a = db.con
        con_a.row_factory = sqlite3.Row
        con_a.execute("BEGIN")
        try:
            del_during_a = con_a.execute(
                "SELECT phase_state FROM deletion_state WHERE artifact_id=? "
                "ORDER BY updated_at DESC, deletion_id DESC LIMIT 1",
                ("art-1",),
            ).fetchone()
            # First read establishes A's WAL snapshot at the pre-FORGET point.
            assert del_during_a is None

            # Connection B commits a FORGET veto while A's snapshot is open.
            con_b = sqlite3.connect(str(path), isolation_level=None)
            con_b.execute("PRAGMA busy_timeout=5000")
            try:
                con_b.execute("BEGIN IMMEDIATE")
                con_b.execute(
                    "INSERT INTO deletion_state "
                    "(deletion_id, artifact_id, phase_state, updated_at) VALUES (?,?,?,?)",
                    ("del-1", "art-1", "REQUESTED", "t1"),
                )
                con_b.execute("COMMIT")
            finally:
                con_b.close()

            # A's still-open snapshot must NOT observe B's veto commit.
            del_after_b = con_a.execute(
                "SELECT phase_state FROM deletion_state WHERE artifact_id=? "
                "ORDER BY updated_at DESC, deletion_id DESC LIMIT 1",
                ("art-1",),
            ).fetchone()
            assert del_after_b is None
        finally:
            con_a.execute("COMMIT")

        # A fresh serve snapshot now DOES observe the committed veto.
        fresh = db.checked_serve_snapshot_read("art-1", "ws-1")
        assert fresh.deletion_phase_state == "REQUESTED"
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# F5: in-transaction event append is atomic with the state it records
# --------------------------------------------------------------------------- #


def test_uow_append_event_commits_atomically_with_state(tmp_path):
    """F5: an event appended inside a unit of work commits atomically with the
    state change it records -- both persist on commit, and a failure rolls back
    BOTH (no state-without-event, no event-without-state)."""
    db = make_db(tmp_path)
    try:
        # Commit path: state + event land together.
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-1", "ws-1", "MEMORY_REVISION", "rev-1", "PREPARED", "t0")
            prev = uow.event_chain_head()
            assert prev is None
            uow.append_event(prev_digest=prev, kind="ARTIFACT_PREPARED", ref_digest="art-1")
        assert db.event_chain_head() is not None
        assert len(db.event_log_rows()) == 1
        with db.unit_of_work() as uow:
            assert uow.get_canonical_artifact("art-1") is not None

        # Rollback path: a failure after the in-tx event append rolls back BOTH
        # the state and the event.
        head_before = db.event_chain_head()
        with pytest.raises(RuntimeError):
            with db.unit_of_work() as uow:
                uow.insert_canonical_artifact("art-2", "ws-1", "MEMORY_REVISION", "rev-2", "PREPARED", "t1")
                prev = uow.event_chain_head()
                uow.append_event(prev_digest=prev, kind="ARTIFACT_PREPARED", ref_digest="art-2")
                raise RuntimeError("simulated crash before commit")
        with db.unit_of_work() as uow:
            assert uow.get_canonical_artifact("art-2") is None
        assert db.event_chain_head() == head_before
        assert len(db.event_log_rows()) == 1  # only the committed event remains

        # The chain still validates forward from the committed event.
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-3", "ws-1", "MEMORY_REVISION", "rev-3", "PREPARED", "t2")
            prev = uow.event_chain_head()
            uow.append_event(prev_digest=prev, kind="ARTIFACT_PREPARED", ref_digest="art-3")
        assert len(db.event_log_rows()) == 2
    finally:
        db.close()


def test_uow_append_event_rejects_stale_prev_and_rolls_back(tmp_path):
    """F5: an in-transaction append with a stale prev_digest raises
    EventChainError and rolls back the whole unit of work (state included)."""
    db = make_db(tmp_path)
    try:
        d1 = db.append_event(None, "first", "ref-1")
        with pytest.raises(EventChainError):
            with db.unit_of_work() as uow:
                uow.insert_canonical_artifact("art-1", "ws-1", "MEMORY_REVISION", "rev-1", "PREPARED", "t0")
                uow.append_event(prev_digest="stale" * 8, kind="BAD", ref_digest="art-1")
        # The artifact inserted before the bad append also rolled back.
        with db.unit_of_work() as uow:
            assert uow.get_canonical_artifact("art-1") is None
        assert db.event_chain_head() == d1
    finally:
        db.close()
